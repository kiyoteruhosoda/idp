-- Back-channel logout の信頼性とセッション識別子 `sid`（G5）。
--
-- 1. `sid` の持ち回り
--
-- OpenID Connect Back-Channel Logout 1.0 §2.1 の `sid` は「ID Token と logout_token が指す同じ
-- セッション」を RP に伝えるための識別子で、これが無いと RP は `sub` 単位でしか失効できない
-- （同一利用者の別デバイスのセッションまで巻き添えになる）。値は SSO セッションの `session_hash`
-- からの非可逆導出（`domain::sso_session::sid_of`）なので専用の採番は要らないが、**code / refresh
-- token を交換する時点では SSO Cookie が手元に無い**（`/token` は Cookie を読まない）ため、発行時に
-- 引き継いだ値をここへ持ち回す。auth_session は「ログイン → 同意 → code 発行」の間の持ち回し用。
ALTER TABLE auth_sessions
    ADD COLUMN sso_sid VARCHAR(64) NULL
        COMMENT 'このフローで確立した SSO セッションの sid（G5）。同意画面を経由する経路で code 発行まで持ち回す';

ALTER TABLE authorization_codes
    ADD COLUMN sid VARCHAR(64) NULL
        COMMENT 'ID Token へ載せる SSO セッション識別子（G5）。NULL = 本列の導入前に発行された code';

ALTER TABLE refresh_tokens
    ADD COLUMN sid VARCHAR(64) NULL
        COMMENT 'ID Token へ載せる SSO セッション識別子（G5）。rotation で引き継ぐ';

-- 2. 送信キュー
--
-- 従来の back-channel logout は `tokio::spawn` の撃ちっぱなしで、非 2xx は WARN を出すだけ・
-- プロセス再起動で未送信分が消えていた。RP 側のログアウトが黙って落ちるため、ログアウトしたはずの
-- セッションが RP に残る。送信要求を行として永続化し、ワーカーが指数バックオフで再試行する。
--
-- logout_token（署名済み JWT）そのものは保存しない。保存すると「RP へ提示すればログアウトが成立する
-- 資格情報」が DB に長期間残るうえ、再試行のたびに `iat`/`exp` が古いままになる。クレームの素材だけを
-- 持ち、送信の直前に現行の署名鍵で署名する（`jti` だけは RP 側の冪等判定のため固定する）。
CREATE TABLE backchannel_logout_deliveries (
    id               CHAR(36)      NOT NULL
        COMMENT '内部識別子（UUIDv7）',
    tenant_id        CHAR(36)      NOT NULL
        COMMENT 'ログアウトが発生したテナント（logout_token の iss を導出する）',
    client_id        VARCHAR(255)  NOT NULL
        COMMENT '通知先クライアント（logout_token の aud）',
    target_uri       VARCHAR(2048) NOT NULL
        COMMENT '送信先 backchannel_logout_uri（送信直前にも内部宛先でないか検査する）',
    subject          VARCHAR(64)   NOT NULL
        COMMENT 'logout_token の sub（利用者の外部公開識別子 sub）',
    sid              VARCHAR(64)   NULL
        COMMENT 'logout_token の sid（セッション単位のログアウト）。NULL = セッション不明',
    jti              CHAR(36)      NOT NULL
        COMMENT 'logout_token の jti。再試行しても変えない（RP 側の冪等判定に使われる）',
    attempts         INT           NOT NULL DEFAULT 0
        COMMENT '送信を試みた回数。上限に達した行は打ち切る',
    next_attempt_at  DATETIME(6)   NOT NULL
        COMMENT '次に送信を試みる時刻（指数バックオフ）',
    last_error       VARCHAR(1000) NULL
        COMMENT '直近の失敗理由（運用情報。英語で記録する）',
    delivered_at     DATETIME(6)   NULL
        COMMENT '2xx を受け取った時刻。非 NULL = 送信済み',
    created_at       DATETIME(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at       DATETIME(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    -- ワーカーの取り出しクエリ（未送信・期限到来・試行上限未満）が使う索引。
    KEY backchannel_logout_deliveries_due_idx (delivered_at, next_attempt_at),
    KEY backchannel_logout_deliveries_tenant_idx (tenant_id, created_at)
    -- クライアント・テナントが消えても送信要求（と失敗の記録）は残す運用情報のため、外部キーは張らない
    -- （`log` テーブルと同じ方針）。
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
