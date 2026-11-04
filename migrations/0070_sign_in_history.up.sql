-- 本人が見る「ログイン履歴」と、ログインごとのアプリでの使われ方（task #879。ADR-0073）。
--
-- ⚠ `sso_sessions`・`sso_session_contexts`・`refresh_tokens` は期限が来ると消える（`expired_records`）。
--   履歴はログイン状態が消えた後も見たいので、別の表に写して残す。監査ログ（`audit_log`）は
--   テナントで引く作りで、利用者ごとに新しい順で引く索引も、入り方・国・どのログインかの列も無い。
--
-- 利用者を消したら一緒に消える（CASCADE）。それ以外では消さない（監査ログと同じく持ち続ける）。

-- ログインの試み 1 回につき 1 行。成功は web がログイン状態の Cookie を置いた応答で
-- （`/internal/devices/observe`）、失敗は監査ログへ書く所で写す。
CREATE TABLE sign_in_history (
    id                     BIGINT       NOT NULL AUTO_INCREMENT,
    user_id                CHAR(36)     NOT NULL COMMENT 'ログインしようとした利用者',
    tenant_id              CHAR(36)     NULL     COMMENT 'ログインした組織（client_id を引くため。成功は所属元）',
    occurred_at            DATETIME(6)  NOT NULL COMMENT 'ログインした・断られた時刻（UTC）',
    outcome                VARCHAR(16)  NOT NULL COMMENT 'succeeded / failed / locked / denied',
    failure_kind           VARCHAR(32)  NULL     COMMENT '断られた理由の種類（成功なら NULL）',
    ip_address             VARCHAR(45)  NULL     COMMENT '接続元',
    user_agent             VARCHAR(512) NULL     COMMENT 'ブラウザの名乗り',
    country                CHAR(2)      NULL     COMMENT 'Cloudflare の国コード（信じられないときは NULL。家の中からは NULL）',
    authentication_methods JSON         NULL     COMMENT '確かめた入り方（成功だけ。sso_sessions と同じ値）',
    client_id              VARCHAR(255) NULL     COMMENT 'ログインを始めたアプリ（失敗のとき分かれば）',
    sid                    VARCHAR(64)  NULL     COMMENT '成功したログインの SSO セッションの sid（refresh_tokens.sid と同じ値）',
    device_registered      BOOLEAN      NULL     COMMENT '登録した端末だったか（成功だけ。task #872）',
    PRIMARY KEY (id),
    UNIQUE KEY sign_in_history_sid_uq (sid),
    KEY sign_in_history_user_idx (user_id, id),
    CONSTRAINT sign_in_history_outcome_chk
        CHECK (outcome IN ('succeeded', 'failed', 'locked', 'denied')),
    CONSTRAINT sign_in_history_user_fk FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- 成功したログイン（sid）が、どのアプリで使われ、リフレッシュトークンがどう使われたか。
-- ⚠ リフレッシュの接続元は「トークンを送ってきた相手」（アプリのサーバーが裏で更新するならそのサーバー）で、
--   元のログインの接続元とは別に持つ。
CREATE TABLE sign_in_app_usage (
    sid                        VARCHAR(64)  NOT NULL COMMENT 'sign_in_history.sid',
    client_id                  VARCHAR(255) NOT NULL COMMENT 'このログインでトークンを受け取ったアプリ',
    user_id                    CHAR(36)     NOT NULL,
    tenant_id                  CHAR(36)     NOT NULL COMMENT 'client_id を引くための組織',
    first_issued_at            DATETIME(6)  NOT NULL COMMENT 'このアプリへ最初にトークンを出した時刻（UTC）',
    last_issued_at             DATETIME(6)  NOT NULL COMMENT '最後にこのログインでこのアプリへ入った時刻（UTC）',
    refresh_issued             BOOLEAN      NOT NULL DEFAULT FALSE COMMENT 'リフレッシュトークンを出したか',
    refresh_use_count          INT          NOT NULL DEFAULT 0     COMMENT 'リフレッシュトークンで更新した回数',
    refresh_last_used_at       DATETIME(6)  NULL     COMMENT '最後に更新した時刻（UTC）',
    refresh_last_ip            VARCHAR(45)  NULL     COMMENT '最後に更新を送ってきた相手の接続元',
    refresh_last_user_agent    VARCHAR(512) NULL     COMMENT '最後に更新を送ってきた相手の名乗り',
    refresh_reuse_detected_at  DATETIME(6)  NULL     COMMENT '使い終えたリフレッシュトークンがもう一度来た時刻（UTC）',
    PRIMARY KEY (sid, client_id),
    KEY sign_in_app_usage_user_idx (user_id),
    CONSTRAINT sign_in_app_usage_user_fk FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
