-- 利用者が「自分の端末」として登録したブラウザと、ログイン状態がどの端末で作られたか（task #872。ADR-0071）。
--
-- 端末は web がブラウザに置く Cookie（端末の印）で見分ける。DB には印の SHA-256 だけを置き、平文は持たない
-- （SSO セッションと同じ扱い）。登録していない端末でログインしたら、監査に残し、送り先があれば知らせる。
--
-- 取り消しは行を消す（経緯は監査ログに残る）。同じ印を登録し直せるよう、取り消し済みの行は持たない。
CREATE TABLE user_devices (
    id            CHAR(36)     NOT NULL COMMENT 'UUIDv7',
    user_id       CHAR(36)     NOT NULL COMMENT '登録した利用者',
    device_hash   CHAR(64)     NOT NULL COMMENT '端末の印（Cookie の値）の SHA-256',
    name          VARCHAR(100) NOT NULL COMMENT '利用者が付けた名前',
    user_agent    VARCHAR(512) NULL     COMMENT '登録したときのブラウザの名乗り（表示用。判定には使わない）',
    registered_at DATETIME(6)  NOT NULL COMMENT '登録した時刻（UTC）',
    last_used_at  DATETIME(6)  NOT NULL COMMENT '最後にこの端末でログインした時刻（UTC）。期限はここから数える',
    last_country  CHAR(2)      NULL     COMMENT '最後にログインしたときの国（Cloudflare の国コード。分からなければ NULL）',
    last_ip       VARCHAR(45)  NULL     COMMENT '最後にログインしたときの接続元',
    PRIMARY KEY (id),
    UNIQUE KEY user_devices_user_device_uq (user_id, device_hash),
    KEY user_devices_last_used_idx (last_used_at),
    CONSTRAINT user_devices_user_fk FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- SSO セッションに付く文脈（どの端末で作られたか・パスキーで確かめた時刻）。
--
-- ⚠ `sso_sessions` に列を足さず別の表にする。`SsoSession` は 5 つのログイン経路と多数の試験が組み立てる型で、
--   端末の話を持ち込むと全部に波及するため。セッションが消えれば一緒に消える（CASCADE）。
CREATE TABLE sso_session_contexts (
    session_hash        CHAR(64)    NOT NULL COMMENT 'sso_sessions.session_hash',
    device_hash         CHAR(64)    NULL     COMMENT 'このセッションを作ったブラウザの端末の印の SHA-256',
    country             CHAR(2)     NULL     COMMENT 'このセッションを作ったときの国',
    observed_at         DATETIME(6) NULL     COMMENT '端末を結び付けた時刻（UTC）',
    passkey_verified_at DATETIME(6) NULL     COMMENT 'このセッションでパスキーの本人確認を最後に通した時刻（UTC）',
    PRIMARY KEY (session_hash),
    KEY sso_session_contexts_device_idx (device_hash),
    CONSTRAINT sso_session_contexts_session_fk FOREIGN KEY (session_hash)
        REFERENCES sso_sessions (session_hash) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
