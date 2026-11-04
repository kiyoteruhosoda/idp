-- 認証アプリで承認するログイン（「アプリで続ける」。task #892。ADR-0077）。
--
-- 3 つの表と、ログイン状態の文脈の 1 列:
--   app_approver_keys        利用者の認証アプリの鍵（Android の Keystore・Key Attestation を確かめた公開鍵）
--   app_approver_enrollments 鍵の登録の受付（10 分）
--   app_approval_requests    「アプリで続ける」の依頼（5 分。始めたブラウザの印の SHA-256 に結ぶ）
--   sso_session_contexts.approver_key_id  そのログイン状態を承認した鍵（長さ 30 日の根拠。取り消しで切る）
--
-- 秘密は置かない。印・コードは SHA-256 だけ。公開鍵は SubjectPublicKeyInfo（DER）。
CREATE TABLE app_approver_keys (
    id              CHAR(36)       NOT NULL COMMENT 'UUIDv7',
    user_id         CHAR(36)       NOT NULL COMMENT '鍵の持ち主',
    key_id          CHAR(43)       NOT NULL COMMENT '公開鍵（SPKI）の SHA-256（base64url）。アプリはこの値で名乗る',
    public_key_spki VARBINARY(512) NOT NULL COMMENT '公開鍵（SubjectPublicKeyInfo・DER・EC P-256）',
    security_level  VARCHAR(16)    NOT NULL COMMENT '鍵の置き場（tee / strongbox / software）',
    device_name     VARCHAR(64)    NOT NULL COMMENT 'アプリの自己申告の機種名（表示だけ）',
    registered_at   DATETIME(6)    NOT NULL COMMENT '登録した時刻（UTC）',
    last_used_at    DATETIME(6)    NULL     COMMENT '最後に承認に使った時刻（UTC）',
    PRIMARY KEY (id),
    UNIQUE KEY app_approver_keys_key_id_uq (key_id),
    KEY app_approver_keys_user_idx (user_id),
    CONSTRAINT app_approver_keys_level_chk CHECK (security_level IN ('tee', 'strongbox', 'software')),
    CONSTRAINT app_approver_keys_user_fk FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

CREATE TABLE app_approver_enrollments (
    id              CHAR(43)       NOT NULL COMMENT '受付の識別子（乱数・base64url）',
    tenant_id       CHAR(36)       NOT NULL COMMENT '登録する組織',
    challenge       CHAR(43)       NOT NULL COMMENT 'Key Attestation に入れてもらう値（base64url）',
    stage           VARCHAR(24)    NOT NULL COMMENT 'awaiting_key / awaiting_confirmation / confirmed',
    public_key_spki VARBINARY(512) NULL     COMMENT '確かめた公開鍵',
    security_level  VARCHAR(16)    NULL,
    device_name     VARCHAR(64)    NULL,
    user_id         CHAR(36)       NULL     COMMENT '確認した利用者（confirmed の後）',
    code_hash       CHAR(64)       NULL     COMMENT 'アプリへ返したコードの SHA-256',
    code_expires_at DATETIME(6)    NULL,
    created_at      DATETIME(6)    NOT NULL,
    expires_at      DATETIME(6)    NOT NULL,
    PRIMARY KEY (id),
    KEY app_approver_enrollments_expires_idx (expires_at),
    CONSTRAINT app_approver_enrollments_stage_chk
        CHECK (stage IN ('awaiting_key', 'awaiting_confirmation', 'confirmed')),
    CONSTRAINT app_approver_enrollments_user_fk FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

CREATE TABLE app_approval_requests (
    id                   CHAR(43)     NOT NULL COMMENT '依頼の識別子（乱数・base64url）',
    tenant_id            CHAR(36)     NOT NULL COMMENT 'ログインする組織',
    browser_binding_hash CHAR(64)     NOT NULL COMMENT '始めたブラウザの印（Cookie）の SHA-256',
    auth_session_hash    CHAR(64)     NULL     COMMENT '認可の途中から来たならその AuthSession の SHA-256',
    client_id            VARCHAR(255) NULL     COMMENT '認可の途中から来たならその RP',
    challenge            CHAR(43)     NOT NULL COMMENT 'アプリが署名に入れる値',
    state                VARCHAR(16)  NOT NULL COMMENT 'pending / approved / denied / completed / refused',
    ip_address           VARCHAR(45)  NULL     COMMENT '依頼を始めた接続元（アプリに見せる）',
    country              CHAR(2)      NULL     COMMENT '依頼を始めた国（アプリに見せる）',
    approver_key_id      CHAR(36)     NULL     COMMENT '承認した鍵（app_approver_keys.id）',
    user_id              CHAR(36)     NULL     COMMENT '承認した利用者',
    code_hash            CHAR(64)     NULL     COMMENT '承認して返したコードの SHA-256',
    code_expires_at      DATETIME(6)  NULL     COMMENT 'コードの期限（30 秒）',
    created_at           DATETIME(6)  NOT NULL,
    expires_at           DATETIME(6)  NOT NULL,
    PRIMARY KEY (id),
    KEY app_approval_requests_expires_idx (expires_at),
    CONSTRAINT app_approval_requests_state_chk
        CHECK (state IN ('pending', 'approved', 'denied', 'completed', 'refused')),
    CONSTRAINT app_approval_requests_key_fk FOREIGN KEY (approver_key_id)
        REFERENCES app_approver_keys (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- ⚠ 鍵を消してもログイン状態は自動では消えない（SET NULL）。取り消しの処理が、先にその鍵で承認した
--   ログイン状態と refresh token を終わらせる（ADR-0044）。列が NULL になった行は 30 日の根拠を失う。
ALTER TABLE sso_session_contexts
    ADD COLUMN approver_key_id CHAR(36) NULL COMMENT 'このログイン状態を承認した認証アプリの鍵（task #892）',
    ADD KEY sso_session_contexts_approver_key_idx (approver_key_id),
    ADD CONSTRAINT sso_session_contexts_approver_key_fk FOREIGN KEY (approver_key_id)
        REFERENCES app_approver_keys (id) ON DELETE SET NULL;
