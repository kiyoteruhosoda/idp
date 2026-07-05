-- ベースライン: OIDC IdP MVP の全テーブル（設計仕様 docs/OIDC_INPUT.md §3, §7）。
-- MariaDB 10.11。方針:
--   * DB ネイティブ ENUM は使わず VARCHAR + CHECK 制約（許可値は Rust 側 enum で集中管理）。
--   * UUID は CHAR(36)、時刻は UTC の DATETIME(6)、配列は JSON。
--   * 既定照合は utf8mb4_unicode_ci（大小無視）。理由:
--       - CITEXT 相当（email / preferred_username）の大小無視一意性を満たす。
--       - redirect_uri / PKCE / state / nonce 等の「完全一致」が要る比較はすべて
--         アプリ層（Rust）で厳密比較しており、DB 照合には依存しない。
--       - DB キーとして引く識別子（code_hash / session_hash は SHA-256 の小文字 16 進、
--         auth_sessions.id は小文字 16 進トークン、kid も小文字系）は大小のゆらぎが無いため
--         ci でも bin と同一に振る舞う。
--     ※ _bin / ascii_bin 照合は sqlx が VARBINARY として扱い String へデコードできないため使わない。

-- 3.1 Users
CREATE TABLE users (
    id                  CHAR(36)     NOT NULL,
    sub                 CHAR(36)     NOT NULL,
    email               VARCHAR(320) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
    email_verified      TINYINT(1)   NOT NULL DEFAULT 0,
    preferred_username  VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL,
    name                VARCHAR(255) NULL,
    password_hash       VARCHAR(255) NOT NULL,
    status              VARCHAR(16)  NOT NULL DEFAULT 'ACTIVE',
    failed_login_count  INT          NOT NULL DEFAULT 0,
    locked_until        DATETIME(6)  NULL,
    created_at          DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at          DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY users_sub_uk (sub),
    UNIQUE KEY users_email_uk (email),
    -- preferred_username は NULL 許容。MariaDB の UNIQUE は複数 NULL を許容するため
    -- 通常の UNIQUE 索引で PostgreSQL の部分 UNIQUE 索引を代替できる。
    UNIQUE KEY users_preferred_username_uk (preferred_username),
    CONSTRAINT users_status_chk CHECK (status IN ('ACTIVE', 'DISABLED', 'LOCKED'))
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- 3.2 Clients
CREATE TABLE clients (
    id                          CHAR(36)     NOT NULL,
    client_id                   VARCHAR(255) NOT NULL,
    client_secret_hash          VARCHAR(255) NULL,
    client_type                 VARCHAR(16)  NOT NULL,
    client_status               VARCHAR(16)  NOT NULL DEFAULT 'ACTIVE',
    app_name                    VARCHAR(255) NOT NULL,
    redirect_uris               JSON         NOT NULL,
    grant_types                 JSON         NOT NULL,
    response_types              JSON         NOT NULL,
    scopes                      JSON         NOT NULL,
    token_endpoint_auth_method  VARCHAR(32)  NOT NULL,
    require_pkce                TINYINT(1)   NOT NULL DEFAULT 1,
    created_at                  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at                  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY clients_client_id_uk (client_id),
    CONSTRAINT clients_type_chk CHECK (client_type IN ('public', 'confidential')),
    CONSTRAINT clients_status_chk CHECK (client_status IN ('ACTIVE', 'DISABLED')),
    CONSTRAINT clients_tokep_auth_chk CHECK (token_endpoint_auth_method IN ('client_secret_basic', 'none'))
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- 3.3 AuthSessions（/authorize 〜 /login の一時状態）
CREATE TABLE auth_sessions (
    -- id は 128bit 以上の推測不能なランダム値（256bit 乱数の小文字 16 進 = 64 文字を想定）。
    id                     VARCHAR(64)  NOT NULL,
    client_id              VARCHAR(255) NOT NULL,
    redirect_uri           VARCHAR(2048) NOT NULL,
    scope                  JSON         NOT NULL,
    state                  VARCHAR(1024) NOT NULL,
    nonce                  VARCHAR(1024) NOT NULL,
    code_challenge         VARCHAR(255) NOT NULL,
    code_challenge_method  VARCHAR(8)   NOT NULL DEFAULT 'S256',
    authenticated_user_id  CHAR(36)     NULL,
    auth_time              DATETIME(6)  NULL,
    expires_at             DATETIME(6)  NOT NULL,
    created_at             DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at             DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    KEY auth_sessions_expires_idx (expires_at),
    KEY auth_sessions_user_idx (authenticated_user_id),
    KEY auth_sessions_client_idx (client_id),
    CONSTRAINT auth_sessions_ccm_chk CHECK (code_challenge_method IN ('S256')),
    CONSTRAINT auth_sessions_user_fk FOREIGN KEY (authenticated_user_id) REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT auth_sessions_client_fk FOREIGN KEY (client_id) REFERENCES clients (client_id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- 3.4 SsoSessions（IdP の SSO ログイン状態。Cookie には session_id、DB にはその SHA-256）
CREATE TABLE sso_sessions (
    session_hash         CHAR(64)     NOT NULL,
    user_id              CHAR(36)     NOT NULL,
    auth_time            DATETIME(6)  NOT NULL,
    idle_expires_at      DATETIME(6)  NOT NULL,
    absolute_expires_at  DATETIME(6)  NOT NULL,
    user_agent           VARCHAR(512) NULL,
    ip_address           VARCHAR(45)  NULL,
    created_at           DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at           DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (session_hash),
    KEY sso_sessions_user_idx (user_id),
    KEY sso_sessions_idle_idx (idle_expires_at),
    CONSTRAINT sso_sessions_user_fk FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- 3.5 AuthorizationCodes（DB には平文ではなく SHA-256 を保存）
CREATE TABLE authorization_codes (
    code_hash              CHAR(64)     NOT NULL,
    user_id                CHAR(36)     NOT NULL,
    client_id              VARCHAR(255) NOT NULL,
    redirect_uri           VARCHAR(2048) NOT NULL,
    scope                  JSON         NOT NULL,
    nonce                  VARCHAR(1024) NOT NULL,
    auth_time              DATETIME(6)  NOT NULL,
    code_challenge         VARCHAR(255) NOT NULL,
    code_challenge_method  VARCHAR(8)   NOT NULL DEFAULT 'S256',
    expires_at             DATETIME(6)  NOT NULL,
    used_at                DATETIME(6)  NULL,
    created_at             DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at             DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (code_hash),
    KEY authorization_codes_expires_idx (expires_at),
    KEY authorization_codes_user_idx (user_id),
    KEY authorization_codes_client_idx (client_id),
    CONSTRAINT authorization_codes_ccm_chk CHECK (code_challenge_method IN ('S256')),
    CONSTRAINT authorization_codes_user_fk FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT authorization_codes_client_fk FOREIGN KEY (client_id) REFERENCES clients (client_id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- 3.6 SigningKeys（JWT 署名鍵。private_key_encrypted は DB 外の鍵で暗号化）
CREATE TABLE signing_keys (
    kid                    VARCHAR(128) NOT NULL,
    algorithm              VARCHAR(16)  NOT NULL DEFAULT 'RS256',
    public_key             TEXT         NOT NULL,
    private_key_encrypted  TEXT         NOT NULL,
    status                 VARCHAR(16)  NOT NULL,
    not_before             DATETIME(6)  NOT NULL,
    not_after              DATETIME(6)  NOT NULL,
    created_at             DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at             DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (kid),
    KEY signing_keys_status_idx (status),
    CONSTRAINT signing_keys_status_chk CHECK (status IN ('ACTIVE', 'RETIRED')),
    CONSTRAINT signing_keys_alg_chk CHECK (algorithm IN ('RS256'))
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- 7. 監査ログ（構造化ログと同時に DB へ書き込む。PII は含めない）
CREATE TABLE audit_log (
    id              BIGINT       NOT NULL AUTO_INCREMENT,
    event_type      VARCHAR(64)  NOT NULL,
    occurred_at     DATETIME(6)  NOT NULL,
    user_id         CHAR(36)     NULL,
    client_id       VARCHAR(255) NULL,
    ip_address      VARCHAR(45)  NULL,
    user_agent      VARCHAR(512) NULL,
    result          VARCHAR(16)  NOT NULL,
    reason          VARCHAR(255) NULL,
    correlation_id  VARCHAR(64)  NOT NULL,
    PRIMARY KEY (id),
    KEY audit_log_event_idx (event_type),
    KEY audit_log_correlation_idx (correlation_id),
    KEY audit_log_occurred_idx (occurred_at)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
