-- 外部 IdP 認証（AP10。ユーザー認証・認証ポリシー仕様書 §13）。
--
-- 外部の OpenID Provider を「認証器」として使い、そこでの認証結果を本 IdP のログインとして
-- 引き受ける。利用者の同一性は **`iss` + `sub`** で判定する（§13.2）。メールアドレスで結び付ける
-- 設計にしないのは、外部 IdP 側でメールを変更・使い回しできる場合に別人へ繋がるため。
-- `iss` + `sub` は外部 IdP が保証する不変の識別子で、これだけがアカウント連携の根拠になる。
CREATE TABLE external_identity_providers (
    id                     CHAR(36)      NOT NULL
        COMMENT '内部識別子（UUIDv7）',
    tenant_id              CHAR(36)      NOT NULL
        COMMENT '外部 IdP はテナント単位で設定する（テナント越しに使えない）',
    provider_code          VARCHAR(100)  NOT NULL
        COMMENT 'テナント内一意の識別コード。URL パス（/{tenant}/external/{code}/start）に載るため英数字と -_.',
    display_name           VARCHAR(255)  NOT NULL
        COMMENT 'ログイン画面のボタンに出す名称',
    issuer                 VARCHAR(512)  NOT NULL
        COMMENT '外部 IdP の issuer。受け取る ID Token の iss と完全一致すること',
    authorization_endpoint VARCHAR(2048) NOT NULL,
    token_endpoint         VARCHAR(2048) NOT NULL,
    jwks_uri               VARCHAR(2048) NOT NULL
        COMMENT 'ID Token の署名検証に使う JWKS の URL',
    client_id              VARCHAR(255)  NOT NULL
        COMMENT '外部 IdP に登録した本 IdP のクライアント ID',
    client_secret_encrypted TEXT         NULL
        COMMENT 'クライアントシークレット（AES-256-GCM。KEY_ENCRYPTION_KEY で暗号化）。public クライアントとして登録した場合は NULL',
    scopes                 JSON          NOT NULL
        COMMENT '認可要求に載せる scope の配列（既定 ["openid", "profile", "email"]）',
    enabled                BOOLEAN       NOT NULL DEFAULT TRUE,
    -- 自動連携（初回ログイン時に、検証済みメールが一致する既存利用者へ結び付ける）。
    -- 既定 false。外部 IdP がメールの所有を検証していない場合、これを有効にすると
    -- 「他人のメールを名乗って既存アカウントを乗っ取る」経路になるため、明示的に選ばせる。
    allow_auto_link        BOOLEAN       NOT NULL DEFAULT FALSE
        COMMENT '検証済みメール一致で既存利用者へ自動連携するか。外部 IdP のメール検証を信頼できる場合のみ有効化する',
    created_at             DATETIME(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at             DATETIME(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY external_idps_code_uk (tenant_id, provider_code),
    KEY external_idps_tenant_idx (tenant_id, enabled),
    CONSTRAINT external_idps_tenant_fk FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- 外部 IdP 上の同一性と、本 IdP の利用者との対応（§13.2）。
CREATE TABLE user_external_identities (
    id                CHAR(36)     NOT NULL
        COMMENT '内部識別子（UUIDv7）',
    user_id           CHAR(36)     NOT NULL,
    provider_id       CHAR(36)     NOT NULL,
    external_issuer   VARCHAR(512) NOT NULL
        COMMENT 'ID Token の iss。プロバイダ設定を変えても、過去の連携がどの iss のものかを追える',
    external_subject  VARCHAR(255) NOT NULL
        COMMENT 'ID Token の sub。外部 IdP が保証する不変の識別子',
    created_at        DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_used_at      DATETIME(6)  NULL,
    PRIMARY KEY (id),
    -- 1 つの外部アカウントが複数の利用者に結び付かない（乗っ取りの経路にしない）。
    UNIQUE KEY user_external_identities_subject_uk (provider_id, external_subject),
    -- 同じプロバイダを 1 利用者につき 1 つまで（別アカウントの掛け持ちは扱わない）。
    UNIQUE KEY user_external_identities_user_provider_uk (user_id, provider_id),
    KEY user_external_identities_user_idx (user_id),
    CONSTRAINT user_external_identities_user_fk FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT user_external_identities_provider_fk FOREIGN KEY (provider_id)
        REFERENCES external_identity_providers (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- 外部 IdP へのリダイレクトからコールバックまでの進行状態（OIDC の auth_sessions に相当）。
--
-- `state` と `nonce` は CSRF・リプレイ対策として必須で、`code_verifier` は PKCE のために持つ。
-- いずれも秘密なので、`state` は SHA-256 だけを保存し（Cookie 側の生値と突き合わせる方式は取らず、
-- 外部 IdP から戻る `state` そのものを鍵として引く）、`code_verifier` は暗号化して保存する。
CREATE TABLE external_login_requests (
    id                     CHAR(36)     NOT NULL
        COMMENT '内部識別子（UUIDv4。揮発トークン。ADR-0009 §12）',
    tenant_id              CHAR(36)     NOT NULL,
    provider_id            CHAR(36)     NOT NULL,
    state_hash             CHAR(64)     NOT NULL
        COMMENT 'state の SHA-256。外部 IdP から戻った値でこの行を引く',
    nonce                  VARCHAR(128) NOT NULL
        COMMENT 'ID Token の nonce と照合する値',
    code_verifier_encrypted TEXT        NOT NULL
        COMMENT 'PKCE の code_verifier（AES-256-GCM）',
    -- 外部 IdP ログインを OIDC 認可フローの途中で使う場合、戻り先の auth_session を覚えておく。
    -- ポータルログインからの利用では NULL。
    auth_session_id        VARCHAR(128) NULL
        COMMENT '呼び出し元の OIDC auth_session。ポータル経由なら NULL',
    expires_at             DATETIME(6)  NOT NULL,
    created_at             DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY external_login_requests_state_uk (state_hash),
    KEY external_login_requests_expiry_idx (expires_at),
    CONSTRAINT external_login_requests_tenant_fk FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT external_login_requests_provider_fk FOREIGN KEY (provider_id)
        REFERENCES external_identity_providers (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
