-- SAML SP-initiated SSO の進行状態（OIDC の auth_sessions に相当）。
--
-- `/{tenant_id}/saml/sso` が AuthnRequest を検証して 1 行作成し、単回・短命のハンドルを
-- web へのリダイレクト URL に載せる（ADR-0018 のハンドオフ方式を SAML にも適用する）。
-- web は `/internal/saml/resume` でハンドルを 1 回だけ交換し（交換時に NULL へ消費）、
-- SSO 未確立の間は行 id（`saml_request_id` Cookie）で再開する。応答発行時に行を削除する。
--
-- テーブルオプション（ENGINE / CHARSET / COLLATE）は他の全テーブルと一致させる
-- （不一致だと参照先との照合順序差で外部キー作成が errno 150 になる）。時刻は UTC の DATETIME(6)。
CREATE TABLE saml_sso_requests (
    -- id は 128bit 以上の推測不能なランダム値（256bit 乱数の小文字 16 進 = 64 文字を想定）。
    id                  VARCHAR(64)   NOT NULL,
    tenant_id           CHAR(36)      NOT NULL,
    service_provider_id CHAR(36)      NOT NULL,
    -- AuthnRequest の Issuer（登録 SP の entity_id。応答の Audience に使う）。
    sp_entity_id        VARCHAR(1024) NOT NULL,
    -- 検証済みのアサーション送信先（登録 SP の acs_url）。
    acs_url             VARCHAR(2048) NOT NULL,
    -- AuthnRequest の ID（応答の InResponseTo。無署名リクエストで省略され得るため NULL 許容）。
    request_id          VARCHAR(1024) NULL,
    -- SP が送った RelayState（応答フォームで透過返却する）。
    relay_state         VARCHAR(1024) NULL,
    -- web ハンドオフ用ハンドルの SHA-256（単回使用。交換時に NULL へ消費）。
    handle_hash         CHAR(64)      NULL,
    -- ハンドルの有効期限（UTC。本体の expires_at より短命）。
    handle_expires_at   DATETIME(6)   NULL,
    expires_at          DATETIME(6)   NOT NULL,
    created_at          DATETIME(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY saml_sso_requests_handle_uq (handle_hash),
    KEY saml_sso_requests_expires_idx (expires_at),
    CONSTRAINT saml_sso_requests_sp_fk FOREIGN KEY (service_provider_id)
        REFERENCES saml_service_providers (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
