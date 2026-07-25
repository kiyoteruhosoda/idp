-- 0014 の巻き戻し: `saml_identity_providers` を 0008 と同一の定義で再作成する。
--
-- テーブルオプション（ENGINE / CHARSET / COLLATE）は他の全テーブルと一致させる。これを省くと
-- サーバ既定の照合順序で作成され、`tenants(id)`（utf8mb4_unicode_ci）を参照する外部キーが
-- 照合順序不一致で errno 150 になり CREATE 自体が失敗する。
-- 行データは復元しない（contract 済みのため保持していない）。
CREATE TABLE IF NOT EXISTS saml_identity_providers (
    id CHAR(36) NOT NULL PRIMARY KEY,
    tenant_id CHAR(36) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    entity_id VARCHAR(1024) NOT NULL,
    sso_url VARCHAR(2048) NOT NULL,
    x509_certificate TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    CONSTRAINT fk_saml_identity_providers_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT uq_saml_identity_providers_tenant_entity
        UNIQUE (tenant_id, entity_id),
    INDEX idx_saml_identity_providers_tenant (tenant_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
