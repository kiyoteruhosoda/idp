-- SAML SP（サービスプロバイダ＝クライアント）登録。テナント単位で SP メタデータを永続化する。
-- 本プロダクトは IdP であり、SP（クライアント）を登録して SAML アサーションの送信先（ACS）を管理する。
--
-- テーブルオプション（ENGINE / CHARSET / COLLATE）は他の全テーブル（0001 baseline 以降）と一致させる。
-- これを省くとサーバ既定の照合順序で作成され、`tenants(id)`（utf8mb4_unicode_ci）を参照する外部キーが
-- 照合順序不一致で errno 150 になり CREATE 自体が失敗する。時刻列は UTC の DATETIME(6)。
-- x509_certificate は任意（SP が AuthnRequest 署名やアサーション暗号化を要求する場合のみ）。
CREATE TABLE saml_service_providers (
    id CHAR(36) NOT NULL PRIMARY KEY,
    tenant_id CHAR(36) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    entity_id VARCHAR(1024) NOT NULL,
    acs_url VARCHAR(2048) NOT NULL,
    name_id_format VARCHAR(255) NOT NULL,
    x509_certificate TEXT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    CONSTRAINT fk_saml_service_providers_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT uq_saml_service_providers_tenant_entity
        UNIQUE (tenant_id, entity_id),
    INDEX idx_saml_service_providers_tenant (tenant_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
