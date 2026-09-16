-- 0058 の巻き戻し。
--
-- ⚠ **サービスアカウントと宛名の名乗りは消える**（0058 より前の表には置き場が無い）。消えると、
--   そのサービスアカウントの self の名簿は 403 に、管理権限を持たないサービスアカウントの
--   管理トークンは `invalid_target` に倒れる。
--
-- 消したサービスアカウントのアプリは、0054 と同じ形（アプリ 1 件 ＋ OIDC binding 1 件、
-- `id` は `clients.id`）で作り直す。割り当ては元から 0 件だったもの（up がそれを確かめてから
-- 消した）なので、失うものは無い。
DELETE FROM application_bindings WHERE kind IN ('service_account', 'resource');

ALTER TABLE application_bindings
    DROP FOREIGN KEY application_bindings_resource_fk,
    DROP CONSTRAINT application_bindings_target_chk,
    DROP CONSTRAINT application_bindings_kind_chk;

ALTER TABLE application_bindings
    DROP INDEX application_bindings_resource_uk,
    DROP COLUMN resource_id;

ALTER TABLE application_bindings
    RENAME COLUMN kind TO protocol;

ALTER TABLE application_bindings
    MODIFY COLUMN protocol VARCHAR(16) NOT NULL COMMENT 'oidc / saml',
    MODIFY COLUMN client_id CHAR(36) NULL COMMENT 'protocol = oidc のときの clients.id',
    ADD CONSTRAINT application_bindings_protocol_chk CHECK (protocol IN ('oidc', 'saml')),
    ADD CONSTRAINT application_bindings_target_chk CHECK (
        (protocol = 'oidc' AND client_id IS NOT NULL AND service_provider_id IS NULL)
        OR
        (protocol = 'saml' AND service_provider_id IS NOT NULL AND client_id IS NULL)
    );

INSERT INTO applications (id, tenant_id, display_name, status, assignment_mode, created_at, updated_at)
SELECT
    c.id,
    c.tenant_id,
    c.app_name,
    CASE WHEN c.client_status = 'ACTIVE' THEN 'ACTIVE' ELSE 'DISABLED' END,
    'INDIVIDUAL',
    c.created_at,
    c.updated_at
FROM clients c
WHERE JSON_CONTAINS(c.grant_types, '"client_credentials"')
  AND NOT JSON_CONTAINS(c.grant_types, '"authorization_code"')
  AND NOT EXISTS (SELECT 1 FROM application_bindings b WHERE b.client_id = c.id)
  AND NOT EXISTS (SELECT 1 FROM applications a WHERE a.id = c.id);

INSERT INTO application_bindings (id, application_id, protocol, client_id, service_provider_id, created_at)
SELECT c.id, c.id, 'oidc', c.id, NULL, c.created_at
FROM clients c
JOIN applications a ON a.id = c.id
WHERE JSON_CONTAINS(c.grant_types, '"client_credentials"')
  AND NOT JSON_CONTAINS(c.grant_types, '"authorization_code"')
  AND NOT EXISTS (SELECT 1 FROM application_bindings b WHERE b.client_id = c.id);
