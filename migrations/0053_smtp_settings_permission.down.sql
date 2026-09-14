-- ADR-0051 の巻き戻し。
--
-- 付与行を先に消してからマスタを消す（`client_permissions` / `user_permissions` の
-- `permission_code` は `permissions.code` を ON DELETE RESTRICT で参照している）。
DELETE FROM client_permissions WHERE permission_code IN ('idp.smtp:read', 'idp.smtp:write');
DELETE FROM user_permissions   WHERE permission_code IN ('idp.smtp:read', 'idp.smtp:write');
DELETE FROM permissions        WHERE code            IN ('idp.smtp:read', 'idp.smtp:write');
