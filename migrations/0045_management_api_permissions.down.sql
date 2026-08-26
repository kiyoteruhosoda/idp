-- 0045 の巻き戻し（ADR-0037）。
--
-- 先に `client_permissions` を落とす。権限コードのマスタ行を消す前にこの表を消さないと、
-- `client_permissions_code_fk`（ON DELETE RESTRICT）がマスタ行の削除を拒む。
DROP TABLE IF EXISTS client_permissions;

-- 細粒度コードを付与された利用者の行を先に落とす（`user_permissions_code_fk` は RESTRICT）。
-- 巻き戻し後は `idp.tenant.admin` を持つ管理者だけが管理 API を通る状態へ戻る。細粒度コード
-- しか持たない主体は権限を失う —— 巻き戻しとはそういう操作であり、誰が何を持っていたかは
-- 監査ログ（`user_permission.granted`）から復元できる。
DELETE FROM user_permissions
 WHERE permission_code IN (
    'idp.users:read', 'idp.users:write',
    'idp.clients:read', 'idp.clients:write',
    'idp.members:read', 'idp.members:write',
    'idp.permissions:read', 'idp.permissions:write',
    'idp.audit:read',
    'idp.keys:read', 'idp.keys:write',
    'idp.tenant-settings:read', 'idp.tenant-settings:write',
    'idp.authentication-policies:read', 'idp.authentication-policies:write',
    'idp.external-idps:read', 'idp.external-idps:write',
    'idp.saml-service-providers:read', 'idp.saml-service-providers:write');

DELETE FROM permissions
 WHERE code IN (
    'idp.users:read', 'idp.users:write',
    'idp.clients:read', 'idp.clients:write',
    'idp.members:read', 'idp.members:write',
    'idp.permissions:read', 'idp.permissions:write',
    'idp.audit:read',
    'idp.keys:read', 'idp.keys:write',
    'idp.tenant-settings:read', 'idp.tenant-settings:write',
    'idp.authentication-policies:read', 'idp.authentication-policies:write',
    'idp.external-idps:read', 'idp.external-idps:write',
    'idp.saml-service-providers:read', 'idp.saml-service-providers:write');
