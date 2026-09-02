-- 0048 の巻き戻し。権限コードのマスタも消す（付与行は client_permissions の
-- ON DELETE RESTRICT に当たるため、先に剥奪しておくこと）。
DROP TABLE IF EXISTS client_resources;
DROP TABLE IF EXISTS resources;
DELETE FROM permissions WHERE code IN ('idp.resources:read', 'idp.resources:write');
