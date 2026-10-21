-- 0065 の巻き戻し。付与行を先に消してからマスタを消す（ON DELETE RESTRICT）。
DELETE FROM client_permissions WHERE permission_code = 'idp.admins:write';
DELETE FROM user_permissions   WHERE permission_code = 'idp.admins:write';
DELETE FROM permissions        WHERE code            = 'idp.admins:write';
