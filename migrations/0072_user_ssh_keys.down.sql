-- 0072 の巻き戻し。付与行を先に消してからマスタを消す（ON DELETE RESTRICT）。
DELETE FROM client_permissions WHERE permission_code = 'idp.ssh-keys:read';
DELETE FROM user_permissions   WHERE permission_code = 'idp.ssh-keys:read';
DELETE FROM permissions        WHERE code            = 'idp.ssh-keys:read';
DROP TABLE IF EXISTS user_ssh_keys;
