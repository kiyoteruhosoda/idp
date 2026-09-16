-- ADR-0054 の巻き戻し。判定より前の段階（表と移行だけ）なので、落としても挙動は変わらない。
-- 割り当ての行は復元できないため、`down` を流すのは「まだ誰にも配っていない」ときに限る。
--
-- 付与行を先に消してからマスタを消す（`client_permissions` / `user_permissions` の
-- `permission_code` は `permissions.code` を ON DELETE RESTRICT で参照している）。
DELETE FROM client_permissions WHERE permission_code IN ('idp.applications:read', 'idp.applications:write');
DELETE FROM user_permissions   WHERE permission_code IN ('idp.applications:read', 'idp.applications:write');
DELETE FROM permissions        WHERE code            IN ('idp.applications:read', 'idp.applications:write');

DROP TABLE IF EXISTS application_assignments;
DROP TABLE IF EXISTS application_bindings;
DROP TABLE IF EXISTS applications;
