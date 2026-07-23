-- 0013 の逆操作: 初期管理者のログイン識別子（preferred_username）を既定の 'admin' へ戻す。
-- 0013 が 'admin@example.com' へ更新した行に限定する（運用者が別名へ変えた行は戻さない）。
-- root は parent_tenant_id IS NULL の唯一の行として構造的に特定する。
SET @root := (SELECT id FROM tenants WHERE parent_tenant_id IS NULL);

UPDATE users
SET preferred_username = 'admin'
WHERE tenant_id = @root
  AND email = 'admin@example.com'
  AND preferred_username = 'admin@example.com';
