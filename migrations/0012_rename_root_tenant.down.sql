-- up の逆操作: 既定表示名を 'ROOT' から seed 時の 'Root' へ戻す（運用者が別名へ変更した行は触らない）。
UPDATE tenants
SET    name = 'Root'
WHERE  parent_tenant_id IS NULL
  AND  name = 'ROOT';
