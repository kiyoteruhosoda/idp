-- root テナントの既定表示名を 'Root' から 'ROOT' へ改める（管理コンソールでの表示を大文字 ROOT に統一）。
-- 0002 の seed は checksum 固定のため直接書き換えず、後続マイグレーションで既定値のみを更新する。
-- 運用者が既に別名へ変更している場合は上書きしない（既定値 'Root' のときだけ 'ROOT' にする）。
-- root は `parent_tenant_id IS NULL` の唯一の行として構造的に識別する（0002 と同じ方針）。
UPDATE tenants
SET    name = 'ROOT'
WHERE  parent_tenant_id IS NULL
  AND  name = 'Root';
