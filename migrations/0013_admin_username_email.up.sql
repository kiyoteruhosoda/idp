-- 初期管理者 admin@example.com のログイン識別子（preferred_username）を、メールアドレスと同じ
-- 'admin@example.com' へ更新する。
--
-- ログイン画面は email ではなく preferred_username で照合する（ADR-0009 §8。application/login.rs・
-- admin_login.rs はいずれも find_by_username を使い、メールアドレスでの照合は行わない）。初期案内の
-- 「admin@example.com でログイン」を成立させるため、ユーザー名を admin@example.com に揃える。
--
-- 0002 seed が投入した既定ユーザー名 'admin' のままの行に限定して置き換える。運用者が既に別名へ
-- 変更した行は上書きしない。追記型マイグレーション（migrations/README.md）に従い 0002 は書き換えず、
-- 本マイグレーションで更新する。root は parent_tenant_id IS NULL の唯一の行として構造的に特定する
-- （0002・0009 と同じ方針）。
--
-- 冪等性: 再適用しても WHERE 条件（preferred_username = 'admin'）で除外されるため二重更新されない。
-- 一意制約 (tenant_id, preferred_username) は、同一テナントに 'admin@example.com' を既に使う別行が
-- 無い限り違反しない（新規 seed 直後は該当行のみが 'admin' を持つため安全）。
SET @root := (SELECT id FROM tenants WHERE parent_tenant_id IS NULL);

UPDATE users
SET preferred_username = 'admin@example.com'
WHERE tenant_id = @root
  AND email = 'admin@example.com'
  AND preferred_username = 'admin';
