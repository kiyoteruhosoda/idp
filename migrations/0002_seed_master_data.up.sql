-- マスタデータ seed（ADR-0009 §1・§4・§5、Phase 1）。
--   1. root テナント（UUIDv7 を投入時に動的採番。固定リテラルは使わない）
--   2. user_permissions への CHECK 制約付与: idp.system.admin の scope = root
--      （root UUID は投入時に確定しているため、解決値をリテラル化して PREPARE/EXECUTE で付与する）
--   3. 権限コードのマスタ（idp.system.admin / idp.tenant.admin。許可値の単一出所）
--   4. 初期管理者 admin@example.com（root 所属・HOME メンバーシップ・idp.system.admin を DB 直接投与）
--
-- 冪等性: すべて「存在しなければ挿入」で書く。再適用しても既存行（変更済みパスワード等）を初期値へ
-- 戻さず、UUID を再採番しない。root は `parent_tenant_id IS NULL` の唯一の行として構造的に識別する
-- （is_root 番兵列 + UNIQUE により DB レベルで高々 1 行）。
--
-- root UUID は環境ごとに異なる。確認手順（ログイン URL の確定に必要）:
--   SELECT id FROM tenants WHERE parent_tenant_id IS NULL;
-- 詳細は docs/OPERATIONS.md「root テナントの UUID を確認したいとき」。

-- ---------------------------------------------------------------------------
-- UUIDv7 の組み立て（MariaDB 10.11 には UUID_v7() が無いため手組みする）:
--   unix time (ms) 48bit ＋ version 7 (4bit) ＋ rand 12bit ＋ variant 10 (2bit) ＋ rand 62bit。
--   乱数は SHA2(UUID(), RAND(), ...) から取る（識別子であり秘密値ではない）。
-- ---------------------------------------------------------------------------

-- 1) root テナント（存在しなければ動的採番して挿入）
SET @ts_hex := LPAD(HEX(CAST(FLOOR(UNIX_TIMESTAMP(NOW(3)) * 1000) AS UNSIGNED)), 12, '0');
SET @rand_hex := LOWER(SHA2(CONCAT(UUID(), RAND(), RAND(), 'tenant-root'), 256));
SET @root_candidate := LOWER(CONCAT(
    SUBSTR(@ts_hex, 1, 8), '-', SUBSTR(@ts_hex, 9, 4),
    '-7', SUBSTR(@rand_hex, 1, 3),
    '-', HEX(8 | (CONV(SUBSTR(@rand_hex, 4, 1), 16, 10) & 3)), SUBSTR(@rand_hex, 5, 3),
    '-', SUBSTR(@rand_hex, 8, 12)));

INSERT INTO tenants (id, parent_tenant_id, name, status)
SELECT @root_candidate, NULL, 'Root', 'ACTIVE'
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM tenants WHERE parent_tenant_id IS NULL);

-- 以降は「解決した root UUID」を使う（is_root 番兵列により常に一意に定まる）。
SET @root := (SELECT id FROM tenants WHERE parent_tenant_id IS NULL);

-- 2) CHECK 制約: idp.system.admin は root scope でしか存在できない（ADR-0009 §4）。
--    MariaDB の CHECK はサブクエリ不可のため、解決済み root UUID をリテラル化して付与する。
--    マイグレーションファイル自体は静的（チェックサムは全環境で一致）。制約に埋め込まれる
--    リテラルは環境ごとの root UUID になるが、CHECK は各 DB ローカルの定義なので問題ない。
SET @chk_exists := (
    SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS
    WHERE CONSTRAINT_SCHEMA = DATABASE()
      AND TABLE_NAME = 'user_permissions'
      AND CONSTRAINT_NAME = 'user_permissions_system_admin_scope_chk');
SET @ddl := IF(@chk_exists = 0,
    CONCAT(
        'ALTER TABLE user_permissions ADD CONSTRAINT user_permissions_system_admin_scope_chk ',
        'CHECK (permission_code <> ''idp.system.admin'' OR tenant_id = ''', @root, ''')'),
    'DO 0');
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 3) 権限コードのマスタ（許可値の単一出所。ADR-0009 §4）
INSERT INTO permissions (code, description) VALUES
    ('idp.system.admin',
     'System administration (scope = root only): system settings, grant/revoke idp.system.admin, tenant creation/deletion'),
    ('idp.tenant.admin',
     'Tenant administration (scope = the tenant): users, clients, tenant settings, members/invitations')
ON DUPLICATE KEY UPDATE description = VALUES(description);

-- 4) 初期管理者（root テナント所属。設計仕様 §3.1・ADR-0009 Phase 1-5）
--    「変更前提のデフォルト値」として seed する。password_hash はアプリと同一の
--    Argon2id（PHC 文字列）で、既定パスワードは 'ChangeMe!123'
--    （平文はコードに保持しない。変更手順は docs/OPERATIONS.md）。
--    must_change_password = 1: 初回ログイン時にパスワード変更へ強制誘導する（誘導の実装はアプリ層）。
SET @ts_hex := LPAD(HEX(CAST(FLOOR(UNIX_TIMESTAMP(NOW(3)) * 1000) AS UNSIGNED)), 12, '0');
SET @rand_hex := LOWER(SHA2(CONCAT(UUID(), RAND(), RAND(), 'admin-id'), 256));
SET @admin_candidate := LOWER(CONCAT(
    SUBSTR(@ts_hex, 1, 8), '-', SUBSTR(@ts_hex, 9, 4),
    '-7', SUBSTR(@rand_hex, 1, 3),
    '-', HEX(8 | (CONV(SUBSTR(@rand_hex, 4, 1), 16, 10) & 3)), SUBSTR(@rand_hex, 5, 3),
    '-', SUBSTR(@rand_hex, 8, 12)));
SET @rand_hex := LOWER(SHA2(CONCAT(UUID(), RAND(), RAND(), 'admin-sub'), 256));
SET @sub_candidate := LOWER(CONCAT(
    SUBSTR(@ts_hex, 1, 8), '-', SUBSTR(@ts_hex, 9, 4),
    '-7', SUBSTR(@rand_hex, 1, 3),
    '-', HEX(8 | (CONV(SUBSTR(@rand_hex, 4, 1), 16, 10) & 3)), SUBSTR(@rand_hex, 5, 3),
    '-', SUBSTR(@rand_hex, 8, 12)));

INSERT INTO users (
    id, tenant_id, sub, email, email_verified, preferred_username, name,
    password_hash, must_change_password, status
)
SELECT
    @admin_candidate, @root, @sub_candidate, 'admin@example.com', 1, 'admin', 'Administrator',
    '$argon2id$v=19$m=65536,t=3,p=4$rDuN4UZ1uO9aCuJjci4tQw$9qhizRUIJntV/0+5fsyfdKt5Xmjw6WyEmPOLkOhY7QM',
    1, 'ACTIVE'
FROM DUAL
WHERE NOT EXISTS (
    SELECT 1 FROM users WHERE tenant_id = @root AND email = 'admin@example.com');

SET @admin := (
    SELECT id FROM users WHERE tenant_id = @root AND email = 'admin@example.com');

-- HOME メンバーシップ（users.tenant_id が単一の出所、この行はフロー判定用の投影。ADR-0009 §3）
INSERT INTO tenant_memberships (tenant_id, user_id, membership_type, status)
VALUES (@root, @admin, 'HOME', 'ACTIVE')
ON DUPLICATE KEY UPDATE tenant_id = tenant_id;

-- idp.system.admin（scope = root）を DB 直接投入で付与する。
-- アプリ経由で「最初の idp.system.admin」を作成する導線は存在しない（ADR-0009 §4）。
INSERT INTO user_permissions (user_id, permission_code, tenant_id)
VALUES (@admin, 'idp.system.admin', @root)
ON DUPLICATE KEY UPDATE user_id = user_id;
