-- メールアドレスを登録簿へ移し、ログインに使うかはテナントが決める（ADR-0050）。
--
-- これまで利用者のメールアドレスは `users.email` と `user_login_identifiers`（`email` 種別）の
-- **2 か所にあり、同期していなかった**。そのため次が成立していた:
--
--   A の `users.email` が `a@example.com` のとき、**B のログイン識別子として `a@example.com` を
--   登録できる。** 登録簿には A の行が無いので一意制約に当たらず、`users` 側の一意制約は別の表。
--
-- 本マイグレーションで `users.email` を登録簿の**主メール行**として写し、一意性を
-- `(tenant_id, normalized_value)`（0041。種別横断）の 1 本へ集める。以後、同じテナントの中では
-- 1 つの正規化値は 1 人のものになり、メールはユーザー名・電話番号・社員番号とも衝突しない。
--
-- # 認証の入り口は広がらない
--
-- 0029 は `users.email` を取り込まない理由を「認証の入り口が黙って広がる」と書いた。
-- 本マイグレーションは行を入れるが、**`email` 種別が解決に参加するかは
-- `tenants.email_login_enabled`（既定 0）が決める**（ADR-0050 決定 3）。当てただけでは
-- 何も変わらない。

-- 1. テナント単位のスイッチ。`self_registration_enabled` と同じ形（fail-closed）。
ALTER TABLE tenants
    ADD COLUMN email_login_enabled TINYINT(1) NOT NULL DEFAULT 0
        COMMENT 'メールアドレス種別のログイン識別子を解決に参加させるか（既定 0。ADR-0050）';

-- 2. 主メール行を指す列。`primary_of_user` と同型（1 利用者 1 行・値は必ず自分の user_id）。
ALTER TABLE user_login_identifiers
    ADD COLUMN primary_email_of_user CHAR(36) NULL
        COMMENT '主メール行なら user_id。NULL は主メールでない（ADR-0050）',
    ADD CONSTRAINT user_login_identifiers_primary_email_self_ck
        CHECK (primary_email_of_user IS NULL OR primary_email_of_user = user_id),
    ADD UNIQUE KEY user_login_identifiers_primary_email_uk (primary_email_of_user);

-- 3. 取りこぼしの取り込み（冪等）。`email` 種別の行が既に `users.email` と一致しているなら、
--    新しく作らずにその行を主メール行にする。
UPDATE user_login_identifiers i
JOIN users u ON u.id = i.user_id
SET i.primary_email_of_user = i.user_id
WHERE i.identifier_type = 'email'
  AND i.normalized_value = LOWER(TRIM(u.email))
  AND NOT EXISTS (
      SELECT 1 FROM (SELECT * FROM user_login_identifiers) p
      WHERE p.user_id = i.user_id AND p.primary_email_of_user IS NOT NULL
  );

-- 4. 主メール行を作る。
--
-- ⚠ **同じ正規化値の行を誰かが既に持っているときは作らない**（一意制約に当たるため）。
-- 該当は 2 通りで、意味がまったく違う:
--
--   * **自分が持っている** —— ユーザー名を指定せずに作った利用者は、ユーザー名が
--     メールアドレスの文字列になっている（`unwrap_or_else(|| email.clone())`。ADR-0009 §8）。
--     この値は既にその人のものとして登録簿が守っているので、行を増やさない（ADR-0050 決定 6）。
--   * **他人が持っている** —— 下の guard で止める。黙って落とすとその人だけが入れなくなる。
INSERT INTO user_login_identifiers
    (id, tenant_id, user_id, identifier_type, display_value, normalized_value, is_active,
     primary_email_of_user)
SELECT
    LOWER(CONCAT(
        SUBSTR(HEX(RANDOM_BYTES(4)), 1, 8), '-',
        SUBSTR(HEX(RANDOM_BYTES(2)), 1, 4), '-4',
        SUBSTR(HEX(RANDOM_BYTES(2)), 2, 3), '-a',
        SUBSTR(HEX(RANDOM_BYTES(2)), 2, 3), '-',
        SUBSTR(HEX(RANDOM_BYTES(6)), 1, 12)
    )),
    u.tenant_id,
    u.id,
    'email',
    u.email,
    LOWER(TRIM(u.email)),
    -- 主メールは基本的に有効（ADR-0050 決定 2）。解決に参加するかはテナントのスイッチが決める。
    1,
    u.id
FROM users u
WHERE TRIM(u.email) <> ''
  AND NOT EXISTS (
      SELECT 1 FROM user_login_identifiers p
      WHERE p.user_id = u.id AND p.primary_email_of_user IS NOT NULL
  )
  AND NOT EXISTS (
      SELECT 1 FROM user_login_identifiers x
      WHERE x.tenant_id = u.tenant_id
        AND x.normalized_value = LOWER(TRIM(u.email))
  );

-- 5. 他人に取られている利用者が残っていたら失敗する。
--
-- 見るのは「主メール行があるか」ではなく「**その値が自分のものとして登録簿に在るか**」である。
-- 自分のユーザー名として在るなら主メール行は無くてよい（決定 6）。無いのは他人が握っている
-- ときだけで、それは要件 4（メールは一意）が破れている既存データそのものである。
--
-- 該当者は次で洗い出す（値は PII なので必要な範囲だけ見る）:
--
--   SELECT u.id AS user_id, u.tenant_id, x.user_id AS taken_by, x.identifier_type
--   FROM users u
--   JOIN user_login_identifiers x
--     ON x.tenant_id = u.tenant_id AND x.normalized_value = LOWER(TRIM(u.email))
--   WHERE x.user_id <> u.id;
CREATE TABLE IF NOT EXISTS adr0050_migration_guard (
    users_whose_email_belongs_to_someone_else INT NOT NULL,
    CONSTRAINT every_users_email_must_be_their_own_in_the_registry
        CHECK (users_whose_email_belongs_to_someone_else = 0)
);

INSERT INTO adr0050_migration_guard (users_whose_email_belongs_to_someone_else)
SELECT COUNT(*)
FROM users u
WHERE TRIM(u.email) <> ''
  AND EXISTS (
      SELECT 1 FROM user_login_identifiers x
      WHERE x.tenant_id = u.tenant_id
        AND x.normalized_value = LOWER(TRIM(u.email))
        AND x.user_id <> u.id
  );

DROP TABLE adr0050_migration_guard;
