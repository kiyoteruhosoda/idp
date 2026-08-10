-- 主たるログイン識別子を登録簿だけに置く（AP15b。AP8 の contract フェーズ **後半**）。
--
-- 0036（前半）で主識別子は登録簿（`user_login_identifiers.primary_of_user`）と
-- `users.preferred_username` の**両方**に載るようになった。解決は「登録簿 → `users`」の順で、
-- どちらが欠けてもログインできた。本マイグレーションでその期間を終わらせ、列を落とす。
--
-- # 適用してよい条件
--
-- **0036 を含むリリースが全ノードへ行き渡っていること。** `users` しか書かない古いプロセスが
-- 残っている間に列を落とすと、そのプロセスが作った利用者・変更したユーザー名が登録簿に載らず、
-- ログインできない利用者が出る。
--
-- # 移送できていない利用者は、ここで**止める**
--
-- 同じ値が既に**他人**の識別子として登録簿に在る利用者は、0036 でも実行時の同期でも登録簿へ
-- 写せていない（一意制約に当たるため）。その利用者は今まで `users.preferred_username` への
-- フォールバックで解決され続けていた。列を落とすと、**その人だけがユーザー名でログインできなく
-- なる**。件数が少なく、当人以外には見えない壊れ方なので、運用で気づける形にしておく必要がある。
--
-- そこで下の guard 表で件数を突き合わせ、残っていればマイグレーションを失敗させる。値の重複を
-- 解消（どちらかのユーザー名を変更）してから再実行する。

-- 1. 取りこぼしの取り込み（冪等）。0036 の後に古いプロセスが作った・変更した利用者を拾う。
UPDATE user_login_identifiers i
JOIN users u ON u.id = i.user_id
SET i.primary_of_user = i.user_id
WHERE i.identifier_type = 'username'
  AND u.preferred_username IS NOT NULL
  AND i.normalized_value = LOWER(TRIM(u.preferred_username))
  AND NOT EXISTS (
      SELECT 1 FROM (SELECT * FROM user_login_identifiers) p
      WHERE p.user_id = i.user_id AND p.primary_of_user IS NOT NULL
  );

INSERT INTO user_login_identifiers
    (id, tenant_id, user_id, identifier_type, display_value, normalized_value, is_active,
     primary_of_user)
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
    'username',
    u.preferred_username,
    LOWER(TRIM(u.preferred_username)),
    1,
    u.id
FROM users u
WHERE u.preferred_username IS NOT NULL
  AND TRIM(u.preferred_username) <> ''
  AND NOT EXISTS (
      SELECT 1 FROM user_login_identifiers p
      WHERE p.user_id = u.id AND p.primary_of_user IS NOT NULL
  )
  AND NOT EXISTS (
      SELECT 1 FROM user_login_identifiers x
      WHERE x.tenant_id = u.tenant_id
        AND x.identifier_type = 'username'
        AND x.normalized_value = LOWER(TRIM(u.preferred_username))
  );

-- 2. 移送できなかった利用者が残っていたら、列を落とす前に失敗する。
--
-- 制約名がそのままエラー文になる（`CONSTRAINT ... failed`）ので、何を直せばよいかが読める。
-- 該当者は次で洗い出せる:
--
--   SELECT u.id, u.tenant_id FROM users u
--   WHERE u.preferred_username IS NOT NULL AND TRIM(u.preferred_username) <> ''
--     AND NOT EXISTS (SELECT 1 FROM user_login_identifiers p
--                     WHERE p.user_id = u.id AND p.primary_of_user IS NOT NULL);
CREATE TABLE IF NOT EXISTS ap15b_migration_guard (
    users_without_a_primary_login_identifier INT NOT NULL,
    CONSTRAINT resolve_duplicate_usernames_before_dropping_the_column
        CHECK (users_without_a_primary_login_identifier = 0)
);

INSERT INTO ap15b_migration_guard (users_without_a_primary_login_identifier)
SELECT COUNT(*)
FROM users u
WHERE u.preferred_username IS NOT NULL
  AND TRIM(u.preferred_username) <> ''
  AND NOT EXISTS (
      SELECT 1 FROM user_login_identifiers p
      WHERE p.user_id = u.id AND p.primary_of_user IS NOT NULL
  );

DROP TABLE ap15b_migration_guard;

-- 3. 列と一意制約を落とす。以後、主識別子と追加識別子の衝突は登録簿の一意制約
--    （tenant × 種別 × 正規化値）が防ぐ —— expand の間はアプリ層の事前チェックしか
--    張れず、同時実行の窓が残っていた（ADR-0025「残る限界」）。
ALTER TABLE users
    DROP INDEX users_tenant_preferred_username_uk,
    DROP COLUMN preferred_username;
