-- 主たるログイン識別子を登録簿へ移す（AP15。AP8 の contract フェーズ **前半**）。
--
-- AP8（0029）で入れたのは expand フェーズまでで、主たるログイン識別子は
-- `users.preferred_username` に残り、登録簿には**追加の識別子だけ**が入っていた。解決は
-- 「登録簿の有効な行 → `users.preferred_username`」の順で、一覧 API は主識別子を読み出し時に
-- 合成して返していた（`id` が `null` の行）。
--
-- # なぜ 2 回に分けるか
--
-- 主識別子の移送は失敗すると**誰もログインできなくなる**操作である。しかもローリングデプロイ中は
-- 古いプロセス（`users.preferred_username` を書く）が動き続ける。そこで:
--
--   * 本マイグレーション（+ 同じリリースのコード）＝ **両方に在る期間**。登録簿へ主識別子の行を
--     作り、以後の更新は両方へ書く。解決は従来どおり「登録簿 → `users`」の順で、どちらが欠けても
--     ログインできる。
--   * 次のリリース ＝ `users.preferred_username` の撤去（contract）と、フォールバック・合成行の削除。
--
-- # `primary_of_user` 列
--
-- 「どの行が主か」を登録簿の中で表せなければ、`preferred_username` クレーム・利用者一覧の表示・
-- プロフィール編集の移送先が決まらない。追加の識別子とは扱いが違う（主識別子は識別子単位で
-- 削除・無効化できない）ため、種別ではなくこの列で区別する。
--
-- 「1 利用者に主識別子は 1 つ」は **NULL 可の列 + UNIQUE** で DB に守らせる。MariaDB に部分
-- UNIQUE 索引は無いが、**UNIQUE 索引は複数の NULL を許す**ので、主でない行を NULL にすれば同じ
-- 制約になる（`CLAUDE.md`「DB モデリング」の読み替えどおり）。
--
-- 真偽値の `is_primary` 列を別に持たないのは、同じ事実が 2 か所になると片方だけ更新される余地が
-- 生まれるため。「主かどうか」は `primary_of_user IS NOT NULL` で読む。値が**必ず自分の
-- `user_id`** であることは CHECK で縛る（他人の id を入れれば他人の主識別子を奪えてしまう）。
-- 生成列（`AS (CASE ...) VIRTUAL`）にしないのは、MariaDB 10.11 が生成列の式にこの形を許さない
-- ため（`ER_GENERATED_COLUMN_FUNCTION_IS_NOT_ALLOWED`）。

ALTER TABLE user_login_identifiers
    ADD COLUMN primary_of_user CHAR(36) NULL
        COMMENT '主たるログイン識別子なら自分の user_id、そうでなければ NULL。主は利用者につき 1 行まで（識別子単位の削除・無効化はできない）'
        AFTER is_active,
    ADD CONSTRAINT user_login_identifiers_primary_ck
        CHECK (primary_of_user IS NULL OR primary_of_user = user_id),
    ADD UNIQUE KEY user_login_identifiers_primary_uk (primary_of_user);

-- 既に登録簿へ同じ値の行がある利用者（管理者が `preferred_username` と同じ値を追加識別子として
-- 足していた場合）は、その行を主へ格上げする。新しく作ると一意制約（tenant × 種別 × 正規化値）に
-- ぶつかる。
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

-- 残り（登録簿に無い主識別子）を作る。id の作り方は 0023 / 0035 と同じ理由で v4 相当
-- （登録簿の id は時系列ソートに使わない）。
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
  -- 既に主を持つ利用者（上の UPDATE で格上げ済み）は作らない。
  AND NOT EXISTS (
      SELECT 1 FROM user_login_identifiers p
      WHERE p.user_id = u.id AND p.primary_of_user IS NOT NULL
  )
  -- 同じ値が**他人**の識別子として既に登録されている場合は作れない（一意制約）。その利用者は
  -- `users.preferred_username` で解決され続ける（フォールバックは次のリリースまで残る）ので、
  -- ログインは通る。撤去の前に運用で解消する必要があり、`docs/Progress.md` に残してある。
  AND NOT EXISTS (
      SELECT 1 FROM user_login_identifiers x
      WHERE x.tenant_id = u.tenant_id
        AND x.identifier_type = 'username'
        AND x.normalized_value = LOWER(TRIM(u.preferred_username))
  );
