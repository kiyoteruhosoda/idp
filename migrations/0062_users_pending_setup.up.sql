-- 仮登録（本人がまだ設定を終えていない利用者。ADR-0064）。
--
-- 管理者が作った利用者は、本人が設定リンクでパスキーを登録するかパスワードを決めるまで
-- 誰も入れない（ADR-0062）。それでも状態は ACTIVE で、一覧にも名簿にも「有効」と出ていた。
--
-- ⚠ `status` の値を増やさない。仮登録は「有効 / 無効」と**直交する**事実である
--   ——仮登録のまま無効にし、また有効に戻す、ができなければならない。値を 1 つ増やすと、
--   有効に戻した瞬間に「本人がまだ何も決めていない」が失われる。
ALTER TABLE users
    ADD COLUMN pending_setup TINYINT(1) NOT NULL DEFAULT 0
        COMMENT '仮登録（本人が設定リンクでまだ資格情報を決めていない）。1 の間はログインできない'
        AFTER status;

-- 既に在る「作られたが、まだ設定されていない」利用者を仮登録へ倒す。
--
-- 条件は「作成と同時に出た設定リンク（作成から 1 分以内の `setup`）があり、どの `setup`
-- リンクも使われておらず、認証器が 1 つも無く、パスワード変更がまだ要る」。
-- ⚠ 管理者の再発行で出たリンク（作成から時間が経っている）は対象にしない ——その人は
--   一度は自分で入っている。
UPDATE users u
SET u.pending_setup = 1
WHERE u.must_change_password = 1
  AND EXISTS (
      SELECT 1 FROM password_reset_tokens t
      WHERE t.user_id = u.id AND t.purpose = 'setup'
        AND t.created_at BETWEEN u.created_at AND DATE_ADD(u.created_at, INTERVAL 1 MINUTE))
  AND NOT EXISTS (
      SELECT 1 FROM password_reset_tokens t
      WHERE t.user_id = u.id AND t.purpose = 'setup' AND t.used_at IS NOT NULL)
  AND NOT EXISTS (SELECT 1 FROM user_authenticators a WHERE a.user_id = u.id);
