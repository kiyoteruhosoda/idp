-- 履歴と設定時刻を落とす。パスワード認証そのものは `users.password_hash` だけで成立するため
-- ログインは通り続ける。失われるのは「過去パスワードの再利用禁止」と「有効期限」の判定材料で、
-- 戻した後は両ポリシーが（設定値に関わらず）一致しなくなる。
ALTER TABLE users DROP COLUMN password_changed_at;

DROP TABLE IF EXISTS user_password_history;
