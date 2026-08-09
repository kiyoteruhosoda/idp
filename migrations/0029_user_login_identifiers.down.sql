-- 登録簿を落とす。主たるログイン識別子は `users.preferred_username` にあり本表には写して
-- いないため（expand フェーズ。up 側のコメント参照）、パスワードログインは通り続ける。
-- 追加登録した識別子（電話番号・社員番号・別名のユーザー名）は失われる。
DROP TABLE IF EXISTS user_login_identifiers;
