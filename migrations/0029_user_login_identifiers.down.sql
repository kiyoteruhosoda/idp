-- 登録簿を落とす。主たるログイン識別子は `users.preferred_username` に残したままなので
-- （expand フェーズ。up 側のコメント参照）、パスワードログインは引き続き通る。
-- 追加登録した識別子（電話番号・社員番号・別名のユーザー名）は失われる。
DROP TABLE IF EXISTS user_login_identifiers;
