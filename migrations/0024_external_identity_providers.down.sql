-- 外部 IdP 連携を取り除く。外部 IdP でしかログイン手段を持たない利用者は、ロールバック後は
-- パスワードでのログインへ戻ることになる（連携行が消えるため）。
DROP TABLE IF EXISTS external_login_requests;
DROP TABLE IF EXISTS user_external_identities;
DROP TABLE IF EXISTS external_identity_providers;
