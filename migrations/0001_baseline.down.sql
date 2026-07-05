-- ベースラインのロールバック。FK 依存の逆順で削除する。
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS authorization_codes;
DROP TABLE IF EXISTS sso_sessions;
DROP TABLE IF EXISTS auth_sessions;
DROP TABLE IF EXISTS signing_keys;
DROP TABLE IF EXISTS clients;
DROP TABLE IF EXISTS users;
