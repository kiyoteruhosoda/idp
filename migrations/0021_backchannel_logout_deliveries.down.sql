-- 送信キューと sid の持ち回り列を取り除く（未送信の通知要求は失われる）。
DROP TABLE IF EXISTS backchannel_logout_deliveries;

ALTER TABLE refresh_tokens DROP COLUMN sid;
ALTER TABLE authorization_codes DROP COLUMN sid;
ALTER TABLE auth_sessions DROP COLUMN sso_sid;
