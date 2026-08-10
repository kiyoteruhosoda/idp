-- 登録簿へ写した秘密を消し、`credential_id` 列を落とす。
--
-- 元の表（`user_totp_secrets` / `user_webauthn_credentials`）は本マイグレーションで触っていない
-- （書き込みは両方へ行うため、どちらにも最新の値がある）。したがって秘密を戻す必要は無く、
-- 登録簿側を空に戻すだけで元の状態になる。
--
-- ただし**このマイグレーションを適用した後に登録された認証器**は、元の表にも書かれているので
-- 失われない（同じリリースのコードが両方へ書く）。ここで消すのは登録簿側の写しだけである。
UPDATE user_authenticators
SET secret_encrypted = NULL
WHERE authenticator_type IN ('totp', 'webauthn');

ALTER TABLE user_authenticators
    DROP INDEX user_authenticators_credential_id_uk,
    DROP COLUMN credential_id;
