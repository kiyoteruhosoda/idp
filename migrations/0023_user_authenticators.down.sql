-- 登録簿を落とす。TOTP・WebAuthn の秘密は元のテーブルに残っているため認証は続けられるが、
-- リカバリーコードと email OTP は本テーブルにしか無いため失われる。
DROP TABLE IF EXISTS user_authenticators;
