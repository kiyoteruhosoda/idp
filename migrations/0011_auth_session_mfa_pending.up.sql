-- Migration 0011: auth_sessions に password_verified_at を追加する。
-- ログイン時にパスワード検証が成功したが MFA がまだ完了していない状態を表す。
-- NULL = パスワード未検証 or MFA なし（従来の状態）。
-- 非 NULL = パスワード検証済み、TOTP 入力待ち。
ALTER TABLE auth_sessions
    ADD COLUMN password_verified_at DATETIME(6) NULL AFTER auth_time;
