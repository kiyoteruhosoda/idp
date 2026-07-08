-- Migration 0012 down: WebAuthn テーブルを削除する。
DROP TABLE IF EXISTS passkey_challenges;
DROP TABLE IF EXISTS user_webauthn_credentials;
