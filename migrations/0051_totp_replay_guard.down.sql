-- リプレイ記録列を取り除く。戻すと TOTP コードは有効な時間窓の間ふたたび再利用可能になる。
ALTER TABLE user_authenticators DROP COLUMN totp_last_used_step;
