-- AP4 の追加列を取り除く（記録は失われるが、SSO セッション自体は有効なまま残る）。
ALTER TABLE sso_sessions
    DROP CONSTRAINT sso_sessions_auth_strength_chk,
    DROP COLUMN mfa_completed_at,
    DROP COLUMN authentication_strength,
    DROP COLUMN authentication_methods;
