-- 列ごと落とす。進行中の認可フローは `query` として応答を返すことになる（要求が
-- `form_post` でも RP は 302 で受け取る）。フロー自体は成立する。
ALTER TABLE auth_sessions
    DROP CONSTRAINT auth_sessions_response_mode_chk,
    DROP COLUMN response_mode;
