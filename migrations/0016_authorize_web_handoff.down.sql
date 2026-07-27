-- 0016 の巻き戻し（ADR-0018 決定 2 の web ハンドオフ列を除去）。
--
-- auth_sessions は `/authorize` 〜 `/login` の短命な一時状態のため、進行中フローが
-- 巻き戻しで失われても再度 `/authorize` からやり直すだけでよい（永続データへの影響なし）。
ALTER TABLE auth_sessions
    DROP CONSTRAINT auth_sessions_prompt_chk,
    DROP KEY auth_sessions_handle_uq,
    DROP COLUMN handle_expires_at,
    DROP COLUMN handle_hash,
    DROP COLUMN max_age,
    DROP COLUMN prompt;
