-- 単一値の列へ戻す。集合として保存されていた行（`select_account` を含む行・複数値の行）は
-- CHECK を通らないため、戻す前に NULL（＝未指定）へ落とす。進行中の認可フローがその要求を
-- 失うだけで、フロー自体は既定の動作で続く。
UPDATE auth_sessions
SET prompt = NULL
WHERE prompt IS NOT NULL AND prompt NOT IN ('none', 'login', 'consent');

ALTER TABLE auth_sessions
    MODIFY COLUMN prompt VARCHAR(16) NULL
        COMMENT '認可リクエストの prompt（none / login / consent。未指定・未知値は NULL）';

ALTER TABLE auth_sessions
    ADD CONSTRAINT auth_sessions_prompt_chk
        CHECK (prompt IS NULL OR prompt IN ('none', 'login', 'consent'));
