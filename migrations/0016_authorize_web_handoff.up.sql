-- api↔web の状態受け渡しから Cookie を外す（ADR-0018 決定 2・3）。
--
-- `/authorize` は `auth_session_id` を Set-Cookie せず、web へのリダイレクト URL に
-- **単回・短命のハンドル**を載せる。ハンドルは auth_session 行に固定的に束ねて保存し
-- （＝その `code_challenge` に束縛され、他の認可要求へ付け替えられない）、web が
-- `/internal/authorize/resume` で 1 回だけ交換できる（交換時に NULL へ消費）。
--
-- SSO 判定も `/authorize`（Cookie 読み）から resume（web がボディで渡す）へ移るため、
-- `prompt` / `max_age` の評価を resume 時点まで持ち越す必要があり、両パラメータを
-- auth_session に保存する。
--
-- expand フェーズのみ: 追加列はすべて NULL 許容で、旧バイナリの INSERT/SELECT を壊さない。
ALTER TABLE auth_sessions
    ADD COLUMN prompt VARCHAR(16) NULL
        COMMENT '認可リクエストの prompt（none / login / consent。未指定・未知値は NULL）'
        AFTER code_challenge_method,
    ADD COLUMN max_age BIGINT NULL
        COMMENT '認可リクエストの max_age（秒。未指定は NULL）'
        AFTER prompt,
    ADD COLUMN handle_hash CHAR(64) NULL
        COMMENT 'web ハンドオフ用ハンドルの SHA-256（単回使用。交換時に NULL へ消費）'
        AFTER max_age,
    ADD COLUMN handle_expires_at DATETIME(6) NULL
        COMMENT 'ハンドルの有効期限（UTC。auth_session 本体の expires_at より短命）'
        AFTER handle_hash,
    ADD CONSTRAINT auth_sessions_prompt_chk
        CHECK (prompt IS NULL OR prompt IN ('none', 'login', 'consent')),
    ADD UNIQUE KEY auth_sessions_handle_uq (handle_hash);
