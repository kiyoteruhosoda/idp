-- 認可応答の返し方（`response_mode`）を認可セッションへ保存する（G12）。
--
-- `response_mode=form_post` は「認可コードを URL ではなくフォーム POST の本文で返す」指定である。
-- 要求は `/authorize` の時点で来るが、応答を組み立てるのは**別のリクエスト**（ログイン完了・MFA
-- 通過・同意承認・外部 IdP からの戻り）なので、その間どこかへ保存しなければならない。
-- 保存しないと、応答を作る時点では「クエリで返してよいのか」が分からない。
--
-- # 既定は NULL
--
-- 既定の `query` は保存しない（`NULL` = `query`）。列に既定値を書き込むと、進行中の古い行と
-- 新しい行で意味が変わらないのに値だけが違う状態になる。読み出し側は `NULL` を `query` として
-- 扱う（`domain::response_mode::ResponseMode::from_stored`）。
--
-- # CHECK 制約を置く
--
-- `prompt`（0032）と違い単一値で、許可値は 2 つしかない。値を増やすときは Rust 側の enum と
-- ここの両方を触ることになるが、認可応答の返し方は増やすたびに応答の組み立てそのものを
-- 変える必要があるため、DDL も一緒に見直すのが正しい（黙って増える値ではない）。
ALTER TABLE auth_sessions
    ADD COLUMN response_mode VARCHAR(16) NULL
        COMMENT '認可応答の返し方（form_post のみ保存。NULL = query）'
        AFTER prompt,
    ADD CONSTRAINT auth_sessions_response_mode_chk
        CHECK (response_mode IS NULL OR response_mode IN ('query', 'form_post'));
