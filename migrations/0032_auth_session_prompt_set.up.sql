-- `prompt` を**値の集合**として保存できるようにする（G12。OIDC Core §3.1.2.1）。
--
-- `prompt` は空白区切りの複数値であり、`prompt=select_account consent` のように「アカウントを
-- 選ばせたうえで同意も取り直す」と要求できる。これまで列は単一値（`none` / `login` / `consent`）の
-- CHECK 付き VARCHAR(16) で、複数値も `select_account` も保存できなかった。保存できない値は
-- アプリ側で「未知の値」として捨てられるため、**要求が無言で無視される**（有効な SSO があれば
-- 黙って現在のアカウントで続いてしまう）。
--
-- # CHECK 制約を外す理由
--
-- 集合を CHECK で表現しようとすると「空白区切りの各要素が許可値であること」を SQL で書くことに
-- なり、値が増えるたびに壊れやすい式が伸びる。許可値の単一の出所は Rust 側の `Prompt` で、
-- 書き込む値は必ず `PromptSet` が正規化した既知の値の並びである（未知の値はここへ到達しない）。
-- DB 側の CHECK は同じ保証を二重化するだけで、しかも表現力が足りない。
--
-- 既存行は単一値（`none` / `login` / `consent`）で、そのまま 1 要素の集合として読める。
-- 移行は不要。
ALTER TABLE auth_sessions DROP CONSTRAINT auth_sessions_prompt_chk;

ALTER TABLE auth_sessions
    MODIFY COLUMN prompt VARCHAR(64) NULL
        COMMENT '認可リクエストの prompt（空白区切りの集合。未指定・未知値のみは NULL）';
