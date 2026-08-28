-- 利用者ごとの配色設定（ライト / ダーク / OS に合わせる）を追加する。
--
-- `language` と同じ「表示の好み」であり、同じ扱いにする: NULL = 未設定で、決定チェーンの
-- 次順位（Cookie → OS の設定）へ落ちる。既定を 'system' で埋めないのは、「まだ選んでいない」と
-- 「OS に合わせると選んだ」を区別できなくなるためである（前者は端末の Cookie を尊重してよいが、
-- 後者は端末をまたいで OS 追従を貫く）。
--
-- 許可値は DB ネイティブ ENUM ではなく VARCHAR + CHECK で持つ（CLAUDE.md「DB モデリング」）。
ALTER TABLE users
    ADD COLUMN theme VARCHAR(16) NULL AFTER language,
    ADD CONSTRAINT users_theme_chk
        CHECK (theme IN ('light', 'dark', 'system'));
