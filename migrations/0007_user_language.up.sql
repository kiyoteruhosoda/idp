-- MT20: ユーザーの表示言語設定列を追加する（i18n 仕様書 §4 の優先度2）。
-- `ja` / `en` の 2 択。NULL = 未設定（決定チェーンで次順位へフォールバック）。
ALTER TABLE users
    ADD COLUMN language VARCHAR(5) NULL AFTER name,
    ADD CONSTRAINT users_language_chk
        CHECK (language IN ('ja', 'en'));
