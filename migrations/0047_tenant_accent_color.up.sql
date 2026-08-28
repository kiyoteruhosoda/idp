-- テナントごとのアクセント色。「いまどのテナントにいるか」を文字を読まずに見分けるために使う。
--
-- NULL = 未設定（画面は既定色にフォールバックする）。値は `#rrggbb`（小文字 16 進）で持つ。
-- 厳密な書式検証は Rust 側の値オブジェクト（`domain::tenant::AccentColor`）が単一の出所として
-- 行い、DB は「長さ 7 で `#` 始まり」だけを見る二重防御に留める —— CHECK に正規表現を書くと
-- 許可の定義が 2 か所に分かれ、片方だけ緩む。
ALTER TABLE tenants
    ADD COLUMN accent_color VARCHAR(7) NULL AFTER name,
    ADD CONSTRAINT tenants_accent_color_chk
        CHECK (accent_color IS NULL
               OR (CHAR_LENGTH(accent_color) = 7 AND accent_color LIKE '#%'));
