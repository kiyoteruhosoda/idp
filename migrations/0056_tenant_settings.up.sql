-- テナントごとの設定を置く受け皿（ADR-0058）。
--
-- これまで設定は `system_settings` の 1 枚しか無く、主キーが `setting_key` だけで**テナント列を
-- 持たない**（0003 の冒頭に「システム設定は IdP 全体に一律適用する」と書いてある）。結果、
-- パスワードの最小長もロックアウトの回数もセッションの寿命も**全テナントで同じ値**になり、
-- 「各テナントは独立した管理境界」という ADR-0009 の建て付けと食い違っていた。
--
-- ⚠ **この時点では誰も読まない。** 表と解決の道だけを入れ、挙動は 1 つも変えない
--   （消費側の作り替えは別のリリースで入る。ADR-0058 §12）。
--
-- 解決順は **テナントの行 > 全体の行（`system_settings`）> 環境変数 > 組み込み既定**。
-- ⚠ **テナントに行が無いことが「全体に従う」である。** 既定値の写しをテナントへ配らない
--   ——写すと、全体の値を変えてもそのテナントだけ追随しなくなり、しかも画面上は同じ値に見える。
--
-- ⚠ **どのキーを置けるかは Rust 側が決める**（`RUNTIME_SETTING_DEFINITIONS` の `scope`）。
--   DB では制約しない ——`system_settings` と同じ方針で、許可値の一覧を DB とコードの 2 か所に
--   持たせない。
CREATE TABLE tenant_settings (
    tenant_id     CHAR(36)     NOT NULL
        COMMENT 'この設定を持つテナント',
    setting_key   VARCHAR(128) NOT NULL
        COMMENT '設定キー（例: PASSWORD_MIN_LENGTH）。許可値は Rust 側で集中管理する',
    setting_value TEXT         NOT NULL
        COMMENT '設定値。is_secret=1 のものは AES-256-GCM 暗号文（base64）',
    is_secret     TINYINT(1)   NOT NULL DEFAULT 0
        COMMENT '1 のとき値は暗号化保存。参照 API へ平文を返さない（system_settings と同じ扱い）',
    updated_at    DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    -- 1 テナント 1 キー 1 行。`(tenant_id, setting_key)` がそのままテナントの設定一覧の索引にもなる。
    PRIMARY KEY (tenant_id, setting_key),
    -- テナントが消えたら設定も消す。`tenant_domains` と同じ CASCADE で、消えたテナントの設定だけが
    -- 残る形を作らない（`clients` / `users` の RESTRICT とは意味が違う ——設定はテナントの持ち物で
    -- あって、テナントを消す前に人が空にすべきものではない）。
    CONSTRAINT tenant_settings_tenant_fk FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
