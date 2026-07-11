-- システム設定（root/idp.system.admin が管理する IdP 全体設定。ADR-0009 §5「システム設定区画」、MT14）。
-- 設定値の優先順位「環境変数 > DB（system_settings）> 既定値」のうち DB 層を担う。
-- SMTP 等の運用設定を保持し、MT17（招待メール配送）・MT18（パスワードリセット）が参照する。
--
-- 方針（0001 baseline と同じ）:
--   * テナント列は持たない。システム設定は IdP 全体に一律適用する（root のみ管理可能。§4）。
--   * 秘匿値（SMTP パスワード等）は is_secret=1 とし、値は AES-256-GCM 暗号文（base64）を保存する
--     （暗号化・復号は Application 層。signing_keys / user_totp_secrets と同方式）。参照 API は
--     秘匿値の平文を返さない（設定済みか否かのみ返す）。
--   * 許可されるキー（smtp.host 等）は Rust 側の定数で集中管理する（DB では制約しない）。
CREATE TABLE system_settings (
    setting_key   VARCHAR(128) NOT NULL COMMENT '設定キー（例: smtp.host）。許可値は Rust 側で集中管理',
    setting_value TEXT         NOT NULL COMMENT '設定値。is_secret=1 のものは AES-256-GCM 暗号文（base64）',
    is_secret     TINYINT(1)   NOT NULL DEFAULT 0 COMMENT '1 のとき値は暗号化保存。参照 API へ平文を返さない',
    updated_at    DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (setting_key)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
