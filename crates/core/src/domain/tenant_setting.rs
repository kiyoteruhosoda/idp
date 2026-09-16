//! テナント設定（ADR-0058）。
//!
//! `system_settings` が IdP 全体の 1 枚であるのに対し、こちらは**テナントごと**の上書きを持つ。
//! 解決順は **テナントの行 > 全体の行 > 環境変数 > 組み込み既定**で、
//! ⚠ **テナントに行が無いことが「全体に従う」である**（既定値の写しをテナントへ配らない）。
//!
//! 置けるキーは [`crate::domain::system_setting::RUNTIME_SETTING_DEFINITIONS`] の
//! `scope` が決める（単位の唯一の出所）。秘匿値の扱いは `system_settings` と同じで、
//! `is_secret` のとき `value` は暗号文であり、参照 API は平文を返さない。
#![allow(dead_code)]

use crate::domain::tenant::TenantId;

/// テナント設定 1 レコード（key-value）。`value` は保存形式そのまま（`is_secret` のときは暗号文）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantSetting {
    pub tenant_id: TenantId,
    pub key: String,
    pub value: String,
    /// `true` のとき `value` は暗号文（AES-256-GCM の base64）。
    pub is_secret: bool,
}
