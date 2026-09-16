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

/// 全テナントを横断した上書き 1 件（全体の設定画面が「既定から外れているテナント」を出すために読む）。
///
/// ⚠ 秘匿値は含めない（リポジトリの時点で落とす）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantOverrideEntry {
    pub tenant_id: TenantId,
    pub tenant_name: String,
    pub key: String,
    pub value: String,
}

/// 全テナントを横断した上書きの状況。「従っているテナントの件数」は
/// `tenant_count` から、そのキーを上書きしているテナントの数を引いて出す。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TenantOverridesAcrossTenants {
    /// テナントの総数（root を含む）。
    pub tenant_count: u64,
    /// 空でない、秘匿値でない上書きの全件。
    pub overrides: Vec<TenantOverrideEntry>,
}
