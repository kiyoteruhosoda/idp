//! ビルド成果物のバージョン情報。
//!
//! Domain 側は「どのような情報を公開するか」だけを表現し、取得元は `VersionInfoProvider` の
//! ポリモーフィズムで差し替え可能にする。

use serde::{Deserialize, Serialize};

/// 実行中のバイナリが公開するバージョン情報。
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct VersionInfo {
    pub package_version: &'static str,
    pub git_version: &'static str,
}

/// DB スキーマ（sqlx マイグレーション）の適用状態。運用者が DB を直接見られなくても、
/// バージョン情報画面から「どこまでマイグレーションが適用されているか」を確認できるようにする。
///
/// - `expected`: 実行中の api バイナリに埋め込まれたマイグレーションの最大 version（＝アプリが期待する版）。
/// - `applied`: DB の `_sqlx_migrations` に成功記録された最大 version（未適用・取得不可なら `None`）。
///
/// api（DB を持つ側）が算出し、web は HTTP 越しに受け取って表示する（web は DB 非依存）。
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SchemaVersionInfo {
    pub expected: Option<i64>,
    pub applied: Option<i64>,
}

/// バージョン情報の取得元を抽象化するポート。
pub trait VersionInfoProvider: Send + Sync {
    fn version_info(&self) -> VersionInfo;
}

/// Cargo とビルドスクリプトが埋め込んだ静的メタデータを返す provider。
#[derive(Debug, Clone, Copy)]
pub struct BuildTimeVersionInfoProvider {
    package_version: &'static str,
}

impl BuildTimeVersionInfoProvider {
    pub const fn new(package_version: &'static str) -> Self {
        Self { package_version }
    }
}

impl VersionInfoProvider for BuildTimeVersionInfoProvider {
    fn version_info(&self) -> VersionInfo {
        VersionInfo {
            package_version: self.package_version,
            git_version: env!("IDP_GIT_VERSION"),
        }
    }
}
