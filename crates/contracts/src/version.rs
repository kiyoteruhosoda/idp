//! ビルド成果物のバージョン情報。
//!
//! Domain 側は「どのような情報を公開するか」だけを表現し、取得元は `VersionInfoProvider` の
//! ポリモーフィズムで差し替え可能にする。

use serde::Serialize;

/// 実行中のバイナリが公開するバージョン情報。
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct VersionInfo {
    pub package_version: &'static str,
    pub git_version: &'static str,
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
