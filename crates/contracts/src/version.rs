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
    /// ビルド番号（CI の通し番号）。**コミットが同じでもビルドし直せば上がる**ので、
    /// 「新しい成果物が配置されたか」を版数だけで判断できる。手元ビルドでは空。
    pub build_number: &'static str,
}

impl VersionInfo {
    /// 画面に出す版数（`v0.1.0+312`）。ビルド番号が無ければ `v0.1.0`。
    ///
    /// SemVer のビルドメタデータ（`+`）に合わせる。順序比較の対象ではなく「同じ版の別ビルド」を
    /// 見分けるための値、という意味がそのまま当てはまる。
    pub fn display_version(&self) -> String {
        if self.build_number.is_empty() {
            format!("v{}", self.package_version)
        } else {
            format!("v{}+{}", self.package_version, self.build_number)
        }
    }

    /// git 版が埋め込まれているか。ビルド引数を渡し忘れると `unknown` になる。
    pub fn has_git_version(&self) -> bool {
        !self.git_version.is_empty() && self.git_version != "unknown"
    }
}

/// DB スキーマ（sqlx マイグレーション）の適用状態。運用者が DB を直接見られなくても、
/// バージョン情報画面から「どこまでマイグレーションが適用されているか」を確認できるようにする。
///
/// - `expected`: 実行中の api バイナリに埋め込まれたマイグレーションの最大 version（＝アプリが期待する版）。
/// - `db_readable`: `_sqlx_migrations` を読み取れたか。`false` のとき DB へ到達できても状態は取得できて
///   おらず（接続断・権限変更・migrate 未実行等）、`applied` は意味を持たない。**「DB が遅れている」と
///   「DB を読み取れない」を取り違えないため**の区別（後者は運用障害）。
/// - `applied`: `db_readable = true` のときのみ有効。DB の `_sqlx_migrations` に成功記録された最大 version
///   （適用がまだ無いなら `None`）。
///
/// api（DB を持つ側）が算出し、web は HTTP 越しに受け取って表示する（web は DB 非依存）。
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SchemaVersionInfo {
    pub expected: Option<i64>,
    pub db_readable: bool,
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
            build_number: env!("IDP_BUILD_NUMBER"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(build_number: &'static str, git_version: &'static str) -> VersionInfo {
        VersionInfo {
            package_version: "0.1.0",
            git_version,
            build_number,
        }
    }

    /// ビルド番号は SemVer のビルドメタデータとして付ける（`v0.1.0+312`）。
    /// コミットが同じでもビルドし直せば上がるので、成果物が入れ替わったことを版数で判断できる。
    #[test]
    fn the_build_number_is_appended_as_semver_build_metadata() {
        assert_eq!(info("312", "abc1234").display_version(), "v0.1.0+312");
    }

    /// 手元ビルドではビルド番号が付かない。`+` だけが残る形にはしない。
    #[test]
    fn a_local_build_shows_the_package_version_alone() {
        assert_eq!(info("", "abc1234").display_version(), "v0.1.0");
    }

    /// ビルド引数を渡し忘れると git 版が `unknown` になる。画面はこれを見て警告を出す。
    #[test]
    fn a_missing_git_version_is_detectable() {
        assert!(info("312", "abc1234").has_git_version());
        assert!(!info("312", "unknown").has_git_version());
        assert!(!info("312", "").has_git_version());
    }
}
