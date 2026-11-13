//! Version information of the build artifact.
//!
//! The domain side expresses only "what information is exposed"; the source can be swapped via
//! `VersionInfoProvider` polymorphism.

use serde::{Deserialize, Serialize};

/// Version information exposed by the running binary.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct VersionInfo {
    pub package_version: &'static str,
    pub git_version: &'static str,
    /// Build number (CI run counter). **It increases on every rebuild even for the same commit**, so
    /// "was a new artifact deployed?" can be told from the version alone. Empty for local builds.
    pub build_number: &'static str,
}

impl VersionInfo {
    /// Version shown on screen (`v0.1.0+312`). `v0.1.0` when there is no build number.
    ///
    /// Follows SemVer build metadata (`+`). Its meaning, a value that tells apart "different builds of the
    /// same version" and is not part of ordering, applies as is.
    pub fn display_version(&self) -> String {
        if self.build_number.is_empty() {
            format!("v{}", self.package_version)
        } else {
            format!("v{}+{}", self.package_version, self.build_number)
        }
    }

    /// Whether the git version is embedded. It becomes `unknown` if the build argument is forgotten.
    pub fn has_git_version(&self) -> bool {
        !self.git_version.is_empty() && self.git_version != "unknown"
    }
}

/// Applied state of the DB schema (sqlx migrations). Lets operators check "how far migrations are applied"
/// from the version information screen even without direct DB access.
///
/// - `expected`: the max migration version embedded in the running api binary (= the version the app expects).
/// - `db_readable`: whether `_sqlx_migrations` could be read. When `false`, the state could not be read even if
///   the DB is reachable (disconnect, permission change, migrate not run etc.) and `applied` is meaningless. The
///   distinction exists **so "the DB is behind" is not confused with "the DB cannot be read"** (the latter is an outage).
/// - `applied`: valid only when `db_readable = true`. The max version recorded as successful in the DB's `_sqlx_migrations`
///   (`None` if nothing is applied yet).
///
/// api (the side with the DB) computes it; web receives it over HTTP and displays it (web is DB-independent).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SchemaVersionInfo {
    pub expected: Option<i64>,
    pub db_readable: bool,
    pub applied: Option<i64>,
}

/// Port abstracting the source of version information.
pub trait VersionInfoProvider: Send + Sync {
    fn version_info(&self) -> VersionInfo;
}

/// Provider returning static metadata embedded by Cargo and the build script.
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

    /// The build number is attached as SemVer build metadata (`v0.1.0+312`).
    /// It increases on every rebuild even for the same commit, so a swapped artifact shows in the version.
    #[test]
    fn the_build_number_is_appended_as_semver_build_metadata() {
        assert_eq!(info("312", "abc1234").display_version(), "v0.1.0+312");
    }

    /// Local builds get no build number. Never leave a bare `+`.
    #[test]
    fn a_local_build_shows_the_package_version_alone() {
        assert_eq!(info("", "abc1234").display_version(), "v0.1.0");
    }

    /// If the build argument is forgotten the git version becomes `unknown`. The screen warns on it.
    #[test]
    fn a_missing_git_version_is_detectable() {
        assert!(info("312", "abc1234").has_git_version());
        assert!(!info("312", "unknown").has_git_version());
        assert!(!info("312", "").has_git_version());
    }
}
