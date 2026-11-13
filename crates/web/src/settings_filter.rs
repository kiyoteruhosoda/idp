//! Filtering on the settings screen (`GET /{tenant_id}/admin/settings?q=&mine=&runtime=`).
//!
//! Tenant settings (around 16 items) and global runtime settings (about 50 rows) are filtered **server-side via a GET
//! form**, like the existing lists (members, audit log). No script is added (CSP stays narrow; works the same on phones).
//!
//! The decisions are collected here; templates only render the filtered result (`CLAUDE.md` "Screen rendering").

use crate::admin_dto::{RuntimeSettingView, TenantSettingView};

/// Filtering of global runtime settings by kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RuntimeSettingFilter {
    #[default]
    All,
    /// Keys a tenant can override (ADR-0058).
    TenantOverridable,
    /// Needs attention (still on a dangerous default, etc.).
    NeedsAction,
    /// Keys that are saved but take effect only after a restart (MT27).
    PendingRestart,
}

impl RuntimeSettingFilter {
    /// Reads from the query value. Unknown values fall back to "all" (so a broken URL does not empty the list).
    pub fn parse(raw: Option<&str>) -> Self {
        match raw.unwrap_or_default() {
            "tenant" => Self::TenantOverridable,
            "action" => Self::NeedsAction,
            "pending" => Self::PendingRestart,
            _ => Self::All,
        }
    }

    /// Spelling used for the form's `<option value>`.
    pub fn as_query(self) -> &'static str {
        match self {
            Self::All => "",
            Self::TenantOverridable => "tenant",
            Self::NeedsAction => "action",
            Self::PendingRestart => "pending",
        }
    }
}

/// Filter conditions of the settings screen.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SettingsFilter {
    /// Text (the input with surrounding whitespace trimmed; kept to write back into the form).
    pub text: String,
    /// "Only what this tenant decided".
    pub tenant_overrides_only: bool,
    pub runtime: RuntimeSettingFilter,
}

impl SettingsFilter {
    pub fn new(text: Option<&str>, mine: Option<&str>, runtime: Option<&str>) -> Self {
        Self {
            text: text.unwrap_or_default().trim().to_string(),
            tenant_overrides_only: mine.is_some_and(|v| !v.is_empty()),
            runtime: RuntimeSettingFilter::parse(runtime),
        }
    }

    /// Whether anything is filtering (whether to show "clear filters").
    pub fn is_active(&self) -> bool {
        !self.text.is_empty()
            || self.tenant_overrides_only
            || self.runtime != RuntimeSettingFilter::All
    }

    /// Text match (case-insensitive substring). Matches if contained in the key, display name or description.
    fn matches_text(&self, fields: &[&str]) -> bool {
        if self.text.is_empty() {
            return true;
        }
        let needle = self.text.to_lowercase();
        fields
            .iter()
            .any(|field| field.to_lowercase().contains(&needle))
    }

    /// Whether to keep one tenant setting item. `label` is the display name shown on screen (translated).
    pub fn keeps_tenant_value(&self, item: &TenantSettingView, label: &str) -> bool {
        (!self.tenant_overrides_only || item.is_tenant_override())
            && self.matches_text(&[&item.key, label, &item.description])
    }

    /// Whether to keep one global runtime setting row.
    pub fn keeps_runtime_setting(&self, item: &RuntimeSettingView) -> bool {
        let kind = match self.runtime {
            RuntimeSettingFilter::All => true,
            RuntimeSettingFilter::TenantOverridable => item.tenant_overridable,
            RuntimeSettingFilter::NeedsAction => item.status == "NEEDS_ACTION",
            RuntimeSettingFilter::PendingRestart => item.pending_restart,
        };
        kind && self.matches_text(&[&item.key, &item.description])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant_value(key: &str, origin: &str, description: &str) -> TenantSettingView {
        TenantSettingView {
            key: key.to_string(),
            description: description.to_string(),
            origin: origin.to_string(),
            ..Default::default()
        }
    }

    fn runtime(key: &str, tenant: bool, status: &str, pending: bool) -> RuntimeSettingView {
        RuntimeSettingView {
            key: key.to_string(),
            description: format!("{key} の説明"),
            tenant_overridable: tenant,
            status: status.to_string(),
            pending_restart: pending,
            ..Default::default()
        }
    }

    #[test]
    fn no_condition_keeps_everything() {
        let filter = SettingsFilter::new(None, None, None);
        assert!(!filter.is_active());
        assert!(filter.keeps_tenant_value(&tenant_value("A", "INHERITED", ""), "a"));
        assert!(filter.keeps_runtime_setting(&runtime("A", false, "SAFE", false)));
    }

    /// Text matches any of key, display name or description, case-insensitively.
    #[test]
    fn text_matches_key_label_or_description_case_insensitively() {
        let filter = SettingsFilter::new(Some("  password "), None, None);
        assert!(filter.is_active());
        let item = tenant_value("PASSWORD_MIN_LENGTH", "INHERITED", "");
        assert!(filter.keeps_tenant_value(&item, "最小長"));
        let by_label = SettingsFilter::new(Some("最小"), None, None);
        assert!(by_label.keeps_tenant_value(&item, "パスワードの最小長"));
        let by_description = tenant_value("X", "INHERITED", "Password reset link");
        assert!(filter.keeps_tenant_value(&by_description, "x"));
        assert!(!filter.keeps_tenant_value(
            &tenant_value("SSO_IDLE_TTL_SECS", "INHERITED", ""),
            "セッション"
        ));
    }

    #[test]
    fn mine_keeps_only_values_decided_by_this_tenant() {
        let filter = SettingsFilter::new(None, Some("1"), None);
        assert!(filter.keeps_tenant_value(&tenant_value("A", "TENANT_OVERRIDE", ""), "a"));
        assert!(!filter.keeps_tenant_value(&tenant_value("B", "INHERITED", ""), "b"));
        // An empty value counts as not set (same as a form with the box unchecked).
        assert!(!SettingsFilter::new(None, Some(""), None).tenant_overrides_only);
    }

    #[test]
    fn runtime_kind_filters_rows() {
        let tenant = SettingsFilter::new(None, None, Some("tenant"));
        assert!(tenant.keeps_runtime_setting(&runtime("A", true, "SAFE", false)));
        assert!(!tenant.keeps_runtime_setting(&runtime("B", false, "SAFE", false)));

        let action = SettingsFilter::new(None, None, Some("action"));
        assert!(action.keeps_runtime_setting(&runtime("A", false, "NEEDS_ACTION", false)));
        assert!(!action.keeps_runtime_setting(&runtime("B", false, "SAFE", false)));

        let pending = SettingsFilter::new(None, None, Some("pending"));
        assert!(pending.keeps_runtime_setting(&runtime("A", false, "SAFE", true)));
        assert!(!pending.keeps_runtime_setting(&runtime("B", false, "SAFE", false)));
    }

    /// Unknown values fall back to "all" (a broken URL does not empty the list).
    #[test]
    fn unknown_runtime_kind_means_all() {
        let filter = SettingsFilter::new(None, None, Some("bogus"));
        assert_eq!(filter.runtime, RuntimeSettingFilter::All);
        assert!(!filter.is_active());
    }
}
