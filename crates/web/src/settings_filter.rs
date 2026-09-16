//! 設定画面の絞り込み（`GET /{tenant_id}/admin/settings?q=&mine=&runtime=`）。
//!
//! テナントの設定（16 項目前後）と全体のランタイム設定（約 50 行）を、既存の一覧（メンバー・監査ログ）と
//! 同じく **GET のフォームでサーバ側で**絞る。スクリプトを足さない（CSP を広げず、スマホでも同じに動く）。
//!
//! 判定をここに集め、テンプレートは絞った結果を描くだけにする（`CLAUDE.md`「画面描画」）。

use crate::admin_dto::{RuntimeSettingView, TenantSettingView};

/// 全体のランタイム設定の種類での絞り込み。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RuntimeSettingFilter {
    #[default]
    All,
    /// テナントが上書きできるキー（ADR-0058）。
    TenantOverridable,
    /// 要対応（危険な既定値のまま等）。
    NeedsAction,
    /// 保存済みだが再起動するまで効かないキー（MT27）。
    PendingRestart,
}

impl RuntimeSettingFilter {
    /// クエリの値から読む。知らない値は「すべて」に倒す（壊れた URL で一覧が空にならないように）。
    pub fn parse(raw: Option<&str>) -> Self {
        match raw.unwrap_or_default() {
            "tenant" => Self::TenantOverridable,
            "action" => Self::NeedsAction,
            "pending" => Self::PendingRestart,
            _ => Self::All,
        }
    }

    /// フォームの `<option value>` に使う綴り。
    pub fn as_query(self) -> &'static str {
        match self {
            Self::All => "",
            Self::TenantOverridable => "tenant",
            Self::NeedsAction => "action",
            Self::PendingRestart => "pending",
        }
    }
}

/// 設定画面の絞り込み条件。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SettingsFilter {
    /// 文字（前後の空白を落とした入力そのもの。フォームへ書き戻すために保持する）。
    pub text: String,
    /// 「このテナントで決めたものだけ」。
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

    /// 何かで絞っているか（「絞り込みを解除」を出すかどうか）。
    pub fn is_active(&self) -> bool {
        !self.text.is_empty()
            || self.tenant_overrides_only
            || self.runtime != RuntimeSettingFilter::All
    }

    /// 文字の一致（大小を区別しない部分一致）。キー・表示名・説明のどれかに含まれていればよい。
    fn matches_text(&self, fields: &[&str]) -> bool {
        if self.text.is_empty() {
            return true;
        }
        let needle = self.text.to_lowercase();
        fields
            .iter()
            .any(|field| field.to_lowercase().contains(&needle))
    }

    /// テナントの設定 1 項目を残すか。`label` は画面に出す表示名（訳）。
    pub fn keeps_tenant_value(&self, item: &TenantSettingView, label: &str) -> bool {
        (!self.tenant_overrides_only || item.is_tenant_override())
            && self.matches_text(&[&item.key, label, &item.description])
    }

    /// 全体のランタイム設定 1 行を残すか。
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

    /// 文字はキー・表示名・説明のどれでも当たり、大小を区別しない。
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
        // 空の値は付いていない扱い（チェックを外したフォームと同じ）。
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

    /// 知らない値は「すべて」に倒す（壊れた URL で一覧が空にならない）。
    #[test]
    fn unknown_runtime_kind_means_all() {
        let filter = SettingsFilter::new(None, None, Some("bogus"));
        assert_eq!(filter.runtime, RuntimeSettingFilter::All);
        assert!(!filter.is_active());
    }
}
