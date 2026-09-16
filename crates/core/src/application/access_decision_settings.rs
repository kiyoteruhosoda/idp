//! [`AccessDecisionSettings`] をテナント設定の解決（ADR-0058）に乗せる実装。
//!
//! 行の無いテナントは全体の値（全体の行 → 環境変数 → 組み込み既定）に従う。既定は `allow` と
//! `record_only` で、⚠ 名簿の無いテナントが勝手に断る側へ倒れることは無い。

use crate::application::tenant_settings::TenantSettingsService;
use crate::domain::access_decision_settings::{
    AccessDecisionSettings, APPLICATION_ASSIGNMENT_ENFORCEMENT, AUTH_POLICY_DEFAULT_EFFECT,
};
use crate::domain::authentication_policy::DefaultPolicyEffect;
use crate::domain::error::{DomainError, Result};
use crate::domain::tenant::TenantId;
use crate::domain::values::AssignmentEnforcement;
use async_trait::async_trait;

#[async_trait]
impl AccessDecisionSettings for TenantSettingsService {
    async fn policy_default_effect(&self, tenant_id: TenantId) -> Result<DefaultPolicyEffect> {
        let resolved = self.resolve(tenant_id, AUTH_POLICY_DEFAULT_EFFECT).await?;
        DefaultPolicyEffect::parse(&resolved.value)
            .map_err(|e| unparsable(AUTH_POLICY_DEFAULT_EFFECT, e))
    }

    async fn assignment_enforcement(&self, tenant_id: TenantId) -> Result<AssignmentEnforcement> {
        let resolved = self
            .resolve(tenant_id, APPLICATION_ASSIGNMENT_ENFORCEMENT)
            .await?;
        AssignmentEnforcement::parse(&resolved.value)
            .map_err(|e| unparsable(APPLICATION_ASSIGNMENT_ENFORCEMENT, e))
    }
}

/// 保存値が型に合わない。⚠ 全体へ黙って落とさない（`TenantSettingsService::parse` と同じ扱い）。
fn unparsable(key: &str, error: DomainError) -> DomainError {
    DomainError::InvalidValue(format!("stored value for {key} cannot be parsed: {error}"))
}

#[cfg(test)]
pub mod test_support {
    //! 判定の既定を差し込むためのテスト用の実装。

    use super::*;
    use crate::application::tenant_settings::SettingOverrides;
    use crate::domain::clock::Clock;
    use crate::domain::repositories::{SystemSettingsRepository, TenantSettingsRepository};
    use crate::domain::system_setting::SystemSetting;
    use crate::domain::tenant_setting::TenantSetting;
    use crate::infrastructure::cache::InMemoryTtlCache;
    use chrono::{DateTime, Duration, Utc};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// どのテナントにも同じ値を返す。判定の既定に関心の無いテスト向け。
    pub struct FixedAccessDecisionSettings {
        pub policy_default_effect: DefaultPolicyEffect,
        pub assignment_enforcement: AssignmentEnforcement,
    }

    #[async_trait]
    impl AccessDecisionSettings for FixedAccessDecisionSettings {
        async fn policy_default_effect(&self, _tenant_id: TenantId) -> Result<DefaultPolicyEffect> {
            Ok(self.policy_default_effect)
        }
        async fn assignment_enforcement(
            &self,
            _tenant_id: TenantId,
        ) -> Result<AssignmentEnforcement> {
            Ok(self.assignment_enforcement)
        }
    }

    /// 既定動作だけを決めた実装（割り当ては `enforce`）。
    pub fn policy_default(effect: DefaultPolicyEffect) -> Arc<FixedAccessDecisionSettings> {
        Arc::new(FixedAccessDecisionSettings {
            policy_default_effect: effect,
            assignment_enforcement: AssignmentEnforcement::Enforce,
        })
    }

    struct EpochClock;
    impl Clock for EpochClock {
        fn now(&self) -> DateTime<Utc> {
            DateTime::<Utc>::UNIX_EPOCH
        }
    }

    #[derive(Default)]
    struct MemoryTenantSettings(Mutex<Vec<TenantSetting>>);

    #[async_trait]
    impl TenantSettingsRepository for MemoryTenantSettings {
        async fn load_for_tenant(&self, tenant_id: TenantId) -> Result<Vec<TenantSetting>> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .iter()
                .filter(|row| row.tenant_id == tenant_id)
                .cloned()
                .collect())
        }
        async fn upsert(&self, setting: &TenantSetting) -> Result<()> {
            let mut rows = self.0.lock().unwrap();
            rows.retain(|row| !(row.tenant_id == setting.tenant_id && row.key == setting.key));
            rows.push(setting.clone());
            Ok(())
        }
        async fn delete(&self, tenant_id: TenantId, key: &str) -> Result<()> {
            self.0
                .lock()
                .unwrap()
                .retain(|row| !(row.tenant_id == tenant_id && row.key == key));
            Ok(())
        }
        async fn list_overrides_across_tenants(
            &self,
        ) -> Result<crate::domain::tenant_setting::TenantOverridesAcrossTenants> {
            // 判定の試験はテナントをまたいで読まない。
            Ok(Default::default())
        }
    }

    struct NoSystemSettings;

    #[async_trait]
    impl SystemSettingsRepository for NoSystemSettings {
        async fn load_all(&self) -> Result<Vec<SystemSetting>> {
            Ok(Vec::new())
        }
        async fn upsert(&self, _setting: &SystemSetting) -> Result<()> {
            Ok(())
        }
    }

    /// 本物の解決（テナントの行 > 組み込み既定）を、指定したテナントの行だけで組み立てる。
    ///
    /// ⚠ テナントごとに違う値を試すときはこちらを使う。固定値の実装では「全体の値を読んでいても
    /// 通ってしまう」試験になる。
    pub fn tenant_settings(rows: &[(TenantId, &str, &str)]) -> Arc<TenantSettingsService> {
        let tenants = MemoryTenantSettings::default();
        tenants
            .0
            .lock()
            .unwrap()
            .extend(rows.iter().map(|(tenant_id, key, value)| TenantSetting {
                tenant_id: *tenant_id,
                key: key.to_string(),
                value: value.to_string(),
                is_secret: false,
            }));
        let fallback = HashMap::from([
            (AUTH_POLICY_DEFAULT_EFFECT.to_string(), "allow".to_string()),
            (
                APPLICATION_ASSIGNMENT_ENFORCEMENT.to_string(),
                "record_only".to_string(),
            ),
        ]);
        let clock: Arc<dyn Clock> = Arc::new(EpochClock);
        Arc::new(TenantSettingsService::new(
            Arc::new(tenants),
            Arc::new(NoSystemSettings),
            fallback,
            Arc::new(InMemoryTtlCache::<TenantId, SettingOverrides>::new(
                Duration::seconds(60),
                clock.clone(),
            )),
            Arc::new(InMemoryTtlCache::<(), SettingOverrides>::new(
                Duration::seconds(60),
                clock,
            )),
            crate::application::tenant_settings::testing::audit(Default::default()),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::tenant_settings;
    use super::*;
    use uuid::Uuid;

    fn tenant() -> TenantId {
        Uuid::now_v7().into()
    }

    /// 2 テナントで違う値を入れ、互いの値が混ざらないこと。行の無いテナントは既定に従う。
    #[tokio::test]
    async fn each_tenant_gets_its_own_decision_defaults() {
        let (strict, lenient, untouched) = (tenant(), tenant(), tenant());
        let settings = tenant_settings(&[
            (strict, AUTH_POLICY_DEFAULT_EFFECT, "deny"),
            (strict, APPLICATION_ASSIGNMENT_ENFORCEMENT, "enforce"),
            (lenient, AUTH_POLICY_DEFAULT_EFFECT, "allow"),
            (lenient, APPLICATION_ASSIGNMENT_ENFORCEMENT, "record_only"),
        ]);

        assert_eq!(
            settings.policy_default_effect(strict).await.unwrap(),
            DefaultPolicyEffect::Deny
        );
        assert_eq!(
            settings.assignment_enforcement(strict).await.unwrap(),
            AssignmentEnforcement::Enforce
        );
        assert_eq!(
            settings.policy_default_effect(lenient).await.unwrap(),
            DefaultPolicyEffect::Allow
        );
        assert_eq!(
            settings.assignment_enforcement(lenient).await.unwrap(),
            AssignmentEnforcement::RecordOnly
        );
        // 行が無ければ既定（allow / record_only）。⚠ 既定が enforce だと名簿の無い全員が締め出される。
        assert_eq!(
            settings.policy_default_effect(untouched).await.unwrap(),
            DefaultPolicyEffect::Allow
        );
        assert_eq!(
            settings.assignment_enforcement(untouched).await.unwrap(),
            AssignmentEnforcement::RecordOnly
        );
    }

    /// 型に合わない保存値は、既定へ黙って落とさずにエラーにする。
    #[tokio::test]
    async fn an_unparsable_value_is_an_error() {
        let t = tenant();
        let settings = tenant_settings(&[
            (t, AUTH_POLICY_DEFAULT_EFFECT, "maybe"),
            (t, APPLICATION_ASSIGNMENT_ENFORCEMENT, "sometimes"),
        ]);
        assert!(matches!(
            settings.policy_default_effect(t).await,
            Err(DomainError::InvalidValue(_))
        ));
        assert!(matches!(
            settings.assignment_enforcement(t).await,
            Err(DomainError::InvalidValue(_))
        ));
    }
}
