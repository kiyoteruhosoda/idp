//! テナント設定の解決（ADR-0058）。
//!
//! # 解決順
//!
//! 1. **テナントの行**（`tenant_settings`）——そのテナントにだけ効く
//! 2. **全体の行**（`system_settings`）
//! 3. **環境変数 → 組み込み既定**（起動時に解決しておいたもの。環境変数は実行中に変わらない）
//!
//! ⚠ **テナントに行が無いことが「全体に従う」である。** 既定値の写しをテナントへ配らない。
//! 写すと、全体の値を変えてもそのテナントだけ追随しなくなり、しかも画面上は同じ値に見える。
//!
//! # 参照のたびに引く
//!
//! テナントごとに違う値は、起動時に 1 つ解決して `Config` で配る形では表せない（ADR-0058 §9）。
//! そこで 1 と 2 は**参照のたびに**引き、TTL キャッシュ（テナント解決と同じ寿命）で抑える。
//! ⚠ **2（全体の行）もスナップショットから採らない。** 起動時の `Config` は DB 由来の値と
//! 環境変数由来の値を区別せずに持つので、全体の上書きを消したときに再起動まで古い値が残る。
//!
//! # この口を通すのは「テナントが上書きできるキー」だけ
//!
//! `scope = Global` のキーを渡すと断る。全体のキーは今までどおり `Config` から読む ——ここで
//! 通してしまうと、呼び出し側は「テナントの値で動いている」と誤解したまま全体の値を使う。
//! 逆に、⚠ **テナントが上書きできるキーを `Config` から直接読む箇所を残さない**（そこだけ全体の
//! 値で動き、しかも静かに間違える）。

use crate::domain::cache::Cache;
use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::{SystemSettingsRepository, TenantSettingsRepository};
use crate::domain::system_setting::{runtime_setting_definition, SettingDefinition, SettingScope};
use crate::domain::tenant::TenantId;
use std::collections::HashMap;
use std::sync::Arc;

/// 保存されている上書きの写し（キー → 保存形式の値）。空文字列の行は含めない。
pub type SettingOverrides = HashMap<String, String>;

/// 解決した値がどこから来たか。画面が「このテナントで決めた」と「全体に従っている」を
/// 読み分けるために持つ（ADR-0058 §6）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingOrigin {
    /// このテナントで上書きした値。
    TenantOverride,
    /// 全体の値に従っている（全体の行・環境変数・組み込み既定のいずれか）。
    Inherited,
}

/// テナントについて解決した設定値。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTenantSetting {
    pub value: String,
    pub origin: SettingOrigin,
}

pub struct TenantSettingsService {
    tenant_settings: Arc<dyn TenantSettingsRepository>,
    system_settings: Arc<dyn SystemSettingsRepository>,
    /// DB を除いた全体の値（環境変数 → 組み込み既定）。テナントが上書きできるキーの分だけ持つ。
    /// 組み立ては配線側が `Config::value_without_db` で行う（本サービスは `Config` に依存しない）。
    fallback: HashMap<String, String>,
    tenant_cache: Arc<dyn Cache<TenantId, SettingOverrides>>,
    /// 全体の行のキャッシュ。キー空間は 1 つだけなので `()` を鍵にする。
    global_cache: Arc<dyn Cache<(), SettingOverrides>>,
}

impl TenantSettingsService {
    pub fn new(
        tenant_settings: Arc<dyn TenantSettingsRepository>,
        system_settings: Arc<dyn SystemSettingsRepository>,
        fallback: HashMap<String, String>,
        tenant_cache: Arc<dyn Cache<TenantId, SettingOverrides>>,
        global_cache: Arc<dyn Cache<(), SettingOverrides>>,
    ) -> Self {
        Self {
            tenant_settings,
            system_settings,
            fallback,
            tenant_cache,
            global_cache,
        }
    }

    /// テナントについてキーの値を解決する（テナントの行 > 全体の行 > 環境変数 > 組み込み既定）。
    pub async fn resolve(&self, tenant_id: TenantId, key: &str) -> Result<ResolvedTenantSetting> {
        let def = overridable_definition(key)?;
        if let Some(value) = self.tenant_overrides(tenant_id).await?.get(def.key) {
            return Ok(ResolvedTenantSetting {
                value: value.clone(),
                origin: SettingOrigin::TenantOverride,
            });
        }
        let value = match self.global_overrides().await?.get(def.key) {
            Some(value) => value.clone(),
            None => self.fallback.get(def.key).cloned().unwrap_or_default(),
        };
        Ok(ResolvedTenantSetting {
            value,
            origin: SettingOrigin::Inherited,
        })
    }

    /// テナントについてキーの値を型へ変換して返す。
    ///
    /// ⚠ 変換に失敗したら**全体へ黙って落とさずにエラーを返す。** 保存の時点で型は検証している
    /// （`validate_setting_value`）ので、ここで失敗するのは DB を直接書き換えた場合だけであり、
    /// 黙って落とすと「上書きしたのに効かない」が見えなくなる。
    pub async fn parse<T>(&self, tenant_id: TenantId, key: &str) -> Result<T>
    where
        T: std::str::FromStr,
        T::Err: std::fmt::Display,
    {
        let resolved = self.resolve(tenant_id, key).await?;
        resolved.value.parse::<T>().map_err(|e| {
            DomainError::InvalidValue(format!(
                "stored value for {key} ({:?}) cannot be parsed: {e}",
                resolved.origin
            ))
        })
    }

    /// そのテナントの上書き（保存形式のまま。空の行は含めない）。
    pub async fn tenant_overrides(&self, tenant_id: TenantId) -> Result<SettingOverrides> {
        if let Some(cached) = self.tenant_cache.get(&tenant_id) {
            return Ok(cached);
        }
        let loaded: SettingOverrides = self
            .tenant_settings
            .load_for_tenant(tenant_id)
            .await?
            .into_iter()
            .filter(|setting| !setting.value.is_empty())
            .map(|setting| (setting.key, setting.value))
            .collect();
        self.tenant_cache.insert(tenant_id, loaded.clone());
        Ok(loaded)
    }

    /// テナントの上書きを書き換えたあとに呼ぶ（次の参照で DB を引き直させる）。
    pub fn invalidate(&self, tenant_id: TenantId) {
        self.tenant_cache.invalidate(&tenant_id);
    }

    /// 全体の設定を書き換えたあとに呼ぶ。
    pub fn invalidate_global(&self) {
        self.global_cache.invalidate(&());
    }

    async fn global_overrides(&self) -> Result<SettingOverrides> {
        if let Some(cached) = self.global_cache.get(&()) {
            return Ok(cached);
        }
        let loaded: SettingOverrides = self
            .system_settings
            .load_all()
            .await?
            .into_iter()
            // secret の暗号文をテナントの解決へ混ぜない（テナントが上書きできるキーに secret は無い）。
            .filter(|setting| !setting.is_secret && !setting.value.is_empty())
            .map(|setting| (setting.key, setting.value))
            .collect();
        self.global_cache.insert((), loaded.clone());
        Ok(loaded)
    }
}

/// テナントが上書きできるキーの定義を返す。そうでなければ断る。
fn overridable_definition(key: &str) -> Result<&'static SettingDefinition> {
    let def = runtime_setting_definition(key)
        .ok_or_else(|| DomainError::InvalidValue(format!("unknown setting key: {key}")))?;
    if def.scope != SettingScope::TenantOverridable {
        return Err(DomainError::InvalidValue(format!(
            "setting {key} is decided by the whole IdP, not by a tenant"
        )));
    }
    // secret は復号の口が別に要る（ADR-0058 §8 の SMTP）。平文と暗号文を同じ口から返さない。
    if def.secret {
        return Err(DomainError::InvalidValue(format!(
            "setting {key} is secret and cannot be resolved as plain text"
        )));
    }
    Ok(def)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::clock::Clock;
    use crate::domain::system_setting::SystemSetting;
    use crate::domain::tenant_setting::TenantSetting;
    use crate::infrastructure::cache::InMemoryTtlCache;
    use async_trait::async_trait;
    use chrono::{DateTime, Duration, TimeZone, Utc};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use uuid::Uuid;

    struct FixedClock(DateTime<Utc>);
    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    #[derive(Default)]
    struct FakeTenantSettings {
        rows: Mutex<Vec<TenantSetting>>,
        loads: AtomicUsize,
    }

    impl FakeTenantSettings {
        fn put(&self, tenant_id: TenantId, key: &str, value: &str) {
            let mut rows = self.rows.lock().unwrap();
            rows.retain(|row| !(row.tenant_id == tenant_id && row.key == key));
            rows.push(TenantSetting {
                tenant_id,
                key: key.to_string(),
                value: value.to_string(),
                is_secret: false,
            });
        }
    }

    #[async_trait]
    impl TenantSettingsRepository for FakeTenantSettings {
        async fn load_for_tenant(&self, tenant_id: TenantId) -> Result<Vec<TenantSetting>> {
            self.loads.fetch_add(1, Ordering::SeqCst);
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .filter(|row| row.tenant_id == tenant_id)
                .cloned()
                .collect())
        }
        async fn upsert(&self, setting: &TenantSetting) -> Result<()> {
            self.put(setting.tenant_id, &setting.key, &setting.value);
            Ok(())
        }
        async fn delete(&self, tenant_id: TenantId, key: &str) -> Result<()> {
            self.rows
                .lock()
                .unwrap()
                .retain(|row| !(row.tenant_id == tenant_id && row.key == key));
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeSystemSettings {
        rows: Mutex<Vec<SystemSetting>>,
    }

    #[async_trait]
    impl SystemSettingsRepository for FakeSystemSettings {
        async fn load_all(&self) -> Result<Vec<SystemSetting>> {
            Ok(self.rows.lock().unwrap().clone())
        }
        async fn upsert(&self, setting: &SystemSetting) -> Result<()> {
            let mut rows = self.rows.lock().unwrap();
            rows.retain(|row| row.key != setting.key);
            rows.push(setting.clone());
            Ok(())
        }
    }

    struct Fixture {
        service: TenantSettingsService,
        tenants: Arc<FakeTenantSettings>,
        system: Arc<FakeSystemSettings>,
    }

    fn fixture() -> Fixture {
        let clock: Arc<dyn Clock> = Arc::new(FixedClock(
            Utc.with_ymd_and_hms(2026, 9, 16, 0, 0, 0).unwrap(),
        ));
        let tenants = Arc::new(FakeTenantSettings::default());
        let system = Arc::new(FakeSystemSettings::default());
        // 環境変数 → 組み込み既定の層（配線側が `Config::value_without_db` で作るもの）。
        let fallback = HashMap::from([
            ("PASSWORD_MIN_LENGTH".to_string(), "8".to_string()),
            ("LOGIN_MAX_FAILED_ATTEMPTS".to_string(), "10".to_string()),
        ]);
        let service = TenantSettingsService::new(
            tenants.clone(),
            system.clone(),
            fallback,
            Arc::new(InMemoryTtlCache::new(Duration::seconds(60), clock.clone())),
            Arc::new(InMemoryTtlCache::new(Duration::seconds(60), clock)),
        );
        Fixture {
            service,
            tenants,
            system,
        }
    }

    fn tenant() -> TenantId {
        Uuid::now_v7().into()
    }

    fn global_row(key: &str, value: &str) -> SystemSetting {
        SystemSetting {
            key: key.to_string(),
            value: value.to_string(),
            is_secret: false,
        }
    }

    #[tokio::test]
    async fn a_tenant_without_a_row_follows_the_fallback() {
        let f = fixture();
        let resolved = f
            .service
            .resolve(tenant(), "PASSWORD_MIN_LENGTH")
            .await
            .unwrap();
        assert_eq!(resolved.value, "8");
        assert_eq!(resolved.origin, SettingOrigin::Inherited);
    }

    #[tokio::test]
    async fn the_whole_idp_row_beats_the_fallback() {
        let f = fixture();
        f.system
            .rows
            .lock()
            .unwrap()
            .push(global_row("PASSWORD_MIN_LENGTH", "12"));
        let resolved = f
            .service
            .resolve(tenant(), "PASSWORD_MIN_LENGTH")
            .await
            .unwrap();
        assert_eq!(resolved.value, "12");
        assert_eq!(resolved.origin, SettingOrigin::Inherited);
    }

    #[tokio::test]
    async fn the_tenant_row_beats_the_whole_idp_row() {
        let f = fixture();
        let t = tenant();
        f.system
            .rows
            .lock()
            .unwrap()
            .push(global_row("PASSWORD_MIN_LENGTH", "12"));
        f.tenants.put(t, "PASSWORD_MIN_LENGTH", "16");
        let resolved = f.service.resolve(t, "PASSWORD_MIN_LENGTH").await.unwrap();
        assert_eq!(resolved.value, "16");
        assert_eq!(resolved.origin, SettingOrigin::TenantOverride);
    }

    /// ⚠ 1 テナントだけの試験は、全体の値を読んでいても通ってしまう。2 テナントで違う値を入れ、
    /// 互いの行が見えないことを確かめる。
    #[tokio::test]
    async fn two_tenants_see_only_their_own_rows() {
        let f = fixture();
        let (a, b, c) = (tenant(), tenant(), tenant());
        f.tenants.put(a, "PASSWORD_MIN_LENGTH", "10");
        f.tenants.put(b, "PASSWORD_MIN_LENGTH", "20");

        assert_eq!(
            f.service
                .parse::<usize>(a, "PASSWORD_MIN_LENGTH")
                .await
                .unwrap(),
            10
        );
        assert_eq!(
            f.service
                .parse::<usize>(b, "PASSWORD_MIN_LENGTH")
                .await
                .unwrap(),
            20
        );
        // 行の無いテナントは全体に従う。
        let resolved = f.service.resolve(c, "PASSWORD_MIN_LENGTH").await.unwrap();
        assert_eq!(resolved.value, "8");
        assert_eq!(resolved.origin, SettingOrigin::Inherited);
    }

    /// 上書きの無いキーは、別のキーを上書きしたテナントでも全体に従う（既定値の写しを作らない）。
    #[tokio::test]
    async fn overriding_one_key_does_not_pin_the_others() {
        let f = fixture();
        let t = tenant();
        f.tenants.put(t, "PASSWORD_MIN_LENGTH", "16");
        f.system
            .rows
            .lock()
            .unwrap()
            .push(global_row("LOGIN_MAX_FAILED_ATTEMPTS", "3"));

        let resolved = f
            .service
            .resolve(t, "LOGIN_MAX_FAILED_ATTEMPTS")
            .await
            .unwrap();
        assert_eq!(resolved.value, "3");
        assert_eq!(resolved.origin, SettingOrigin::Inherited);
        assert_eq!(f.tenants.rows.lock().unwrap().len(), 1, "no row is copied");
    }

    /// 空の行は「行が無い」と同じ（`system_settings` と同じ扱い）。
    #[tokio::test]
    async fn an_empty_row_means_no_override() {
        let f = fixture();
        let t = tenant();
        f.tenants.put(t, "PASSWORD_MIN_LENGTH", "");
        let resolved = f.service.resolve(t, "PASSWORD_MIN_LENGTH").await.unwrap();
        assert_eq!(resolved.value, "8");
        assert_eq!(resolved.origin, SettingOrigin::Inherited);
    }

    /// 全体で決めるキーはこの口を通さない。通すと、呼び出し側は「テナントの値で動いている」と
    /// 誤解したまま全体の値を使う。
    #[tokio::test]
    async fn keys_decided_by_the_whole_idp_are_refused() {
        let f = fixture();
        for key in ["ACCESS_TOKEN_TTL_SECS", "ISSUER", "COOKIE_SECURE"] {
            let err = f.service.resolve(tenant(), key).await.unwrap_err();
            assert!(matches!(err, DomainError::InvalidValue(_)), "{key}");
        }
    }

    #[tokio::test]
    async fn unknown_keys_are_refused() {
        let f = fixture();
        let err = f
            .service
            .resolve(tenant(), "PASSWORD_MIN_LENGHT")
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::InvalidValue(_)));
    }

    /// キャッシュは書き換えのあと `invalidate` で捨てるまで古い値を返す ——書き込み側は必ず呼ぶこと。
    #[tokio::test]
    async fn invalidate_makes_the_next_lookup_reload() {
        let f = fixture();
        let t = tenant();
        f.service.resolve(t, "PASSWORD_MIN_LENGTH").await.unwrap();
        f.tenants.put(t, "PASSWORD_MIN_LENGTH", "16");

        let cached = f.service.resolve(t, "PASSWORD_MIN_LENGTH").await.unwrap();
        assert_eq!(cached.value, "8", "served from the cache until invalidated");
        assert_eq!(f.tenants.loads.load(Ordering::SeqCst), 1);

        f.service.invalidate(t);
        let reloaded = f.service.resolve(t, "PASSWORD_MIN_LENGTH").await.unwrap();
        assert_eq!(reloaded.value, "16");
        assert_eq!(f.tenants.loads.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn invalidate_global_makes_the_whole_idp_row_reload() {
        let f = fixture();
        let t = tenant();
        f.service.resolve(t, "PASSWORD_MIN_LENGTH").await.unwrap();
        f.system
            .rows
            .lock()
            .unwrap()
            .push(global_row("PASSWORD_MIN_LENGTH", "12"));

        f.service.invalidate_global();
        let resolved = f.service.resolve(t, "PASSWORD_MIN_LENGTH").await.unwrap();
        assert_eq!(resolved.value, "12");
    }

    /// 型に合わない保存値は、全体へ黙って落とさずにエラーにする。
    #[tokio::test]
    async fn an_unparsable_stored_value_is_an_error_not_a_silent_fallback() {
        let f = fixture();
        let t = tenant();
        f.tenants.put(t, "PASSWORD_MIN_LENGTH", "sixteen");
        let err = f
            .service
            .parse::<usize>(t, "PASSWORD_MIN_LENGTH")
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::InvalidValue(_)));
    }
}
