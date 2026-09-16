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
//!
//! # どのテナントの値で動くか（ADR-0058 §13）
//!
//! 消費側は下の型付きの口（[`TenantSettingsService::password_policy`] など）から引く。渡す
//! テナントは次のとおりで、⚠ **発行と検証で必ず同じテナントを渡す**（片方だけ違うと、発行した
//! 直後に切れているリンクやセッションが出る）。
//!
//! | まとまり | 渡すテナント | 理由 |
//! |---|---|---|
//! | パスワードポリシー・ロックアウト | 利用者の**所属元** | 資格情報とロックの状態は利用者の行にあり、所属元だけが管理する（ADR-0009 §2） |
//! | SSO セッションの寿命・step-up の間隔 | 利用者の**所属元** | SSO セッションはホスト単位で全テナントに共有され、テナント列を持たない |
//! | パスワード再設定・メール検証のリンク | 利用者の**所属元** | リンクは所属元を指し、消費も所属元でしか通らない（MT26） |
//! | 招待のリンク | 招待した**参加先** | 招待は参加先のメンバーシップ行である |

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::admin_actor::AdminActor;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::authentication_policy::LockoutPolicy;
use crate::domain::cache::Cache;
use crate::domain::error::{DomainError, Result};
use crate::domain::password_policy::{PasswordPolicy, MAX_PASSWORD_LEN};
use crate::domain::repositories::{SystemSettingsRepository, TenantSettingsRepository};
use crate::domain::system_setting::{
    runtime_setting_definition, validate_setting_value, SettingDefinition, SettingScope,
    RUNTIME_SETTING_DEFINITIONS,
};
use crate::domain::tenant::TenantId;
use crate::domain::tenant_context::TenantContext;
use crate::domain::tenant_setting::{TenantOverrideEntry, TenantSetting};
use chrono::Duration;
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

/// テナントの設定画面に並べる 1 項目（ADR-0058 §6）。
///
/// ⚠ **値だけを見せない。** 「このテナントで決めた」か「全体に従っている」か（`origin`）と、
/// 全体の値（`whole_idp_value`）を必ず一緒に持つ。上書きしている項目でも全体の値を並べるのは、
/// 「全体に戻すと何になるか」を読めないまま戻させないため。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantSettingView {
    pub definition: &'static SettingDefinition,
    /// このテナントで効いている値。
    pub value: String,
    pub origin: SettingOrigin,
    /// 全体の値（全体の行 → 環境変数 → 組み込み既定）。上書きを消すとこの値に戻る。
    pub whole_idp_value: String,
}

/// あるキーについて、全テナントがどう決めているか（全体の設定画面が読む。ADR-0058 §6）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TenantSettingAdoption {
    /// 全体の値に従っている（行を持たない）テナントの件数。
    pub following: u64,
    /// 既定から外れている（このキーを上書きしている）テナント。
    pub overriding: Vec<TenantOverrideEntry>,
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
    audit: Arc<AuditService>,
}

impl TenantSettingsService {
    pub fn new(
        tenant_settings: Arc<dyn TenantSettingsRepository>,
        system_settings: Arc<dyn SystemSettingsRepository>,
        fallback: HashMap<String, String>,
        tenant_cache: Arc<dyn Cache<TenantId, SettingOverrides>>,
        global_cache: Arc<dyn Cache<(), SettingOverrides>>,
        audit: Arc<AuditService>,
    ) -> Self {
        Self {
            tenant_settings,
            system_settings,
            fallback,
            tenant_cache,
            global_cache,
            audit,
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
        Ok(ResolvedTenantSetting {
            value: self.whole_idp_value(def).await?,
            origin: SettingOrigin::Inherited,
        })
    }

    /// 全体の値（全体の行 → 環境変数 → 組み込み既定）。テナントの行は見ない。
    async fn whole_idp_value(&self, def: &SettingDefinition) -> Result<String> {
        Ok(match self.global_overrides().await?.get(def.key) {
            Some(value) => value.clone(),
            None => self.fallback.get(def.key).cloned().unwrap_or_default(),
        })
    }

    /// テナントが上書きできる全項目を、出どころと全体の値つきで返す（定義の並び順）。
    ///
    /// 項目はキー定義（`scope = TenantOverridable`）から導く ——キーを足すたびに画面や API の型を
    /// 書き足さない。
    pub async fn list(&self, tenant_id: TenantId) -> Result<Vec<TenantSettingView>> {
        let tenant = self.tenant_overrides(tenant_id).await?;
        let mut views = Vec::new();
        for def in overridable_definitions() {
            let whole_idp_value = self.whole_idp_value(def).await?;
            let (value, origin) = match tenant.get(def.key) {
                Some(value) => (value.clone(), SettingOrigin::TenantOverride),
                None => (whole_idp_value.clone(), SettingOrigin::Inherited),
            };
            views.push(TenantSettingView {
                definition: def,
                value,
                origin,
                whole_idp_value,
            });
        }
        Ok(views)
    }

    /// テナントの値を決める（行を書く）。
    ///
    /// - 定義に無いキー・全体で決めるキー・秘匿値のキーは断る（`InvalidValue`）
    /// - 型は全体の保存と同じ `validate_setting_value` を通す
    /// - ⚠ **締め出し得る値**（定義の `locks_out`）は `confirmed` が無ければ保存せず `Conflict` を返す。
    ///   画面は確認を挟んでから `confirmed` を付けて送り直す
    /// - 空の値は受けない。全体に戻すのは [`Self::clear`]（空の行を残すと「決めた」のか「戻した」
    ///   のかが行から読めなくなる）
    pub async fn set(
        &self,
        tenant: TenantContext,
        key: &str,
        value: &str,
        confirmed: bool,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<()> {
        let def = overridable_definition(key)?;
        let value = value.trim();
        if value.is_empty() {
            return Err(DomainError::InvalidValue(format!(
                "setting {key} needs a value; clear the override to follow the whole IdP"
            )));
        }
        validate_setting_value(def, value).map_err(DomainError::InvalidValue)?;
        if def.needs_confirmation(value) && !confirmed {
            return Err(DomainError::Conflict(format!(
                "setting {key} = {value} can lock users out and needs confirmation"
            )));
        }
        let tenant_id = tenant.tenant_id();
        self.tenant_settings
            .upsert(&TenantSetting {
                tenant_id,
                key: def.key.to_string(),
                value: value.to_string(),
                is_secret: false,
            })
            .await?;
        self.invalidate(tenant_id);
        self.record(tenant_id, def.key, "set", actor, ctx).await;
        Ok(())
    }

    /// テナントの上書きを消す（＝全体に従う状態へ戻す）。行が無くても成功する。
    pub async fn clear(
        &self,
        tenant: TenantContext,
        key: &str,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<()> {
        let def = overridable_definition(key)?;
        let tenant_id = tenant.tenant_id();
        self.tenant_settings.delete(tenant_id, def.key).await?;
        self.invalidate(tenant_id);
        self.record(tenant_id, def.key, "cleared", actor, ctx).await;
        Ok(())
    }

    async fn record(
        &self,
        tenant_id: TenantId,
        key: &str,
        change: &str,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) {
        self.audit
            .record(
                AuditEventType::TenantSettingsUpdated,
                AuditResult::Success,
                Some(tenant_id),
                actor.user_id(),
                actor.client_id(),
                // 値そのものは記録しない（キーと設定/解除の別のみ）。
                Some(&format!("{key} {change}")),
                ctx,
            )
            .await;
    }

    /// テナントが上書きできる各キーについて、従っているテナントの件数と、外れているテナントを返す。
    ///
    /// ⚠ テナントをまたいで読む。呼べるのは全体の設定画面（`idp.system.admin`）だけにすること。
    pub async fn adoption_across_tenants(
        &self,
    ) -> Result<HashMap<&'static str, TenantSettingAdoption>> {
        let across = self.tenant_settings.list_overrides_across_tenants().await?;
        let mut adoption: HashMap<&'static str, TenantSettingAdoption> = overridable_definitions()
            .map(|def| (def.key, TenantSettingAdoption::default()))
            .collect();
        for entry in across.overrides {
            // 定義に無い行・全体のキーの行は数えない（効いていない行を「外れている」と見せない）。
            if let Some((_, item)) = adoption.iter_mut().find(|(key, _)| **key == entry.key) {
                item.overriding.push(entry);
            }
        }
        for item in adoption.values_mut() {
            item.following = across
                .tenant_count
                .saturating_sub(item.overriding.len() as u64);
        }
        Ok(adoption)
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

/// SSO セッションの寿命（`SSO_IDLE_TTL_SECS` / `SSO_ABSOLUTE_TTL_SECS`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SsoSessionLifetime {
    pub idle: Duration,
    pub absolute: Duration,
}

/// 型付きの口。消費側はキーの綴りと型変換をここに任せる（呼び出し側で `parse` を書かせない）。
impl TenantSettingsService {
    /// パスワードポリシー（`PASSWORD_*`）。渡すのは利用者の**所属元**テナント。
    pub async fn password_policy(&self, tenant_id: TenantId) -> Result<PasswordPolicy> {
        Ok(PasswordPolicy {
            min_length: self.parse(tenant_id, "PASSWORD_MIN_LENGTH").await?,
            // 上限はハッシュ計算量の防御（argon2 の入力長）であって運用で緩める値ではないため、
            // 設定にせずドメインの既定値を使う。
            max_length: MAX_PASSWORD_LEN,
            history_count: self.parse(tenant_id, "PASSWORD_HISTORY_COUNT").await?,
            max_age_days: self.parse(tenant_id, "PASSWORD_MAX_AGE_DAYS").await?,
            reject_breached: self
                .parse(tenant_id, "PASSWORD_BREACH_CHECK_ENABLED")
                .await?,
        })
    }

    /// ロックアウト（`LOGIN_*`）。渡すのは利用者の**所属元**テナント。
    pub async fn login_lockout(&self, tenant_id: TenantId) -> Result<LockoutPolicy> {
        let max_failed_attempts: u32 = self.parse(tenant_id, "LOGIN_MAX_FAILED_ATTEMPTS").await?;
        Ok(LockoutPolicy {
            // i32 に収まらない巨大値は「実質ロックしない」として i32::MAX へ飽和させる
            // （`as` キャストだと負数へラップし、初回失敗で即ロックという逆の挙動になる）。
            max_failed_attempts: i32::try_from(max_failed_attempts).unwrap_or(i32::MAX),
            lock_duration_secs: self.parse(tenant_id, "LOGIN_LOCK_DURATION_SECS").await?,
            max_lock_duration_secs: self
                .parse(tenant_id, "LOGIN_MAX_LOCK_DURATION_SECS")
                .await?,
        })
    }

    /// SSO セッションの寿命。渡すのは利用者の**所属元**テナント（確立と idle 延長の両方で）。
    pub async fn sso_session_lifetime(&self, tenant_id: TenantId) -> Result<SsoSessionLifetime> {
        Ok(SsoSessionLifetime {
            idle: self.seconds(tenant_id, "SSO_IDLE_TTL_SECS").await?,
            absolute: self.seconds(tenant_id, "SSO_ABSOLUTE_TTL_SECS").await?,
        })
    }

    /// step-up（重要操作の直前の本人確認）の有効秒数。渡すのは利用者の**所属元**テナント。
    pub async fn step_up_max_age_secs(&self, tenant_id: TenantId) -> Result<u64> {
        self.parse(tenant_id, "STEP_UP_MAX_AGE_SECS").await
    }

    /// 招待リンクの有効期間。渡すのは招待した**参加先**テナント。
    pub async fn invitation_ttl(&self, tenant_id: TenantId) -> Result<Duration> {
        self.seconds(tenant_id, "INVITATION_TTL_SECS").await
    }

    /// パスワード再設定リンクの有効期間。渡すのは利用者の**所属元**テナント。
    pub async fn password_reset_ttl(&self, tenant_id: TenantId) -> Result<Duration> {
        self.seconds(tenant_id, "PASSWORD_RESET_TTL_SECS").await
    }

    /// SMTP で送れないとき、再設定リンクをサーバのコンソールへ出してよいか。
    pub async fn password_reset_console_link_enabled(&self, tenant_id: TenantId) -> Result<bool> {
        self.parse(tenant_id, "PASSWORD_RESET_CONSOLE_LINK_ENABLED")
            .await
    }

    /// メール検証リンクの有効期間。渡すのは利用者の**所属元**テナント。
    pub async fn email_verification_ttl(&self, tenant_id: TenantId) -> Result<Duration> {
        self.seconds(tenant_id, "EMAIL_VERIFICATION_TTL_SECS").await
    }

    async fn seconds(&self, tenant_id: TenantId, key: &str) -> Result<Duration> {
        let secs: u64 = self.parse(tenant_id, key).await?;
        i64::try_from(secs)
            .ok()
            .and_then(Duration::try_seconds)
            .ok_or_else(|| DomainError::InvalidValue(format!("{key} is out of range: {secs}")))
    }
}

/// テナントが上書きできる（秘匿値でない）キーの定義。並びは定義の順。
fn overridable_definitions() -> impl Iterator<Item = &'static SettingDefinition> {
    RUNTIME_SETTING_DEFINITIONS
        .iter()
        .filter(|def| def.scope == SettingScope::TenantOverridable && !def.secret)
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

/// 消費側の単体試験が使う土台（ADR-0058）。
///
/// ⚠ **試験では行を repository へ直接入れる。** 書き込みの口（`set` / `clear`）を通すと、
/// 消費側の試験が監査や入力検査の都合に引きずられる。
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use crate::domain::audit::AuditEvent;
    use crate::domain::clock::Clock;
    use crate::domain::repositories::AuditLogSink;
    use crate::domain::system_setting::{tenant_overridable_setting_keys, SystemSetting};
    use crate::domain::tenant_setting::TenantOverridesAcrossTenants;
    use async_trait::async_trait;
    use chrono::{DateTime, Utc};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    #[derive(Default)]
    pub struct FakeTenantSettings {
        pub rows: Mutex<Vec<TenantSetting>>,
        pub loads: AtomicUsize,
        /// 行を 1 つも持たないテナントの数（横断集計の試験用）。
        pub extra_tenants: Mutex<u64>,
    }

    impl FakeTenantSettings {
        /// 秘匿値の行を入れる（SMTP のパスワードのような行が集計へ混ざらないことの試験用）。
        pub fn put_secret(&self, tenant_id: TenantId, key: &str, value: &str) {
            self.rows.lock().unwrap().push(TenantSetting {
                tenant_id,
                key: key.to_string(),
                value: value.to_string(),
                is_secret: true,
            });
        }
    }

    impl FakeTenantSettings {
        pub fn put(&self, tenant_id: TenantId, key: &str, value: &str) {
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
        async fn list_overrides_across_tenants(&self) -> Result<TenantOverridesAcrossTenants> {
            let rows = self.rows.lock().unwrap();
            let mut tenants: Vec<TenantId> = rows.iter().map(|row| row.tenant_id).collect();
            tenants.sort_by_key(|id| id.to_string());
            tenants.dedup();
            Ok(TenantOverridesAcrossTenants {
                // 行を持たないテナントも数に入る（`extra_tenants` 件ぶん）。
                tenant_count: tenants.len() as u64 + *self.extra_tenants.lock().unwrap(),
                overrides: rows
                    .iter()
                    .filter(|row| !row.is_secret && !row.value.is_empty())
                    .map(|row| TenantOverrideEntry {
                        tenant_id: row.tenant_id,
                        tenant_name: format!("tenant-{}", row.tenant_id),
                        key: row.key.clone(),
                        value: row.value.clone(),
                    })
                    .collect(),
            })
        }
    }

    /// 監査イベントを溜めるだけの sink。
    #[derive(Default)]
    pub struct CapturingSink {
        pub events: Mutex<Vec<AuditEvent>>,
    }

    #[async_trait]
    impl AuditLogSink for CapturingSink {
        async fn record(&self, event: &AuditEvent) -> Result<()> {
            self.events.lock().unwrap().push(event.clone());
            Ok(())
        }
    }

    struct EpochClock;
    impl Clock for EpochClock {
        fn now(&self) -> DateTime<Utc> {
            DateTime::<Utc>::UNIX_EPOCH
        }
    }

    /// 試験用の監査サービス（記録は捨てずに `CapturingSink` へ溜める）。
    pub fn audit(sink: Arc<CapturingSink>) -> Arc<AuditService> {
        Arc::new(AuditService::new(sink, Arc::new(EpochClock)))
    }

    #[derive(Default)]
    pub struct FakeSystemSettings {
        pub rows: Mutex<Vec<SystemSetting>>,
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

    /// 何も覚えないキャッシュ。試験の途中で行を足しても次の参照で必ず見える。
    pub struct NoCache;

    impl<K, V> Cache<K, V> for NoCache {
        fn get(&self, _key: &K) -> Option<V> {
            None
        }
        fn insert(&self, _key: K, _value: V) {}
        fn invalidate(&self, _key: &K) {}
    }

    /// 行の無い状態（＝全テナントが組み込み既定に従う）の解決器と、行を入れるための repository。
    pub struct TenantSettingsFixture {
        pub service: Arc<TenantSettingsService>,
        pub tenants: Arc<FakeTenantSettings>,
        pub system: Arc<FakeSystemSettings>,
    }

    impl TenantSettingsFixture {
        /// そのテナントの行を入れる（テナントの上書き）。
        pub fn set_tenant(&self, tenant_id: TenantId, key: &str, value: &str) {
            self.tenants.put(tenant_id, key, value);
        }

        /// 全体の行を入れる（`system_settings`）。
        pub fn set_global(&self, key: &str, value: &str) {
            let mut rows = self.system.rows.lock().unwrap();
            rows.retain(|row| row.key != key);
            rows.push(SystemSetting {
                key: key.to_string(),
                value: value.to_string(),
                is_secret: false,
            });
        }
    }

    /// 組み込み既定（定義の `default_value`）を最後の層にした解決器。
    pub fn tenant_settings() -> TenantSettingsFixture {
        let fallback = tenant_overridable_setting_keys()
            .filter_map(|key| {
                runtime_setting_definition(key)
                    .and_then(|def| def.default_value)
                    .map(|value| (key.to_string(), value.to_string()))
            })
            .collect();
        let tenants = Arc::new(FakeTenantSettings::default());
        let system = Arc::new(FakeSystemSettings::default());
        let service = Arc::new(TenantSettingsService::new(
            tenants.clone(),
            system.clone(),
            fallback,
            Arc::new(NoCache),
            Arc::new(NoCache),
            audit(Arc::new(CapturingSink::default())),
        ));
        TenantSettingsFixture {
            service,
            tenants,
            system,
        }
    }

    /// 組み込み既定から一部のキーだけ全体の値を変えた解決器（従来 `Config` で値を注入していた試験用）。
    pub fn tenant_settings_with_global(values: &[(&str, &str)]) -> Arc<TenantSettingsService> {
        let fixture = tenant_settings();
        for (key, value) in values {
            fixture.set_global(key, value);
        }
        fixture.service
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{CapturingSink, FakeSystemSettings, FakeTenantSettings};
    use super::*;
    use crate::domain::clock::Clock;
    use crate::domain::system_setting::SystemSetting;
    use crate::infrastructure::cache::InMemoryTtlCache;
    use chrono::{DateTime, Duration, TimeZone, Utc};
    use std::sync::atomic::Ordering;
    use uuid::Uuid;

    struct FixedClock(DateTime<Utc>);
    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    struct Fixture {
        service: TenantSettingsService,
        tenants: Arc<FakeTenantSettings>,
        system: Arc<FakeSystemSettings>,
        audit: Arc<CapturingSink>,
    }

    fn fixture() -> Fixture {
        let clock: Arc<dyn Clock> = Arc::new(FixedClock(
            Utc.with_ymd_and_hms(2026, 9, 16, 0, 0, 0).unwrap(),
        ));
        let tenants = Arc::new(FakeTenantSettings::default());
        let system = Arc::new(FakeSystemSettings::default());
        let audit = Arc::new(CapturingSink::default());
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
            super::testing::audit(audit.clone()),
        );
        Fixture {
            service,
            tenants,
            system,
            audit,
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

    /// 型付きの口も 2 テナントで確かめる。行のあるテナントはその値、行の無いテナントは全体に従う。
    #[tokio::test]
    async fn typed_readers_resolve_each_tenant_separately() {
        let fixture = super::testing::tenant_settings();
        let (a, b) = (tenant(), tenant());
        fixture.set_global("SSO_ABSOLUTE_TTL_SECS", "7200");
        fixture.set_global("LOGIN_MAX_FAILED_ATTEMPTS", "7");
        fixture.set_tenant(a, "SSO_ABSOLUTE_TTL_SECS", "600");
        fixture.set_tenant(a, "LOGIN_MAX_FAILED_ATTEMPTS", "3");
        fixture.set_tenant(a, "PASSWORD_BREACH_CHECK_ENABLED", "true");
        let service = &fixture.service;

        assert_eq!(
            service.sso_session_lifetime(a).await.unwrap().absolute,
            Duration::seconds(600)
        );
        assert_eq!(
            service.sso_session_lifetime(b).await.unwrap().absolute,
            Duration::seconds(7200)
        );
        assert_eq!(
            service.login_lockout(a).await.unwrap().max_failed_attempts,
            3
        );
        assert_eq!(
            service.login_lockout(b).await.unwrap().max_failed_attempts,
            7
        );
        assert!(service.password_policy(a).await.unwrap().reject_breached);
        assert!(!service.password_policy(b).await.unwrap().reject_breached);
    }

    /// 組み込み既定だけで全部の口が引ける（定義の `default_value` の綴りと型が口と合っている）。
    #[tokio::test]
    async fn every_typed_reader_works_on_the_builtin_defaults() {
        let fixture = super::testing::tenant_settings();
        let service = &fixture.service;
        let t = tenant();
        service.password_policy(t).await.unwrap();
        service.login_lockout(t).await.unwrap();
        service.sso_session_lifetime(t).await.unwrap();
        service.step_up_max_age_secs(t).await.unwrap();
        service.invitation_ttl(t).await.unwrap();
        service.password_reset_ttl(t).await.unwrap();
        service
            .password_reset_console_link_enabled(t)
            .await
            .unwrap();
        service.email_verification_ttl(t).await.unwrap();
    }

    /// i32 に収まらない失敗回数は負数へラップさせず i32::MAX へ飽和させる（初回失敗で即ロックしない）。
    #[tokio::test]
    async fn a_huge_failure_threshold_saturates_instead_of_wrapping() {
        let fixture = super::testing::tenant_settings();
        let t = tenant();
        fixture.set_tenant(t, "LOGIN_MAX_FAILED_ATTEMPTS", &u32::MAX.to_string());
        assert_eq!(
            fixture
                .service
                .login_lockout(t)
                .await
                .unwrap()
                .max_failed_attempts,
            i32::MAX
        );
    }

    fn actor() -> AdminActor {
        AdminActor::User(Uuid::now_v7())
    }

    fn ctx() -> RequestContext {
        RequestContext {
            correlation_id: "test".to_string(),
            ip_address: None,
            user_agent: None,
        }
    }

    #[tokio::test]
    async fn set_writes_a_row_and_the_next_lookup_sees_it_without_waiting_for_the_cache() {
        let f = fixture();
        let t = tenant();
        // 先に引いてキャッシュへ載せておく（書いたあとに invalidate しないと古い値が返る）。
        f.service.resolve(t, "PASSWORD_MIN_LENGTH").await.unwrap();

        f.service
            .set(
                TenantContext::new(t),
                "PASSWORD_MIN_LENGTH",
                " 16 ",
                false,
                &actor(),
                &ctx(),
            )
            .await
            .unwrap();

        let resolved = f.service.resolve(t, "PASSWORD_MIN_LENGTH").await.unwrap();
        assert_eq!(resolved.value, "16", "trimmed and visible at once");
        assert_eq!(resolved.origin, SettingOrigin::TenantOverride);
    }

    /// 「全体に戻す」は行を消す。値を全体と同じにするのとは違い、以後は全体の変更に追随する。
    #[tokio::test]
    async fn clear_removes_the_row_so_the_tenant_follows_the_whole_idp_again() {
        let f = fixture();
        let t = tenant();
        f.service
            .set(
                TenantContext::new(t),
                "PASSWORD_MIN_LENGTH",
                "8",
                false,
                &actor(),
                &ctx(),
            )
            .await
            .unwrap();
        f.service
            .clear(
                TenantContext::new(t),
                "PASSWORD_MIN_LENGTH",
                &actor(),
                &ctx(),
            )
            .await
            .unwrap();
        assert!(f.tenants.rows.lock().unwrap().is_empty(), "the row is gone");

        f.system
            .rows
            .lock()
            .unwrap()
            .push(global_row("PASSWORD_MIN_LENGTH", "12"));
        f.service.invalidate_global();
        let resolved = f.service.resolve(t, "PASSWORD_MIN_LENGTH").await.unwrap();
        assert_eq!(resolved.value, "12", "follows the new whole-IdP value");
        assert_eq!(resolved.origin, SettingOrigin::Inherited);
    }

    /// ⚠ テナントの権限でシステム区画のキーを開かない（使う側の防御）。定義に無いキーも書かない。
    #[tokio::test]
    async fn keys_decided_by_the_whole_idp_cannot_be_written_or_cleared_by_a_tenant() {
        let f = fixture();
        let t = tenant();
        for key in [
            "ACCESS_TOKEN_TTL_SECS",
            "ISSUER",
            "COOKIE_SECURE",
            "AUTH_SESSION_TTL_SECS",
            "DATABASE_URL",
            "KEY_ENCRYPTION_KEY",
            "PASSWORD_MIN_LENGHT",
        ] {
            let err = f
                .service
                .set(TenantContext::new(t), key, "1", true, &actor(), &ctx())
                .await
                .unwrap_err();
            assert!(matches!(err, DomainError::InvalidValue(_)), "set {key}");
            let err = f
                .service
                .clear(TenantContext::new(t), key, &actor(), &ctx())
                .await
                .unwrap_err();
            assert!(matches!(err, DomainError::InvalidValue(_)), "clear {key}");
        }
        assert!(f.tenants.rows.lock().unwrap().is_empty());
        assert!(f.audit.events.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn values_are_checked_against_the_kind_and_empty_values_are_refused() {
        let f = fixture();
        let t = tenant();
        for (key, value) in [
            ("PASSWORD_MIN_LENGTH", "sixteen"),
            ("PASSWORD_MIN_LENGTH", "-1"),
            ("PASSWORD_BREACH_CHECK_ENABLED", "yes"),
            ("PASSWORD_MIN_LENGTH", "  "),
        ] {
            let err = f
                .service
                .set(TenantContext::new(t), key, value, false, &actor(), &ctx())
                .await
                .unwrap_err();
            assert!(matches!(err, DomainError::InvalidValue(_)), "{key}={value}");
        }
        assert!(f.tenants.rows.lock().unwrap().is_empty());
    }

    /// 監査ログにはキーと設定/解除の別だけを残し、値そのものは残さない。
    #[tokio::test]
    async fn the_audit_log_records_the_key_and_the_change_but_not_the_value() {
        let f = fixture();
        let t = tenant();
        f.service
            .set(
                TenantContext::new(t),
                "PASSWORD_MIN_LENGTH",
                "123",
                false,
                &actor(),
                &ctx(),
            )
            .await
            .unwrap();
        f.service
            .clear(
                TenantContext::new(t),
                "PASSWORD_MIN_LENGTH",
                &actor(),
                &ctx(),
            )
            .await
            .unwrap();

        let events = f.audit.events.lock().unwrap();
        let reasons: Vec<&str> = events.iter().filter_map(|e| e.reason.as_deref()).collect();
        assert_eq!(
            reasons,
            ["PASSWORD_MIN_LENGTH set", "PASSWORD_MIN_LENGTH cleared"]
        );
        assert!(events.iter().all(|e| {
            e.event_type == AuditEventType::TenantSettingsUpdated && e.tenant_id == Some(t)
        }));
        assert!(!reasons.iter().any(|r| r.contains("123")));
    }

    #[tokio::test]
    async fn list_shows_every_overridable_key_with_its_origin_and_the_whole_idp_value() {
        let f = fixture();
        let t = tenant();
        f.system
            .rows
            .lock()
            .unwrap()
            .push(global_row("PASSWORD_MIN_LENGTH", "12"));
        f.tenants.put(t, "PASSWORD_MIN_LENGTH", "16");

        let views = f.service.list(t).await.unwrap();
        let keys: Vec<&str> = views.iter().map(|v| v.definition.key).collect();
        let expected: Vec<&str> =
            crate::domain::system_setting::tenant_overridable_setting_keys().collect();
        assert_eq!(keys, expected, "derived from the definitions");

        let min_length = views
            .iter()
            .find(|v| v.definition.key == "PASSWORD_MIN_LENGTH")
            .unwrap();
        assert_eq!(min_length.value, "16");
        assert_eq!(min_length.origin, SettingOrigin::TenantOverride);
        assert_eq!(
            min_length.whole_idp_value, "12",
            "shown next to the override"
        );

        let attempts = views
            .iter()
            .find(|v| v.definition.key == "LOGIN_MAX_FAILED_ATTEMPTS")
            .unwrap();
        assert_eq!(attempts.value, "10");
        assert_eq!(attempts.origin, SettingOrigin::Inherited);
        assert_eq!(attempts.whole_idp_value, "10");
    }

    #[tokio::test]
    async fn adoption_counts_the_tenants_that_follow_and_lists_the_ones_that_do_not() {
        let f = fixture();
        let (a, b) = (tenant(), tenant());
        f.tenants.put(a, "PASSWORD_MIN_LENGTH", "16");
        f.tenants.put(b, "LOGIN_MAX_FAILED_ATTEMPTS", "3");
        // 定義に無いキーの行（綴り違い）は「外れている」に数えない。
        f.tenants.put(b, "PASSWORD_MIN_LENGHT", "4");
        *f.tenants.extra_tenants.lock().unwrap() = 1;

        let adoption = f.service.adoption_across_tenants().await.unwrap();
        let min_length = &adoption["PASSWORD_MIN_LENGTH"];
        assert_eq!(min_length.following, 2);
        assert_eq!(min_length.overriding.len(), 1);
        assert_eq!(min_length.overriding[0].tenant_id, a);
        assert_eq!(min_length.overriding[0].value, "16");

        assert_eq!(adoption["LOGIN_MAX_FAILED_ATTEMPTS"].following, 2);
        assert_eq!(adoption["SSO_IDLE_TTL_SECS"].following, 3);
        assert!(!adoption.contains_key("PASSWORD_MIN_LENGHT"));
        assert!(!adoption.contains_key("ACCESS_TOKEN_TTL_SECS"));
    }

    /// SMTP の行（#113 が同じ表に置く）は、秘匿でも非秘匿でも、テナントが上書きできるキーの
    /// 集計に混ざらない（キーの絞り込みは呼び出し側で定義から行う）。
    #[tokio::test]
    async fn smtp_rows_in_the_same_table_are_not_counted_as_overrides() {
        let f = fixture();
        let t = tenant();
        f.tenants.put(t, "smtp.host", "mail.example.com");
        f.tenants.put_secret(t, "smtp.password", "ciphertext");

        let adoption = f.service.adoption_across_tenants().await.unwrap();
        assert!(!adoption.contains_key("smtp.host"));
        assert!(!adoption.contains_key("smtp.password"));
        assert!(adoption.values().all(|item| item.overriding.is_empty()));
        assert!(adoption.values().all(|item| item.following == 1));
    }

    /// 締め出し得る値（定義の `locks_out`）は、確認が無ければ保存しない。確認があれば保存する。
    #[tokio::test]
    async fn a_value_that_can_lock_people_out_needs_confirmation() {
        let f = fixture();
        let t = tenant();
        for (key, value) in [
            ("AUTH_POLICY_DEFAULT_EFFECT", "deny"),
            ("APPLICATION_ASSIGNMENT_ENFORCEMENT", "enforce"),
        ] {
            let err = f
                .service
                .set(TenantContext::new(t), key, value, false, &actor(), &ctx())
                .await
                .unwrap_err();
            assert!(matches!(err, DomainError::Conflict(_)), "{key}");
            assert!(f.tenants.rows.lock().unwrap().is_empty(), "{key} not saved");

            f.service
                .set(TenantContext::new(t), key, value, true, &actor(), &ctx())
                .await
                .unwrap();
            f.tenants.rows.lock().unwrap().clear();
        }
        // 締め出さない側の値は確認なしで保存できる。
        f.service
            .set(
                TenantContext::new(t),
                "AUTH_POLICY_DEFAULT_EFFECT",
                "allow",
                false,
                &actor(),
                &ctx(),
            )
            .await
            .unwrap();
        // 選択肢に無い値は確認があっても断る。
        let err = f
            .service
            .set(
                TenantContext::new(t),
                "AUTH_POLICY_DEFAULT_EFFECT",
                "denyy",
                true,
                &actor(),
                &ctx(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::InvalidValue(_)));
    }
}
