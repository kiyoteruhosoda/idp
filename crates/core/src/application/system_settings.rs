//! システム設定ユースケース（root/idp.system.admin による SMTP 等の管理。ADR-0009 §5、MT14）。
//!
//! `system_settings` テーブル（DB 層）を読み書きする。秘匿値（SMTP パスワード）は
//! `crypto::encrypt`（AES-256-GCM）で暗号化して保存し、参照時は**平文を返さない**
//! （設定済みか否かのみ返す）。認可（root のみ）は Presentation の `RequirePerms<IdpSystemAdmin>`
//! が担い、本サービスは呼び出された時点で認可済みとして扱う。
//!
//! 設定値の消費側（MT17 招待メール・MT18 パスワードリセット）は本サービスの `get_smtp` を通す。

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::admin_actor::AdminActor;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::error::{DomainError, Result};
use crate::domain::mailer::SmtpServerConfig;
use crate::domain::repositories::{SystemSettingsRepository, TenantSettingsRepository};
use crate::domain::sms::SmsGatewayConfig;
use crate::domain::system_setting::{
    ensure_override_is_bootable, runtime_setting_definition, validate_setting_value,
    DeploymentState, SettingOwner, SmsSettingsView, SmtpSettingsView, SystemSetting,
    UpdateSmsCommand, UpdateSmtpCommand, SMS_AUTH_HEADER, SMS_AUTH_TOKEN, SMS_GATEWAY_URL,
    SMS_SENDER_ID, SMTP_FROM_ADDRESS, SMTP_HOST, SMTP_PASSWORD, SMTP_PORT, SMTP_USERNAME,
    SMTP_USE_TLS,
};
use crate::domain::tenant::TenantId;
use crate::domain::tenant_context::TenantContext;
use crate::domain::tenant_setting::TenantSetting;
use std::collections::HashMap;
use std::sync::Arc;

/// メールの経路を構成するキー（ADR-0058 §8）。テナントの経路はこの**塊**で解決する。
const SMTP_KEYS: &[&str] = &[
    SMTP_HOST,
    SMTP_PORT,
    SMTP_USERNAME,
    SMTP_PASSWORD,
    SMTP_FROM_ADDRESS,
    SMTP_USE_TLS,
];

/// テナントが自分の経路を持っているかを決めるキー。`port` と `use_tls` だけの行は数えない
/// （保存フォームは既定値を必ず送るので、数えると空のフォームを保存しただけで経路を持った扱いになり、
/// 全体の経路へ落ちなくなる ——メールが黙って止まる）。
const SMTP_ROUTE_DEFINING_KEYS: &[&str] =
    &[SMTP_HOST, SMTP_USERNAME, SMTP_PASSWORD, SMTP_FROM_ADDRESS];

/// テナントの SMTP 設定の表示用（ADR-0058 §8）。
#[derive(Debug, Clone, Default)]
pub struct TenantSmtpView {
    /// このテナントの経路（持っていなければ全項目が空）。パスワードは設定の有無だけ。
    pub settings: SmtpSettingsView,
    /// `true` = このテナントは経路を持たず、全体の経路でメールを送る。
    pub inherited: bool,
}

pub struct SystemSettingsService {
    repo: Arc<dyn SystemSettingsRepository>,
    /// テナントのメールの経路（ADR-0058 §8）。全体の表とは別の表に置く。
    tenant_settings: Arc<dyn TenantSettingsRepository>,
    key_encryption_key: [u8; 32],
    /// 実行中プロセスの配置状態（ADR-0017）。DB 上書きを保存する前に「その値で次回起動できるか」を
    /// 判定するために持つ。
    deployment_state: DeploymentState,
    audit: Arc<AuditService>,
    #[allow(dead_code)]
    clock: Arc<dyn Clock>,
}

impl SystemSettingsService {
    pub fn new(
        repo: Arc<dyn SystemSettingsRepository>,
        tenant_settings: Arc<dyn TenantSettingsRepository>,
        key_encryption_key: [u8; 32],
        deployment_state: DeploymentState,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            repo,
            tenant_settings,
            key_encryption_key,
            deployment_state,
            audit,
            clock,
        }
    }

    async fn load_map(&self) -> Result<HashMap<String, String>> {
        let all = self.repo.load_all().await?;
        Ok(all.into_iter().map(|s| (s.key, s.value)).collect())
    }

    /// テナントのメールの経路の行（保存形式のまま。空の行は含めない）。
    async fn tenant_smtp_map(&self, tenant_id: TenantId) -> Result<HashMap<String, String>> {
        Ok(self
            .tenant_settings
            .load_for_tenant(tenant_id)
            .await?
            .into_iter()
            .filter(|s| SMTP_KEYS.contains(&s.key.as_str()) && !s.value.is_empty())
            .map(|s| (s.key, s.value))
            .collect())
    }

    /// そのテナントのメールを送るための SMTP 接続情報（復号済みパスワード込み）を返す（ADR-0058 §8）。
    /// **画面表示には使わない**。`None` はメールを送れないことを表す（呼び出し側は手動伝達へ落ちる）。
    ///
    /// ⚠ **経路は塊で決める。** テナントが自分の経路を 1 項目でも持っていれば、**そのテナントの塊だけ**を
    /// 使い、欠けた項目を全体の値で埋めない。項目ごとに全体へ落とすと、テナントが `host` だけを
    /// 自分のサーバに向けて `password` を未設定にするだけで、**全体の SMTP 資格情報が
    /// そのテナントのサーバへ送られる**。
    ///
    /// 返り値の秘匿値をログ・監査に出さないこと。
    pub async fn smtp_server_for(&self, tenant_id: TenantId) -> Result<Option<SmtpServerConfig>> {
        let tenant = self.tenant_smtp_map(tenant_id).await?;
        if defines_own_route(&tenant) {
            return self.smtp_server_from(&tenant);
        }
        self.smtp_server_from(&self.load_map().await?)
    }

    /// テナントの SMTP 設定を返す（パスワードは設定の有無だけ）。
    pub async fn get_tenant_smtp(&self, tenant_id: TenantId) -> Result<TenantSmtpView> {
        let tenant = self.tenant_smtp_map(tenant_id).await?;
        let inherited = !defines_own_route(&tenant);
        Ok(TenantSmtpView {
            settings: if inherited {
                SmtpSettingsView::default()
            } else {
                smtp_view_from(&tenant)
            },
            inherited,
        })
    }

    /// テナントの SMTP 設定を保存する。`password` は `None` = 現行維持 / `Some("")` = 消去 /
    /// `Some(x)` = 設定（全体と同じ規則）。
    ///
    /// 保存した結果、経路を決める項目が 1 つも残らなければ**行ごと消して全体に従う状態へ戻す**
    /// （空のフォームを保存しただけでメールが止まる形を作らない）。
    pub async fn update_tenant_smtp(
        &self,
        tenant: TenantContext,
        cmd: UpdateSmtpCommand,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<TenantSmtpView> {
        let tenant_id = tenant.tenant_id();
        let keeps_password = match &cmd.password {
            None => self
                .tenant_smtp_map(tenant_id)
                .await?
                .contains_key(SMTP_PASSWORD),
            Some(password) => !password.is_empty(),
        };
        let defines_route = keeps_password
            || [&cmd.host, &cmd.username, &cmd.from_address]
                .iter()
                .any(|v| !v.trim().is_empty());
        if !defines_route {
            return self.clear_tenant_smtp(tenant, actor, ctx).await;
        }

        let plain = [
            (SMTP_HOST, cmd.host.trim().to_string()),
            (
                SMTP_PORT,
                cmd.port.map(|p| p.to_string()).unwrap_or_default(),
            ),
            (SMTP_USERNAME, cmd.username.trim().to_string()),
            (SMTP_FROM_ADDRESS, cmd.from_address.trim().to_string()),
            (
                SMTP_USE_TLS,
                if cmd.use_tls { "true" } else { "false" }.to_string(),
            ),
        ];
        for (key, value) in plain {
            self.upsert_tenant(tenant_id, key, value, false).await?;
        }
        if let Some(password) = cmd.password {
            if password.is_empty() {
                self.tenant_settings
                    .delete(tenant_id, SMTP_PASSWORD)
                    .await?;
            } else {
                let stored = crypto::encrypt(password.as_bytes(), &self.key_encryption_key)
                    .map_err(|e| DomainError::Repository(format!("smtp password encrypt: {e}")))?;
                self.upsert_tenant(tenant_id, SMTP_PASSWORD, stored, true)
                    .await?;
            }
        }
        self.record_tenant_smtp(tenant_id, "set", actor, ctx).await;
        self.get_tenant_smtp(tenant_id).await
    }

    /// テナントの SMTP 設定を消し、全体の経路に従う状態へ戻す。
    pub async fn clear_tenant_smtp(
        &self,
        tenant: TenantContext,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<TenantSmtpView> {
        let tenant_id = tenant.tenant_id();
        for key in SMTP_KEYS {
            self.tenant_settings.delete(tenant_id, key).await?;
        }
        self.record_tenant_smtp(tenant_id, "cleared", actor, ctx)
            .await;
        self.get_tenant_smtp(tenant_id).await
    }

    async fn upsert_tenant(
        &self,
        tenant_id: TenantId,
        key: &str,
        value: String,
        is_secret: bool,
    ) -> Result<()> {
        self.tenant_settings
            .upsert(&TenantSetting {
                tenant_id,
                key: key.to_string(),
                value,
                is_secret,
            })
            .await
    }

    async fn record_tenant_smtp(
        &self,
        tenant_id: TenantId,
        change: &str,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) {
        self.audit
            .record(
                AuditEventType::TenantUpdated,
                AuditResult::Success,
                Some(tenant_id),
                actor.user_id(),
                actor.client_id(),
                // 値そのものは記録しない（経路の設定/解除の別だけ）。
                Some(&format!("smtp {change}")),
                ctx,
            )
            .await;
    }

    /// 保存形式の塊から SMTP 接続情報を組み立てる。`host` か `from_address` が空なら `None`。
    fn smtp_server_from(&self, map: &HashMap<String, String>) -> Result<Option<SmtpServerConfig>> {
        let host = map.get(SMTP_HOST).cloned().unwrap_or_default();
        let from_address = map.get(SMTP_FROM_ADDRESS).cloned().unwrap_or_default();
        if host.is_empty() || from_address.is_empty() {
            return Ok(None);
        }
        let password = match map.get(SMTP_PASSWORD).filter(|v| !v.is_empty()) {
            Some(stored) => {
                let bytes = crypto::decrypt(stored, &self.key_encryption_key)
                    .map_err(|e| DomainError::Repository(format!("smtp password decrypt: {e}")))?;
                String::from_utf8(bytes)
                    .map_err(|_| DomainError::Repository("smtp password is not UTF-8".into()))?
            }
            None => String::new(),
        };
        Ok(Some(SmtpServerConfig {
            host,
            port: map.get(SMTP_PORT).and_then(|v| v.parse().ok()),
            username: map.get(SMTP_USERNAME).cloned().unwrap_or_default(),
            password,
            from_address,
            use_tls: map.get(SMTP_USE_TLS).map(|v| v == "true").unwrap_or(false),
        }))
    }

    /// 全体の SMTP 設定を取得する。パスワードは平文を返さず「設定済みか否か」（`password_set`）のみ返す。
    pub async fn get_smtp(&self) -> Result<SmtpSettingsView> {
        Ok(smtp_view_from(&self.load_map().await?))
    }

    /// SMTP 設定を保存する。`password` が `Some` のときのみパスワードを暗号化して上書きする
    /// （`None` は現行維持、`Some("")` は消去）。
    pub async fn update_smtp(
        &self,
        tenant: TenantContext,
        cmd: UpdateSmtpCommand,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<SmtpSettingsView> {
        self.upsert_plain(SMTP_HOST, &cmd.host).await?;
        self.upsert_plain(
            SMTP_PORT,
            &cmd.port.map(|p| p.to_string()).unwrap_or_default(),
        )
        .await?;
        self.upsert_plain(SMTP_USERNAME, &cmd.username).await?;
        self.upsert_plain(SMTP_FROM_ADDRESS, &cmd.from_address)
            .await?;
        self.upsert_plain(SMTP_USE_TLS, if cmd.use_tls { "true" } else { "false" })
            .await?;

        if let Some(password) = cmd.password {
            let stored = if password.is_empty() {
                String::new()
            } else {
                crypto::encrypt(password.as_bytes(), &self.key_encryption_key)
                    .map_err(|e| DomainError::Repository(format!("smtp password encrypt: {e}")))?
            };
            self.repo
                .upsert(&SystemSetting {
                    key: SMTP_PASSWORD.to_string(),
                    value: stored,
                    is_secret: true,
                })
                .await?;
        }

        self.audit
            .record(
                AuditEventType::SystemSettingsUpdated,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                actor.user_id(),
                actor.client_id(),
                Some("smtp"),
                ctx,
            )
            .await;

        self.get_smtp().await
    }

    /// SMS 送信用にゲートウェイ接続情報（復号済みトークン込み）を返す（AP13）。**画面表示には
    /// 使わない**（表示用は `get_sms`）。URL が未設定なら `None`（SMS 送信は無効）。
    /// 返り値の秘匿値をログ・監査に出さないこと。
    pub async fn sms_gateway(&self) -> Result<Option<SmsGatewayConfig>> {
        let map = self.load_map().await?;
        let endpoint_url = map.get(SMS_GATEWAY_URL).cloned().unwrap_or_default();
        if endpoint_url.trim().is_empty() {
            return Ok(None);
        }
        let auth_token = match map.get(SMS_AUTH_TOKEN).filter(|v| !v.is_empty()) {
            Some(stored) => {
                let bytes = crypto::decrypt(stored, &self.key_encryption_key)
                    .map_err(|e| DomainError::Repository(format!("sms token decrypt: {e}")))?;
                String::from_utf8(bytes)
                    .map_err(|_| DomainError::Repository("sms token is not UTF-8".into()))?
            }
            None => String::new(),
        };
        Ok(Some(SmsGatewayConfig {
            endpoint_url,
            auth_header: map.get(SMS_AUTH_HEADER).cloned().unwrap_or_default(),
            auth_token,
            sender_id: map.get(SMS_SENDER_ID).cloned().unwrap_or_default(),
        }))
    }

    /// SMS ゲートウェイ設定を取得する。トークンは平文を返さず「設定済みか否か」のみ返す。
    pub async fn get_sms(&self) -> Result<SmsSettingsView> {
        let map = self.load_map().await?;
        Ok(SmsSettingsView {
            gateway_url: map.get(SMS_GATEWAY_URL).cloned().unwrap_or_default(),
            auth_header: map.get(SMS_AUTH_HEADER).cloned().unwrap_or_default(),
            auth_token_set: map
                .get(SMS_AUTH_TOKEN)
                .map(|v| !v.is_empty())
                .unwrap_or(false),
            sender_id: map.get(SMS_SENDER_ID).cloned().unwrap_or_default(),
        })
    }

    /// SMS ゲートウェイ設定を保存する。`auth_token` が `Some` のときのみトークンを暗号化して
    /// 上書きする（`None` は現行維持、`Some("")` は消去。SMTP パスワードと同じ規則）。
    pub async fn update_sms(
        &self,
        tenant: TenantContext,
        cmd: UpdateSmsCommand,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<SmsSettingsView> {
        self.upsert_plain(SMS_GATEWAY_URL, cmd.gateway_url.trim())
            .await?;
        self.upsert_plain(SMS_AUTH_HEADER, cmd.auth_header.trim())
            .await?;
        self.upsert_plain(SMS_SENDER_ID, cmd.sender_id.trim())
            .await?;

        if let Some(token) = cmd.auth_token {
            let stored = if token.is_empty() {
                String::new()
            } else {
                crypto::encrypt(token.as_bytes(), &self.key_encryption_key)
                    .map_err(|e| DomainError::Repository(format!("sms token encrypt: {e}")))?
            };
            self.repo
                .upsert(&SystemSetting {
                    key: SMS_AUTH_TOKEN.to_string(),
                    value: stored,
                    is_secret: true,
                })
                .await?;
        }

        self.audit
            .record(
                AuditEventType::SystemSettingsUpdated,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                actor.user_id(),
                actor.client_id(),
                Some("sms"),
                ctx,
            )
            .await;

        self.get_sms().await
    }

    /// DB に保存されているランタイム設定（`RUNTIME_SETTING_DEFINITIONS` のキー）の上書き値を返す
    /// （表示用。空文字列 = 未設定として除外する。secret キーは含めない）。
    pub async fn runtime_overrides(&self) -> Result<HashMap<String, String>> {
        let map = self.load_map().await?;
        Ok(map
            .into_iter()
            .filter(|(key, value)| {
                !value.is_empty()
                    && runtime_setting_definition(key)
                        .map(|def| !def.secret)
                        .unwrap_or(false)
            })
            .collect())
    }

    /// ランタイム設定の DB 上書き値を更新する。`DB_MANAGED` かつ非 secret のキーのみ許可する。
    /// `value` が `None` または空文字列のときは上書きを解除する（既定値・環境変数へ戻る）。
    /// 反映には再起動が必要（起動時に `Config` が解決する）。
    pub async fn update_runtime_setting(
        &self,
        tenant: TenantContext,
        key: &str,
        value: Option<String>,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<()> {
        let def = runtime_setting_definition(key).ok_or_else(|| {
            DomainError::InvalidValue(format!("unknown runtime setting key: {key}"))
        })?;
        if def.owner != SettingOwner::DbManaged || def.secret {
            return Err(DomainError::InvalidValue(format!(
                "setting {key} is not DB-managed"
            )));
        }
        let value = value.map(|v| v.trim().to_string()).unwrap_or_default();
        if !value.is_empty() {
            // 書式の検査はテナント設定（ADR-0058）と同じ関数を通す。片方だけ規則を変えると、
            // 全体には保存できるのにテナントには保存できない値が生まれる。
            validate_setting_value(def, &value).map_err(DomainError::InvalidValue)?;
            // 書式が正しくても、その値では次回起動できないことがある（https ISSUER × 開発用既定
            // secret）。保存してしまうと再起動で api・web ごと落ちて画面から直せなくなるため、
            // 「値の書式」ではなく「配置状態との衝突」として 409 相当で返す（ADR-0017）。
            ensure_override_is_bootable(key, &value, &self.deployment_state)
                .map_err(DomainError::Conflict)?;
        }
        // 空文字列の upsert = 上書き解除（`Config` の resolver は空値を未設定として扱う）。
        self.upsert_plain(key, &value).await?;
        self.audit
            .record(
                AuditEventType::SystemSettingsUpdated,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                actor.user_id(),
                actor.client_id(),
                // 値そのものは記録しない（キーと設定/解除の別のみ）。
                Some(&format!(
                    "runtime {key} {}",
                    if value.is_empty() { "cleared" } else { "set" }
                )),
                ctx,
            )
            .await;
        Ok(())
    }

    async fn upsert_plain(&self, key: &str, value: &str) -> Result<()> {
        self.repo
            .upsert(&SystemSetting {
                key: key.to_string(),
                value: value.to_string(),
                is_secret: false,
            })
            .await
    }
}

/// テナントが自分のメールの経路を持っているか（[`SMTP_ROUTE_DEFINING_KEYS`] が 1 つでもあるか）。
fn defines_own_route(map: &HashMap<String, String>) -> bool {
    SMTP_ROUTE_DEFINING_KEYS
        .iter()
        .any(|key| map.get(*key).is_some_and(|v| !v.is_empty()))
}

/// 保存形式の塊から表示用の SMTP 設定を作る（パスワードは設定の有無だけ）。
fn smtp_view_from(map: &HashMap<String, String>) -> SmtpSettingsView {
    SmtpSettingsView {
        host: map.get(SMTP_HOST).cloned().unwrap_or_default(),
        port: map.get(SMTP_PORT).and_then(|v| v.parse().ok()),
        username: map.get(SMTP_USERNAME).cloned().unwrap_or_default(),
        password_set: map
            .get(SMTP_PASSWORD)
            .map(|v| !v.is_empty())
            .unwrap_or(false),
        from_address: map.get(SMTP_FROM_ADDRESS).cloned().unwrap_or_default(),
        use_tls: map.get(SMTP_USE_TLS).map(|v| v == "true").unwrap_or(false),
    }
}

/// テナントの設定を持たない実装（テナントの経路を使わない試験の土台）。
#[cfg(test)]
pub(crate) struct NoTenantSettings;

#[cfg(test)]
#[async_trait::async_trait]
impl TenantSettingsRepository for NoTenantSettings {
    async fn load_for_tenant(&self, _tenant_id: TenantId) -> Result<Vec<TenantSetting>> {
        Ok(Vec::new())
    }
    async fn upsert(&self, _setting: &TenantSetting) -> Result<()> {
        Ok(())
    }
    async fn delete(&self, _tenant_id: TenantId, _key: &str) -> Result<()> {
        Ok(())
    }
    async fn list_overrides_across_tenants(
        &self,
    ) -> Result<crate::domain::tenant_setting::TenantOverridesAcrossTenants> {
        Ok(Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::audit::AuditEvent;
    use crate::domain::repositories::AuditLogSink;
    use std::sync::Mutex;
    use uuid::Uuid;

    fn request() -> RequestContext {
        RequestContext {
            correlation_id: "test".into(),
            ip_address: None,
            user_agent: None,
        }
    }

    const KEY: [u8; 32] = *b"unit-test-key-0123456789abcdef!!";

    struct FixedClock;
    impl Clock for FixedClock {
        fn now(&self) -> chrono::DateTime<chrono::Utc> {
            chrono::DateTime::from_timestamp(1_758_000_000, 0).unwrap()
        }
    }

    #[derive(Default)]
    struct MemorySystemSettings(Mutex<Vec<SystemSetting>>);
    #[async_trait::async_trait]
    impl SystemSettingsRepository for MemorySystemSettings {
        async fn load_all(&self) -> Result<Vec<SystemSetting>> {
            Ok(self.0.lock().unwrap().clone())
        }
        async fn upsert(&self, setting: &SystemSetting) -> Result<()> {
            let mut rows = self.0.lock().unwrap();
            rows.retain(|r| r.key != setting.key);
            rows.push(setting.clone());
            Ok(())
        }
    }

    #[derive(Default)]
    struct MemoryTenantSettings(Mutex<Vec<TenantSetting>>);
    #[async_trait::async_trait]
    impl TenantSettingsRepository for MemoryTenantSettings {
        async fn load_for_tenant(&self, tenant_id: TenantId) -> Result<Vec<TenantSetting>> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.tenant_id == tenant_id)
                .cloned()
                .collect())
        }
        async fn upsert(&self, setting: &TenantSetting) -> Result<()> {
            let mut rows = self.0.lock().unwrap();
            rows.retain(|r| !(r.tenant_id == setting.tenant_id && r.key == setting.key));
            rows.push(setting.clone());
            Ok(())
        }
        async fn delete(&self, tenant_id: TenantId, key: &str) -> Result<()> {
            self.0
                .lock()
                .unwrap()
                .retain(|r| !(r.tenant_id == tenant_id && r.key == key));
            Ok(())
        }
        async fn list_overrides_across_tenants(
            &self,
        ) -> Result<crate::domain::tenant_setting::TenantOverridesAcrossTenants> {
            Ok(Default::default())
        }
    }

    struct NullSink;
    #[async_trait::async_trait]
    impl AuditLogSink for NullSink {
        async fn record(&self, _event: &AuditEvent) -> Result<()> {
            Ok(())
        }
    }

    struct Fixture {
        service: SystemSettingsService,
        tenants: Arc<MemoryTenantSettings>,
    }

    /// 全体の経路（パスワード付き）が入った状態。
    async fn fixture() -> Fixture {
        let system = Arc::new(MemorySystemSettings::default());
        let tenants = Arc::new(MemoryTenantSettings::default());
        let service = SystemSettingsService::new(
            system,
            tenants.clone(),
            KEY,
            DeploymentState::default(),
            Arc::new(AuditService::new(Arc::new(NullSink), Arc::new(FixedClock))),
            Arc::new(FixedClock),
        );
        service
            .update_smtp(
                TenantContext::new(tenant()),
                UpdateSmtpCommand {
                    host: "smtp.whole.example".into(),
                    port: Some(587),
                    username: "whole".into(),
                    password: Some("whole-secret".into()),
                    from_address: "noreply@whole.example".into(),
                    use_tls: true,
                },
                &actor(),
                &request(),
            )
            .await
            .unwrap();
        Fixture { service, tenants }
    }

    fn tenant() -> TenantId {
        Uuid::now_v7().into()
    }

    fn actor() -> AdminActor {
        AdminActor::User(Uuid::now_v7())
    }

    fn command(host: &str, password: Option<&str>) -> UpdateSmtpCommand {
        UpdateSmtpCommand {
            host: host.into(),
            port: Some(25),
            username: "tenant".into(),
            password: password.map(str::to_string),
            from_address: "noreply@tenant.example".into(),
            use_tls: false,
        }
    }

    #[tokio::test]
    async fn a_tenant_without_its_own_route_sends_through_the_whole_idp_route() {
        let f = fixture().await;
        let t = tenant();
        let server = f.service.smtp_server_for(t).await.unwrap().unwrap();
        assert_eq!(server.host, "smtp.whole.example");
        assert_eq!(server.password, "whole-secret");
        assert!(f.service.get_tenant_smtp(t).await.unwrap().inherited);
    }

    #[tokio::test]
    async fn a_tenant_route_is_used_as_a_whole() {
        let f = fixture().await;
        let t = tenant();
        f.service
            .update_tenant_smtp(
                TenantContext::new(t),
                command("smtp.tenant.example", Some("tenant-secret")),
                &actor(),
                &request(),
            )
            .await
            .unwrap();
        let server = f.service.smtp_server_for(t).await.unwrap().unwrap();
        assert_eq!(server.host, "smtp.tenant.example");
        assert_eq!(server.password, "tenant-secret");
        assert_eq!(server.from_address, "noreply@tenant.example");
    }

    /// ⚠ いちばん大事な試験。テナントが `host` だけを持ち、パスワードを未設定にしても、
    /// **全体のパスワードがそのテナントのサーバへ送られない**（項目ごとに全体へ落とさない）。
    #[tokio::test]
    async fn the_whole_idp_password_never_goes_to_a_tenant_server() {
        let f = fixture().await;
        let t = tenant();
        f.service
            .update_tenant_smtp(
                TenantContext::new(t),
                command("smtp.attacker.example", None),
                &actor(),
                &request(),
            )
            .await
            .unwrap();
        let server = f.service.smtp_server_for(t).await.unwrap().unwrap();
        assert_eq!(server.host, "smtp.attacker.example");
        assert_eq!(
            server.password, "",
            "the whole-IdP password must not be borrowed"
        );
        assert_eq!(server.username, "tenant");
    }

    /// 経路を持っているのに `host` が空なら、全体へ落ちずにメールを送れない状態になる。
    #[tokio::test]
    async fn an_incomplete_tenant_route_does_not_fall_back_to_the_whole_idp() {
        let f = fixture().await;
        let t = tenant();
        f.service
            .update_tenant_smtp(
                TenantContext::new(t),
                command("", Some("tenant-secret")),
                &actor(),
                &request(),
            )
            .await
            .unwrap();
        assert!(f.service.smtp_server_for(t).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn one_tenant_route_does_not_leak_into_another_tenant() {
        let f = fixture().await;
        let (a, b) = (tenant(), tenant());
        f.service
            .update_tenant_smtp(
                TenantContext::new(a),
                command("smtp.a.example", Some("a-secret")),
                &actor(),
                &request(),
            )
            .await
            .unwrap();
        let server = f.service.smtp_server_for(b).await.unwrap().unwrap();
        assert_eq!(server.host, "smtp.whole.example");
    }

    /// パスワードは暗号化して保存し、表示には設定の有無だけを出す。
    #[tokio::test]
    async fn the_tenant_password_is_stored_encrypted_and_never_shown() {
        let f = fixture().await;
        let t = tenant();
        let view = f
            .service
            .update_tenant_smtp(
                TenantContext::new(t),
                command("smtp.tenant.example", Some("tenant-secret")),
                &actor(),
                &request(),
            )
            .await
            .unwrap();
        assert!(view.settings.password_set);
        assert!(!view.inherited);
        let rows = f.tenants.0.lock().unwrap().clone();
        let stored = rows.iter().find(|r| r.key == SMTP_PASSWORD).unwrap();
        assert!(stored.is_secret);
        assert_ne!(stored.value, "tenant-secret");
    }

    /// 空のフォームを保存しただけでメールが止まらない（行ごと消えて全体に従う）。
    #[tokio::test]
    async fn saving_an_empty_form_returns_the_tenant_to_the_whole_idp_route() {
        let f = fixture().await;
        let t = tenant();
        f.service
            .update_tenant_smtp(
                TenantContext::new(t),
                command("smtp.tenant.example", Some("tenant-secret")),
                &actor(),
                &request(),
            )
            .await
            .unwrap();
        let empty = UpdateSmtpCommand {
            password: Some(String::new()),
            ..UpdateSmtpCommand::default()
        };
        let view = f
            .service
            .update_tenant_smtp(TenantContext::new(t), empty, &actor(), &request())
            .await
            .unwrap();
        assert!(view.inherited);
        assert!(f.tenants.0.lock().unwrap().is_empty());
        let server = f.service.smtp_server_for(t).await.unwrap().unwrap();
        assert_eq!(server.host, "smtp.whole.example");
    }

    #[tokio::test]
    async fn clearing_returns_the_tenant_to_the_whole_idp_route() {
        let f = fixture().await;
        let t = tenant();
        f.service
            .update_tenant_smtp(
                TenantContext::new(t),
                command("smtp.tenant.example", Some("tenant-secret")),
                &actor(),
                &request(),
            )
            .await
            .unwrap();
        let view = f
            .service
            .clear_tenant_smtp(TenantContext::new(t), &actor(), &request())
            .await
            .unwrap();
        assert!(view.inherited);
        assert_eq!(
            f.service.smtp_server_for(t).await.unwrap().unwrap().host,
            "smtp.whole.example"
        );
    }
}
