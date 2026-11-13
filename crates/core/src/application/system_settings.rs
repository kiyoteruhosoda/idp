//! System settings use case (management of SMTP etc. by root/idp.system.admin. ADR-0009 §5, MT14).
//!
//! Reads and writes the `system_settings` table (DB layer). Secret values (SMTP password) are
//! encrypted with `crypto::encrypt` (AES-256-GCM) when stored, and **plaintext is never returned** on read
//! (only whether it is set). Authorization (root only) is handled by Presentation's `RequirePerms<IdpSystemAdmin>`,
//! and this service treats itself as already authorized when called.
//!
//! Consumers of the settings (MT17 invitation email, MT18 password reset) go through this service's `get_smtp`.

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::admin_actor::AdminActor;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::error::{DomainError, Result};
use crate::domain::mailer::{SmtpRoute, SmtpServerConfig};
use crate::domain::outbound_uri::is_internal_host;
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

/// Keys that make up the mail route (ADR-0058 §8). A tenant's route is resolved as this **block**.
const SMTP_KEYS: &[&str] = &[
    SMTP_HOST,
    SMTP_PORT,
    SMTP_USERNAME,
    SMTP_PASSWORD,
    SMTP_FROM_ADDRESS,
    SMTP_USE_TLS,
];

/// Keys that decide whether a tenant has its own route. Rows with only `port` and `use_tls` are not counted
/// (the save form always sends defaults, so counting them would make saving an empty form count as having a route,
/// and it would no longer fall back to the global route: mail would silently stop).
const SMTP_ROUTE_DEFINING_KEYS: &[&str] =
    &[SMTP_HOST, SMTP_USERNAME, SMTP_PASSWORD, SMTP_FROM_ADDRESS];

/// For displaying a tenant's SMTP settings (ADR-0058 §8).
#[derive(Debug, Clone, Default)]
pub struct TenantSmtpView {
    /// This tenant's route (all fields empty if it has none). The password shows only whether it is set.
    pub settings: SmtpSettingsView,
    /// `true` = this tenant has no route and sends mail via the global route.
    pub inherited: bool,
}

pub struct SystemSettingsService {
    repo: Arc<dyn SystemSettingsRepository>,
    /// Tenants' mail routes (ADR-0058 §8). Kept in a separate table from the global one.
    tenant_settings: Arc<dyn TenantSettingsRepository>,
    key_encryption_key: [u8; 32],
    /// Deployment state of the running process (ADR-0017). Held to decide, before saving a DB override,
    /// "can the next startup succeed with that value".
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

    /// A tenant's mail route rows (as stored. Empty rows are excluded).
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

    /// Returns the SMTP connection info (including the decrypted password) for sending that tenant's mail (ADR-0058 §8).
    /// **Not used for screen display**. `None` means mail cannot be sent (the caller falls back to manual delivery).
    ///
    /// ⚠ **The route is decided as a block.** If the tenant has even one field of its own route, **only that tenant's block**
    /// is used, and missing fields are not filled with global values. Falling back per field would mean that just by pointing
    /// `host` at its own server and leaving `password` unset, a tenant would get **the global SMTP credentials
    /// sent to that tenant's server**.
    ///
    /// Do not output the returned secret values to logs or audits.
    pub async fn smtp_server_for(&self, tenant_id: TenantId) -> Result<Option<SmtpServerConfig>> {
        let tenant = self.tenant_smtp_map(tenant_id).await?;
        if defines_own_route(&tenant) {
            return self.smtp_server_from(&tenant, SmtpRoute::Tenant);
        }
        self.smtp_server_from(&self.load_map().await?, SmtpRoute::WholeIdp)
    }

    /// Returns the tenant's SMTP settings (the password shows only whether it is set).
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

    /// Saves the tenant's SMTP settings. `password`: `None` = keep current / `Some("")` = clear /
    /// `Some(x)` = set (same rules as the global settings).
    ///
    /// If, after saving, no route-defining field remains, **the row is deleted to go back to following the global route**
    /// (so that just saving an empty form does not stop mail).
    pub async fn update_tenant_smtp(
        &self,
        tenant: TenantContext,
        cmd: UpdateSmtpCommand,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<TenantSmtpView> {
        let tenant_id = tenant.tenant_id();
        // Destinations recognizably internal by their text are refused here. The resolved address is checked when sending (task #740).
        if !cmd.host.trim().is_empty() && is_internal_host(&cmd.host) {
            return Err(DomainError::InvalidValue(
                "smtp host must not point at an internal destination".to_string(),
            ));
        }
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

    /// Deletes the tenant's SMTP settings and goes back to following the global route.
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
                // The value itself is not recorded (only whether the route was set or cleared).
                Some(&format!("smtp {change}")),
                ctx,
            )
            .await;
    }

    /// Builds SMTP connection info from the stored block. `None` if `host` or `from_address` is empty.
    fn smtp_server_from(
        &self,
        map: &HashMap<String, String>,
        route: SmtpRoute,
    ) -> Result<Option<SmtpServerConfig>> {
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
            route,
        }))
    }

    /// Gets the global SMTP settings. The password is not returned in plaintext; only "set or not" (`password_set`).
    pub async fn get_smtp(&self) -> Result<SmtpSettingsView> {
        Ok(smtp_view_from(&self.load_map().await?))
    }

    /// Saves the SMTP settings. The password is encrypted and overwritten only when `password` is `Some`
    /// (`None` keeps current, `Some("")` clears).
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

    /// Returns gateway connection info (including the decrypted token) for sending SMS (AP13). **Not used for
    /// screen display** (display uses `get_sms`). `None` if the URL is unset (SMS sending disabled).
    /// Do not output the returned secret values to logs or audits.
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

    /// Gets the SMS gateway settings. The token is not returned in plaintext; only "set or not".
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

    /// Saves the SMS gateway settings. The token is encrypted and overwritten only when `auth_token` is `Some`
    /// (`None` keeps current, `Some("")` clears. Same rules as the SMTP password).
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

    /// Returns the DB override values of runtime settings (keys of `RUNTIME_SETTING_DEFINITIONS`)
    /// (for display. Empty strings are excluded as unset. Secret keys are not included).
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

    /// Updates the DB override value of a runtime setting. Only `DB_MANAGED`, non-secret keys are allowed.
    /// When `value` is `None` or an empty string, the override is removed (falls back to default / environment variable).
    /// A restart is needed to apply it (`Config` resolves it at startup).
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
            // Format checks go through the same function as tenant settings (ADR-0058). Changing the rules on only one side
            // would create values that can be saved globally but not for a tenant.
            validate_setting_value(def, &value).map_err(DomainError::InvalidValue)?;
            // Even with a correct format, the next startup may fail with that value (https ISSUER x development default
            // secret). Saving it would bring down both api and web on restart, unfixable from the screen, so
            // it is returned as a 409-equivalent "conflict with the deployment state", not a "value format" error (ADR-0017).
            ensure_override_is_bootable(key, &value, &self.deployment_state)
                .map_err(DomainError::Conflict)?;
        }
        // Upserting an empty string = removing the override (`Config`'s resolver treats empty values as unset).
        self.upsert_plain(key, &value).await?;
        self.audit
            .record(
                AuditEventType::SystemSettingsUpdated,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                actor.user_id(),
                actor.client_id(),
                // The value itself is not recorded (only the key and whether it was set or cleared).
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

/// Whether the tenant has its own mail route (whether any of [`SMTP_ROUTE_DEFINING_KEYS`] is present).
fn defines_own_route(map: &HashMap<String, String>) -> bool {
    SMTP_ROUTE_DEFINING_KEYS
        .iter()
        .any(|key| map.get(*key).is_some_and(|v| !v.is_empty()))
}

/// Builds display SMTP settings from the stored block (the password shows only whether it is set).
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

/// An implementation with no tenant settings (the base for tests that do not use tenant routes).
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

    /// A state containing the global route (with password).
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

    /// A tenant route destination recognizably internal by its text is refused on save (task #740).
    #[tokio::test]
    async fn a_tenant_route_to_an_internal_host_is_refused_on_save() {
        let f = fixture().await;
        let t = tenant();
        for host in [
            "mariadb",
            "10.10.2.11",
            "127.0.0.1",
            "169.254.169.254",
            "a.svc",
            "localhost",
        ] {
            let refused = f
                .service
                .update_tenant_smtp(
                    TenantContext::new(t),
                    command(host, Some("secret")),
                    &actor(),
                    &request(),
                )
                .await;
            assert!(
                matches!(refused, Err(DomainError::InvalidValue(_))),
                "{host}"
            );
        }
        assert!(f.service.get_tenant_smtp(t).await.unwrap().inherited);
    }

    /// The route distinction reaches sending (the destination is checked before sending only for tenant routes).
    #[tokio::test]
    async fn the_route_tells_where_the_config_came_from() {
        let f = fixture().await;
        let t = tenant();
        let whole = f.service.smtp_server_for(t).await.unwrap().unwrap();
        assert_eq!(whole.route, SmtpRoute::WholeIdp);
        f.service
            .update_tenant_smtp(
                TenantContext::new(t),
                command("smtp.tenant.example", Some("tenant-secret")),
                &actor(),
                &request(),
            )
            .await
            .unwrap();
        let own = f.service.smtp_server_for(t).await.unwrap().unwrap();
        assert_eq!(own.route, SmtpRoute::Tenant);
    }

    /// ⚠ The most important test. Even if a tenant has only `host` and leaves the password unset,
    /// **the global password is not sent to that tenant's server** (no per-field fallback to global).
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

    /// If a route exists but `host` is empty, it does not fall back to global and mail cannot be sent.
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

    /// The password is stored encrypted, and display shows only whether it is set.
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

    /// Just saving an empty form does not stop mail (the row is deleted and the global route is followed).
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
