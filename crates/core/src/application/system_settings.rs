//! システム設定ユースケース（root/idp.system.admin による SMTP 等の管理。ADR-0009 §5、MT14）。
//!
//! `system_settings` テーブル（DB 層）を読み書きする。秘匿値（SMTP パスワード）は
//! `crypto::encrypt`（AES-256-GCM）で暗号化して保存し、参照時は**平文を返さない**
//! （設定済みか否かのみ返す）。認可（root のみ）は Presentation の `RequirePerms<IdpSystemAdmin>`
//! が担い、本サービスは呼び出された時点で認可済みとして扱う。
//!
//! 設定値の消費側（MT17 招待メール・MT18 パスワードリセット）は本サービスの `get_smtp` を通す。

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::error::{DomainError, Result};
use crate::domain::mailer::SmtpServerConfig;
use crate::domain::repositories::SystemSettingsRepository;
use crate::domain::sms::SmsGatewayConfig;
use crate::domain::system_setting::{
    ensure_override_is_bootable, runtime_setting_definition, validate_public_base_url,
    DeploymentState, SettingKind, SettingOwner, SmsSettingsView, SmtpSettingsView, SystemSetting,
    UpdateSmsCommand, UpdateSmtpCommand, SMS_AUTH_HEADER, SMS_AUTH_TOKEN, SMS_GATEWAY_URL,
    SMS_SENDER_ID, SMTP_FROM_ADDRESS, SMTP_HOST, SMTP_PASSWORD, SMTP_PORT, SMTP_USERNAME,
    SMTP_USE_TLS,
};
use crate::domain::tenant_context::TenantContext;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

pub struct SystemSettingsService {
    repo: Arc<dyn SystemSettingsRepository>,
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
        key_encryption_key: [u8; 32],
        deployment_state: DeploymentState,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            repo,
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

    /// メール配送用に SMTP 接続情報（復号済みパスワード込み）を返す。**画面表示には使わない**
    /// （表示用は `get_smtp`）。`host` または `from_address` が未設定なら `None`（配送は無効。
    /// 呼び出し側は手動伝達へフォールバックする）。返り値の秘匿値をログ・監査に出さないこと。
    pub async fn smtp_server(&self) -> Result<Option<SmtpServerConfig>> {
        let map = self.load_map().await?;
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

    /// SMTP 設定を取得する。パスワードは平文を返さず「設定済みか否か」（`password_set`）のみ返す。
    pub async fn get_smtp(&self) -> Result<SmtpSettingsView> {
        let map = self.load_map().await?;
        Ok(SmtpSettingsView {
            host: map.get(SMTP_HOST).cloned().unwrap_or_default(),
            port: map.get(SMTP_PORT).and_then(|v| v.parse().ok()),
            username: map.get(SMTP_USERNAME).cloned().unwrap_or_default(),
            password_set: map
                .get(SMTP_PASSWORD)
                .map(|v| !v.is_empty())
                .unwrap_or(false),
            from_address: map.get(SMTP_FROM_ADDRESS).cloned().unwrap_or_default(),
            use_tls: map.get(SMTP_USE_TLS).map(|v| v == "true").unwrap_or(false),
        })
    }

    /// SMTP 設定を保存する。`password` が `Some` のときのみパスワードを暗号化して上書きする
    /// （`None` は現行維持、`Some("")` は消去）。
    pub async fn update_smtp(
        &self,
        tenant: TenantContext,
        cmd: UpdateSmtpCommand,
        actor: Uuid,
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
                Some(actor),
                None,
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
        actor: Uuid,
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
                Some(actor),
                None,
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
        actor: Uuid,
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
            match def.kind {
                SettingKind::UnsignedInteger => {
                    // `Config` 側の最小の消費型（`KEY_ROTATION_LEAD_DAYS` 等の u32）でも起動時に
                    // 必ずパースできるよう、u32 の範囲で検証する（範囲外を保存すると再起動が
                    // 構成エラーで失敗するため）。
                    value.parse::<u32>().map_err(|_| {
                        DomainError::InvalidValue(format!(
                            "setting {key} must be a non-negative integer (max {})",
                            u32::MAX
                        ))
                    })?;
                }
                SettingKind::Boolean => {
                    if value != "true" && value != "false" {
                        return Err(DomainError::InvalidValue(format!(
                            "setting {key} must be true or false"
                        )));
                    }
                }
                SettingKind::Text => {}
                SettingKind::PublicBaseUrl => {
                    validate_public_base_url(key, &value).map_err(DomainError::InvalidValue)?;
                }
            }
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
                Some(actor),
                None,
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
