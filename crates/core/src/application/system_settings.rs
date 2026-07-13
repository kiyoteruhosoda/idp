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
use crate::domain::error::{DomainError, Result};
use crate::domain::mailer::SmtpServerConfig;
use crate::domain::repositories::SystemSettingsRepository;
use crate::domain::system_setting::{
    SmtpSettingsView, SystemSetting, UpdateSmtpCommand, SMTP_FROM_ADDRESS, SMTP_HOST,
    SMTP_PASSWORD, SMTP_PORT, SMTP_USERNAME, SMTP_USE_TLS,
};
use crate::domain::tenant_context::TenantContext;
use crate::infrastructure::crypto;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

pub struct SystemSettingsService {
    repo: Arc<dyn SystemSettingsRepository>,
    key_encryption_key: [u8; 32],
    audit: Arc<AuditService>,
    #[allow(dead_code)]
    clock: Arc<dyn Clock>,
}

impl SystemSettingsService {
    pub fn new(
        repo: Arc<dyn SystemSettingsRepository>,
        key_encryption_key: [u8; 32],
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            repo,
            key_encryption_key,
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
