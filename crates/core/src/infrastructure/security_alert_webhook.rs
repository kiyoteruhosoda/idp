//! セキュリティの知らせを Webhook で送る（task #872。ADR-0071）。
//!
//! 送る形は nolumia notice の受け口（`POST /api/notices`、`Authorization: Bearer <受付の鍵>`）と同じ
//! JSON（`source` / `level` / `headline` / `items` / `key`）。宛先と鍵は**環境変数だけ**で決める
//! （`SECURITY_ALERT_WEBHOOK_URL` / `SECURITY_ALERT_WEBHOOK_TOKEN_FILE`。画面から通信先を変えさせない）。
//!
//! 送信は呼び出し元を待たせない（`tokio::spawn`）。失敗したら間を空けて 3 回まで送り直し、それでも
//! 届かなければエラーログを残して諦める。出来事そのものは監査ログに残っている。

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Value};

use crate::domain::security_alert::{
    SecurityAlert, SecurityAlertKind, SecurityAlertSeverity, SecurityAlertSink,
};
use crate::domain::values::AuthenticationMethod;

/// 送り直しの回数（最初の 1 回を含まない）。
const RETRIES: u32 = 3;
/// 1 回の送信の時間切れ。
const TIMEOUT: Duration = Duration::from_secs(10);

/// Webhook の送り口。
pub struct WebhookSecurityAlertSink {
    client: reqwest::Client,
    url: String,
    token: Arc<str>,
    retry_base: Duration,
}

impl WebhookSecurityAlertSink {
    /// `url` は http(s) の URL、`token` は受付の鍵（ファイルから読んだ値）。
    pub fn new(url: String, token: String) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(TIMEOUT)
            // 送り先が別の場所へ転送しても追わない（鍵を載せたまま知らない宛先へ行かせない）。
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!(
                "assay/",
                env!("CARGO_PKG_VERSION"),
                " security-alert"
            ))
            .build()?;
        Ok(Self {
            client,
            url,
            token: Arc::from(token.trim()),
            retry_base: Duration::from_secs(5),
        })
    }

    async fn deliver(
        client: reqwest::Client,
        url: String,
        token: Arc<str>,
        body: Value,
        retry_base: Duration,
    ) {
        for attempt in 0..=RETRIES {
            if attempt > 0 {
                tokio::time::sleep(retry_base * 2u32.pow(attempt - 1)).await;
            }
            let result = client
                .post(&url)
                .bearer_auth(token.as_ref())
                .json(&body)
                .send()
                .await;
            match result {
                Ok(response) if response.status().is_success() => return,
                Ok(response) => {
                    tracing::warn!(
                        status = response.status().as_u16(),
                        attempt,
                        "security alert webhook answered with an error"
                    );
                    // 4xx は送り直しても通らない（鍵の誤り・形の誤り）。
                    if response.status().is_client_error() {
                        break;
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, attempt, "security alert webhook request failed");
                }
            }
        }
        tracing::error!("security alert could not be delivered; it remains in the audit log");
    }
}

#[async_trait]
impl SecurityAlertSink for WebhookSecurityAlertSink {
    async fn send(&self, alert: SecurityAlert) {
        let body = notice_body(&alert);
        tokio::spawn(Self::deliver(
            self.client.clone(),
            self.url.clone(),
            self.token.clone(),
            body,
            self.retry_base,
        ));
    }
}

fn method_label(method: &AuthenticationMethod) -> &'static str {
    match method {
        AuthenticationMethod::WebAuthn => "パスキー",
        AuthenticationMethod::Password => "パスワード",
        AuthenticationMethod::Totp => "確認コード（TOTP）",
        AuthenticationMethod::RecoveryCode => "回復コード",
        AuthenticationMethod::EmailOtp => "メールの確認コード",
        AuthenticationMethod::SmsOtp => "SMS の確認コード",
        AuthenticationMethod::ExternalIdp => "外部のログイン",
        AuthenticationMethod::AppApproval => "認証アプリでの承認",
    }
}

/// notice の受け口の形へ組み立てる。
///
/// ⚠ 知らせの文言は運用者（持ち主）が読むものなので日本語で組む（assay の利用者向けの i18n とは別）。
pub(crate) fn notice_body(alert: &SecurityAlert) -> Value {
    let (headline, key_prefix) = match &alert.kind {
        SecurityAlertKind::UnregisteredDeviceSignIn { first_seen, .. } => (
            if *first_seen {
                format!(
                    "登録していない端末で {} がログインしました（初めての端末）",
                    alert.username
                )
            } else {
                format!("登録していない端末で {} がログインしました", alert.username)
            },
            "unregistered-device",
        ),
        SecurityAlertKind::UnregisteredDeviceRefused { .. } => (
            format!(
                "登録していない端末で {} のログインが正しく行われかけました（ログインはさせていません）",
                alert.username
            ),
            "unregistered-device-refused",
        ),
        SecurityAlertKind::DeviceRegistered { device_name } => (
            format!("{} が端末「{}」を登録しました", alert.username, device_name),
            "device-registered",
        ),
        SecurityAlertKind::DeviceRevoked { device_name } => (
            format!(
                "{} が端末「{}」の登録を取り消しました",
                alert.username, device_name
            ),
            "device-revoked",
        ),
        SecurityAlertKind::DeviceExpired { device_name } => (
            format!(
                "{} の端末「{}」の登録が切れました（180 日使われていません）",
                alert.username, device_name
            ),
            "device-expired",
        ),
        SecurityAlertKind::SshKeyRegistered { key_name, .. } => (
            format!(
                "{} が SSH の鍵「{}」を登録しました",
                alert.username, key_name
            ),
            "ssh-key-registered",
        ),
        SecurityAlertKind::SshKeyRevoked { key_name, .. } => (
            format!(
                "{} が SSH の鍵「{}」を取り消しました",
                alert.username, key_name
            ),
            "ssh-key-revoked",
        ),
        SecurityAlertKind::SessionKeyMismatch => (
            format!(
                "{} のログイン状態が、結び付けた端末の鍵とは別の鍵で使われようとしました（Cookie の持ち出しの疑い）",
                alert.username
            ),
            "session-key-mismatch",
        ),
        SecurityAlertKind::ApproverKeyRegistered { device_name } => (
            format!(
                "{} が認証アプリ（{}）の鍵を登録しました",
                alert.username, device_name
            ),
            "approver-key-registered",
        ),
        SecurityAlertKind::ApproverKeyRevoked { device_name } => (
            format!(
                "{} が認証アプリ（{}）の鍵を取り消しました",
                alert.username, device_name
            ),
            "approver-key-revoked",
        ),
        SecurityAlertKind::AppApprovalFromAnotherBrowser { device_name } => (
            format!(
                "{} が認証アプリ（{}）で承認したログインを、別のブラウザで使おうとしました（ログインはさせていません）",
                alert.username, device_name
            ),
            "app-approval-another-browser",
        ),
    };
    let subject = match &alert.kind {
        SecurityAlertKind::SshKeyRegistered { .. } | SecurityAlertKind::SshKeyRevoked { .. } => {
            "SSH の鍵"
        }
        SecurityAlertKind::ApproverKeyRegistered { .. }
        | SecurityAlertKind::ApproverKeyRevoked { .. }
        | SecurityAlertKind::AppApprovalFromAnotherBrowser { .. } => "認証アプリ",
        _ => "ログインした端末",
    };

    let mut details = vec![format!(
        "時刻: {}",
        alert.occurred_at.format("%Y-%m-%d %H:%M:%S UTC")
    )];
    details.push(format!(
        "国: {}",
        alert
            .country
            .as_ref()
            .map(|c| c.as_str().to_string())
            .unwrap_or_else(|| "不明（家の中からの接続か、国が分からない接続）".to_string())
    ));
    if let Some(ip) = &alert.ip_address {
        details.push(format!("接続元: {ip}"));
    }
    if let Some(ua) = &alert.user_agent {
        details.push(format!(
            "ブラウザ: {}",
            ua.chars().take(300).collect::<String>()
        ));
    }
    if let SecurityAlertKind::SshKeyRegistered { fingerprint, .. }
    | SecurityAlertKind::SshKeyRevoked { fingerprint, .. } = &alert.kind
    {
        details.push(format!("指紋: {fingerprint}"));
    }
    if let SecurityAlertKind::UnregisteredDeviceSignIn { methods, .. }
    | SecurityAlertKind::UnregisteredDeviceRefused { methods } = &alert.kind
    {
        let labels: Vec<&str> = methods.iter().map(method_label).collect();
        details.push(format!(
            "入り方: {}",
            if labels.is_empty() {
                "不明".to_string()
            } else {
                labels.join(" ＋ ")
            }
        ));
    }

    let look = match &alert.kind {
        SecurityAlertKind::UnregisteredDeviceSignIn { .. } => vec![
            "自分のログインなら、その端末で assay の「アカウントのセキュリティ」→「端末」から登録すると次から鳴りません"
                .to_string(),
            "覚えが無ければ、assay の「アカウントのセキュリティ」でそのセッションを切り、パスワードとパスキーを確かめてください"
                .to_string(),
        ],
        SecurityAlertKind::UnregisteredDeviceRefused { .. } => vec![
            "自分なら、その端末でパスキーで確かめて登録すれば入れます（登録すると「端末を登録しました」の知らせも届きます）"
                .to_string(),
            "覚えが無ければ、「入り方」の資格情報（パスワードなど）が他人に使われています。すぐに変えてください（登録していない端末なので、まだ入られてはいません）"
                .to_string(),
        ],
        SecurityAlertKind::DeviceRegistered { .. } => vec![
            "覚えが無ければ、assay の「アカウントのセキュリティ」→「端末」から取り消してください".to_string(),
        ],
        SecurityAlertKind::SshKeyRegistered { .. } => vec![
            "この鍵は数分のうちに機器（nolumialab・naso・ASUS）へ配られます".to_string(),
            "覚えが無ければ、すぐに assay の「アカウントのセキュリティ」→「SSH の鍵」から取り消し、パスキーを確かめてください".to_string(),
        ],
        SecurityAlertKind::SessionKeyMismatch => vec![
            "そのログイン状態は終わらせました。本人はログインし直せば使えます".to_string(),
            "その端末の Cookie が持ち出された疑いがあります。端末のウイルス対策を確かめ、assay の「アカウントのセキュリティ」で他のセッションも切ってください"
                .to_string(),
        ],
        SecurityAlertKind::ApproverKeyRegistered { .. } => vec![
            "覚えが無ければ、assay の「アカウントのセキュリティ」→「端末」の「認証アプリ」から取り消してください（その鍵で承認したログイン状態も終わります）".to_string(),
        ],
        SecurityAlertKind::AppApprovalFromAnotherBrowser { .. } => vec![
            "自分のスマホで始めたログインでなければ、だれかが別の端末で始めた依頼を承認させようとした疑いがあります".to_string(),
            "ログインはさせていません。心当たりが無ければパスワードとパスキーを確かめてください".to_string(),
        ],
        _ => Vec::new(),
    };

    json!({
        "source": "assay",
        "level": match alert.kind.severity() {
            SecurityAlertSeverity::Warning => "warning",
            SecurityAlertSeverity::Info => "info",
        },
        "headline": headline,
        "items": [{
            "subject": subject,
            "state": "",
            "details": details,
        }],
        "look": look,
        // 同じ端末の同じ種類の知らせを 1 件へ束ねる（対応済みにするまで足されていく）。
        "key": format!("assay-{key_prefix}-{}", alert.group_key),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::tenant::TenantId;
    use crate::domain::user_device::CountryCode;
    use chrono::{TimeZone, Utc};
    use uuid::Uuid;

    fn alert(kind: SecurityAlertKind) -> SecurityAlert {
        SecurityAlert {
            kind,
            tenant_id: TenantId::from(Uuid::nil()),
            user_id: Uuid::nil(),
            username: "kyon".to_string(),
            occurred_at: Utc.with_ymd_and_hms(2026, 11, 4, 9, 0, 0).unwrap(),
            country: CountryCode::parse("JP"),
            ip_address: Some("203.0.113.7".to_string()),
            user_agent: Some("Mozilla/5.0".to_string()),
            group_key: "abcd1234".to_string(),
        }
    }

    #[test]
    fn unregistered_sign_in_is_a_warning_with_method_and_country() {
        let body = notice_body(&alert(SecurityAlertKind::UnregisteredDeviceSignIn {
            first_seen: true,
            methods: vec![AuthenticationMethod::Password, AuthenticationMethod::Totp],
        }));
        assert_eq!(body["source"], "assay");
        assert_eq!(body["level"], "warning");
        assert_eq!(body["key"], "assay-unregistered-device-abcd1234");
        let headline = body["headline"].as_str().unwrap();
        assert!(headline.contains("kyon"));
        assert!(headline.contains("初めて"));
        let details: Vec<&str> = body["items"][0]["details"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(details.contains(&"国: JP"));
        assert!(details.contains(&"入り方: パスワード ＋ 確認コード（TOTP）"));
    }

    #[test]
    fn ssh_key_registration_is_a_warning_with_the_fingerprint() {
        let body = notice_body(&alert(SecurityAlertKind::SshKeyRegistered {
            key_name: "kyon-pc".to_string(),
            fingerprint: "SHA256:abc".to_string(),
        }));
        assert_eq!(body["level"], "warning");
        assert_eq!(body["key"], "assay-ssh-key-registered-abcd1234");
        assert_eq!(body["items"][0]["subject"], "SSH の鍵");
        assert!(body["headline"].as_str().unwrap().contains("kyon-pc"));
        let details = body["items"][0]["details"].as_array().unwrap();
        assert!(details.iter().any(|d| d == "指紋: SHA256:abc"));
    }

    #[test]
    fn expiry_is_informational() {
        let body = notice_body(&alert(SecurityAlertKind::DeviceExpired {
            device_name: "pc".to_string(),
        }));
        assert_eq!(body["level"], "info");
    }

    #[test]
    fn unknown_country_says_so() {
        let mut a = alert(SecurityAlertKind::DeviceRegistered {
            device_name: "pc".to_string(),
        });
        a.country = None;
        let body = notice_body(&a);
        let details = body["items"][0]["details"].as_array().unwrap();
        assert!(details
            .iter()
            .any(|d| d.as_str().unwrap().starts_with("国: 不明")));
    }
}
