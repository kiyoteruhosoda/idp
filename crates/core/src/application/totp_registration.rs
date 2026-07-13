//! TOTP（Time-based One-Time Password）の自己登録ユースケース。
//!
//! MFA は任意でユーザーが自身でセットアップ・削除する。登録フロー:
//! 1. `setup()` — シークレット生成・仮保存・QR URI と生シークレット（base32）を返す。
//! 2. `confirm()` — 6 桁コードを検証してシークレットを有効化する。
//! 3. `delete()` — TOTP 設定を削除する（MFA 無効化）。
//!
//! シークレットは `crypto::encrypt` で AES-256-GCM 暗号化して DB に保存し、
//! 検証時にのみ復号する（signing_keys と同方式）。

use crate::domain::clock::Clock;
use crate::domain::error::DomainError;
use crate::domain::repositories::{SsoSessionRepository, TotpSecretRepository};
use crate::domain::totp_secret::TotpSecret;
use crate::infrastructure::crypto;
use std::sync::Arc;
use totp_rs::{Algorithm, Secret, TOTP};
use uuid::Uuid;

/// TOTP の桁数（RFC 6238 標準の 6 桁）。
const TOTP_DIGITS: usize = 6;
/// TOTP のステップ（秒。RFC 4226 のデフォルト 30 秒）。
const TOTP_STEP: u64 = 30;
/// 許容するクロックスキュー（前後 1 ステップ = ±30 秒）。
const TOTP_SKEW: u8 = 1;
/// 生成するシークレットのバイト数（160 bit = 20 bytes。HMAC-SHA1 の出力長に合わせる）。
const SECRET_BYTES: usize = 20;

#[derive(Debug, thiserror::Error)]
pub enum TotpRegistrationError {
    #[error("totp already configured and confirmed")]
    AlreadyConfigured,
    #[error("invalid totp code")]
    InvalidCode,
    #[error("no pending totp setup found")]
    NotFound,
    #[error("sso session expired or not found")]
    SessionExpired,
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<DomainError> for TotpRegistrationError {
    fn from(e: DomainError) -> Self {
        TotpRegistrationError::Internal(e.to_string())
    }
}

/// TOTP セットアップ開始時に返すデータ。
pub struct TotpSetupData {
    /// `otpauth://totp/...` URI（QR コード生成に使う）。
    pub totp_uri: String,
    /// base32 エンコードされたシークレット（QR コードが使えないユーザー向けに直接表示する）。
    pub secret_base32: String,
}

pub struct TotpRegistrationService {
    totp_secrets: Arc<dyn TotpSecretRepository>,
    sso_sessions: Arc<dyn SsoSessionRepository>,
    key_encryption_key: [u8; 32],
    issuer: String,
    clock: Arc<dyn Clock>,
}

impl TotpRegistrationService {
    pub fn new(
        totp_secrets: Arc<dyn TotpSecretRepository>,
        sso_sessions: Arc<dyn SsoSessionRepository>,
        key_encryption_key: [u8; 32],
        issuer: impl Into<String>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            totp_secrets,
            sso_sessions,
            key_encryption_key,
            issuer: issuer.into(),
            clock,
        }
    }

    /// TOTP セットアップを開始する。仮登録中のシークレットを生成・保存し、QR URI と生シークレットを返す。
    ///
    /// - すでに有効な（confirmed）TOTP がある場合は `AlreadyConfigured` を返す。
    /// - `sso_session_id` は Cookie の生値（SHA-256 ハッシュで DB 検索する）。
    pub async fn setup(
        &self,
        sso_session_id: &str,
        account_name: &str,
    ) -> Result<TotpSetupData, TotpRegistrationError> {
        let user_id = self.resolve_user(sso_session_id).await?;

        // すでに有効な TOTP が設定済みなら拒否する。
        if let Some(existing) = self.totp_secrets.find_by_user_id(user_id).await? {
            if existing.is_confirmed() {
                return Err(TotpRegistrationError::AlreadyConfigured);
            }
        }

        // 新しいシークレットを生成する。
        let secret_bytes = generate_secret();
        let secret_base32 = to_base32(&secret_bytes);
        let totp_uri = build_totp_uri(&secret_bytes, account_name, &self.issuer)?;
        let secret_encrypted = crypto::encrypt(&secret_bytes, &self.key_encryption_key)
            .map_err(|e| TotpRegistrationError::Internal(e.to_string()))?;

        let now = self.clock.now();
        let record = TotpSecret {
            user_id,
            secret_encrypted,
            confirmed_at: None,
            created_at: now,
            updated_at: now,
        };
        self.totp_secrets.upsert(&record).await?;

        Ok(TotpSetupData {
            totp_uri,
            secret_base32,
        })
    }

    /// TOTP を確定する。ユーザーが提示した 6 桁コードを検証し、`confirmed_at` を設定する。
    pub async fn confirm(
        &self,
        sso_session_id: &str,
        code: &str,
    ) -> Result<(), TotpRegistrationError> {
        let user_id = self.resolve_user(sso_session_id).await?;

        let record = self
            .totp_secrets
            .find_by_user_id(user_id)
            .await?
            .ok_or(TotpRegistrationError::NotFound)?;

        // 仮登録中のシークレットのみ確定できる。
        if record.is_confirmed() {
            return Err(TotpRegistrationError::AlreadyConfigured);
        }

        let secret_bytes = crypto::decrypt(&record.secret_encrypted, &self.key_encryption_key)
            .map_err(|e| TotpRegistrationError::Internal(e.to_string()))?;

        if !verify_totp_code(&secret_bytes, code)? {
            return Err(TotpRegistrationError::InvalidCode);
        }

        let now = self.clock.now();
        self.totp_secrets.confirm(user_id, now).await?;
        Ok(())
    }

    /// TOTP 設定を削除する（MFA 無効化）。
    pub async fn delete(&self, sso_session_id: &str) -> Result<(), TotpRegistrationError> {
        let user_id = self.resolve_user(sso_session_id).await?;
        self.totp_secrets.delete(user_id).await?;
        Ok(())
    }

    /// SSO セッション Cookie 値からユーザー ID を解決する。
    async fn resolve_user(&self, sso_session_id: &str) -> Result<Uuid, TotpRegistrationError> {
        let hash = crypto::sha256_hex(sso_session_id);
        let session = self
            .sso_sessions
            .find_by_hash(&hash)
            .await?
            .ok_or(TotpRegistrationError::SessionExpired)?;
        let now = self.clock.now();
        if session.idle_expires_at <= now || session.absolute_expires_at <= now {
            return Err(TotpRegistrationError::SessionExpired);
        }
        Ok(session.user_id)
    }
}

// --- TOTP ユーティリティ ---

/// 20 バイトの暗号学的乱数シークレットを生成する。
fn generate_secret() -> Vec<u8> {
    use rand::RngCore;
    let mut buf = vec![0u8; SECRET_BYTES];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

/// バイト列を base32 エンコードする（Google Authenticator 互換。アルファベット大文字 + 数字）。
pub fn to_base32(bytes: &[u8]) -> String {
    // totp-rs の Secret::Raw から Encoded（base32）へ変換する。
    let secret = Secret::Raw(bytes.to_vec());
    secret.to_encoded().to_string()
}

/// `otpauth://totp/` URI を構築する。QR コード生成に使う。
fn build_totp_uri(
    secret_bytes: &[u8],
    account_name: &str,
    issuer: &str,
) -> Result<String, TotpRegistrationError> {
    let totp = TOTP::new(
        Algorithm::SHA1,
        TOTP_DIGITS,
        TOTP_SKEW,
        TOTP_STEP,
        secret_bytes.to_vec(),
        Some(issuer.to_string()),
        account_name.to_string(),
    )
    .map_err(|e| TotpRegistrationError::Internal(format!("failed to build TOTP: {e}")))?;
    Ok(totp.get_url())
}

/// TOTP コードを検証する。`true` なら有効。
pub fn verify_totp_code(secret_bytes: &[u8], code: &str) -> Result<bool, TotpRegistrationError> {
    // アカウント名は検証に不要（issuer も同様）。空文字で構わない。
    let totp = TOTP::new(
        Algorithm::SHA1,
        TOTP_DIGITS,
        TOTP_SKEW,
        TOTP_STEP,
        secret_bytes.to_vec(),
        None,
        String::new(),
    )
    .map_err(|e| TotpRegistrationError::Internal(format!("failed to build TOTP: {e}")))?;
    totp.check_current(code)
        .map_err(|e| TotpRegistrationError::Internal(format!("TOTP check failed: {e}")))
}
