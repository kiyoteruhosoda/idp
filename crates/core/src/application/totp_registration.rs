//! TOTP（Time-based One-Time Password）の自己登録ユースケース。
//!
//! MFA は任意でユーザーが自身でセットアップ・削除する。登録フロー:
//! 1. `setup()` — シークレット生成・仮保存・QR URI と生シークレット（base32）を返す。
//! 2. `confirm()` — 6 桁コードを検証してシークレットを有効化する。
//! 3. `delete()` — TOTP 設定を削除する（MFA 無効化）。
//!
//! シークレットは `crypto::encrypt` で AES-256-GCM 暗号化して DB に保存し、
//! 検証時にのみ復号する（signing_keys と同方式）。

use crate::application::authenticator_management::AuthenticatorManagementService;
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::error::DomainError;
use crate::domain::repositories::{SsoSessionRepository, TotpSecretRepository};
use crate::domain::totp_secret::TotpSecret;
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
    /// 認証器の登録簿（AP9）。秘密は本サービス側の表に残しつつ、状態は登録簿へ反映する。
    authenticators: Arc<AuthenticatorManagementService>,
    totp_secrets: Arc<dyn TotpSecretRepository>,
    sso_sessions: Arc<dyn SsoSessionRepository>,
    key_encryption_key: [u8; 32],
    issuer: String,
    clock: Arc<dyn Clock>,
}

impl TotpRegistrationService {
    pub fn new(
        authenticators: Arc<AuthenticatorManagementService>,
        totp_secrets: Arc<dyn TotpSecretRepository>,
        sso_sessions: Arc<dyn SsoSessionRepository>,
        key_encryption_key: [u8; 32],
        issuer: impl Into<String>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            authenticators,
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
        // **登録簿の行を先に作る。** 共有鍵の置き場所はその行なので（AP11b）、逆順にすると
        // 載せる先が無く、鍵は行が無いまま捨てられる（そして直後に作られる行は空になる）。
        self.authenticators
            .register_totp_pending(user_id)
            .await
            .map_err(|e| TotpRegistrationError::Internal(e.to_string()))?;
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

        let Some(step) = verify_totp_code(&secret_bytes, code)? else {
            return Err(TotpRegistrationError::InvalidCode);
        };

        let now = self.clock.now();
        // 確認に使ったコードのステップを記録しておき、同じコードを直後のログインで再利用できない
        // ようにする（登録→初回ログインの窓を跨いだリプレイを塞ぐ。RFC 6238 §5.2）。
        self.totp_secrets
            .record_totp_step_if_newer(user_id, step as i64, now)
            .await?;
        self.totp_secrets.confirm(user_id, now).await?;
        self.authenticators
            .activate_totp(user_id)
            .await
            .map_err(|e| TotpRegistrationError::Internal(e.to_string()))?;
        Ok(())
    }

    /// TOTP 設定を削除する（MFA 無効化）。
    pub async fn delete(&self, sso_session_id: &str) -> Result<(), TotpRegistrationError> {
        let user_id = self.resolve_user(sso_session_id).await?;
        self.totp_secrets.delete(user_id).await?;
        self.authenticators
            .revoke_totp(user_id)
            .await
            .map_err(|e| TotpRegistrationError::Internal(e.to_string()))?;
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

/// TOTP コードを検証し、一致した **time-step**（unix 秒 / `TOTP_STEP`）を返す。`None` なら無効。
///
/// 単なる真偽ではなくステップを返すのは、受理したコードの**再利用**（リプレイ）を防ぐためである
/// （RFC 6238 §5.2）。呼び出し側は返ったステップを記録し、同じか古いステップのコードを再受理
/// しない（`TotpSecretRepository::record_totp_step_if_newer`）。skew を許すため、現在ステップの
/// 前後 `TOTP_SKEW` 個を新しい側から順に照合し、最初に一致したステップを返す。
///
/// 時刻は `totp-rs` の `check_current` と同じく実時刻（`SystemTime`）を使う。TOTP は元々実時刻に
/// 束縛される要素で、ステップの算出も同じ時計に合わせる（この 1 か所に集約する）。
pub fn verify_totp_code(secret_bytes: &[u8], code: &str) -> Result<Option<u64>, TotpRegistrationError> {
    // skew はここで自前に扱うため、TOTP 自体は skew=0 で作る（`check` に厳密なステップを問う）。
    let totp = TOTP::new(
        Algorithm::SHA1,
        TOTP_DIGITS,
        0,
        TOTP_STEP,
        secret_bytes.to_vec(),
        None,
        String::new(),
    )
    .map_err(|e| TotpRegistrationError::Internal(format!("failed to build TOTP: {e}")))?;
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| TotpRegistrationError::Internal(format!("system clock before epoch: {e}")))?
        .as_secs();
    let base = (now_secs / TOTP_STEP) as i64;
    let skew = TOTP_SKEW as i64;
    // 新しいステップを優先して返す（同じコードが窓内の複数ステップに現れることは無いが、順序を
    // 決めておくと記録するステップが一意になる）。
    for delta in (-skew..=skew).rev() {
        let step = base + delta;
        if step < 0 {
            continue;
        }
        let time = (step as u64) * TOTP_STEP;
        // `check` は skew=0 のこの TOTP では `time` のステップだけを（定数時間比較で）照合する。
        if totp.check(code, time) {
            return Ok(Some(step as u64));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 現在有効なコードを実時刻で生成する（`verify_totp_code` と同じパラメータ）。
    fn current_code(secret: &[u8]) -> (String, u64) {
        let totp = TOTP::new(
            Algorithm::SHA1,
            TOTP_DIGITS,
            0,
            TOTP_STEP,
            secret.to_vec(),
            None,
            String::new(),
        )
        .unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        (totp.generate(now), now / TOTP_STEP)
    }

    #[test]
    fn a_valid_code_returns_the_matching_step() {
        let secret = [7u8; SECRET_BYTES];
        let (code, step) = current_code(&secret);
        assert_eq!(verify_totp_code(&secret, &code).unwrap(), Some(step));
    }

    #[test]
    fn a_wrong_code_returns_none() {
        let secret = [7u8; SECRET_BYTES];
        // 現在の正しいコードとは必ず異なる 6 桁を作る（末尾桁をずらす）。
        let (code, _) = current_code(&secret);
        let last: u32 = code[5..6].parse().unwrap();
        let tampered = format!("{}{}", &code[..5], (last + 1) % 10);
        assert_eq!(verify_totp_code(&secret, &tampered).unwrap(), None);
    }

    /// 返るステップは「今の time-step」であること（記録・再利用判定の基準になる値）。
    #[test]
    fn the_returned_step_is_the_current_time_step() {
        let secret = [42u8; SECRET_BYTES];
        let (code, step) = current_code(&secret);
        let matched = verify_totp_code(&secret, &code).unwrap().unwrap();
        // 生成と検証の間に境界を跨ぐと 1 ずれ得るため、±1 を許容する。
        assert!(
            matched == step || matched == step + 1 || matched + 1 == step,
            "matched={matched} step={step}"
        );
    }
}
