//! 認証器の統合管理ユースケース（AP9。ユーザー認証・認証ポリシー仕様書 §5）。
//!
//! 扱うのは 3 つ:
//!
//! 1. **一覧と状態管理** — 種別によらず「この人が使える認証器」を 1 箇所で返し、一時停止・再開・
//!    失効を行う。一時停止があるのは、端末を失くしたが手元に戻るかもしれないという状況に、
//!    削除以外の答えを用意するため。
//! 2. **リカバリーコード** — 認証器を全部失った利用者の自助手段。束（既定 10 本）で発行し、
//!    1 本ずつ使い捨てる。平文は発行時にしか見せず、DB には SHA-256 だけ置く。
//! 3. **email OTP** — 認証アプリを持てない利用者向けの第二要素。登録済みアドレスへ短命コードを
//!    送り、1 回だけ使える認証器として登録簿へ積む。
//!
//! いずれも「登録簿（`user_authenticators`）」を単一の出所とし、ログイン側は種別ごとの分岐では
//! なく登録簿の問い合わせで済むようにする。

use crate::application::audit::{AuditService, RequestContext};
use crate::application::system_settings::SystemSettingsService;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::id_generator::IdGenerator;
use crate::domain::mailer::{Mailer, OutgoingEmail};
use crate::domain::repositories::{UserAuthenticatorRepository, UserRepository};
use crate::domain::user_authenticator::{
    AuthenticatorStatus, AuthenticatorType, UserAuthenticator,
};
use chrono::{DateTime, Duration, Utc};
use std::sync::Arc;
use uuid::Uuid;

/// 一度に発行するリカバリーコードの本数。
///
/// 少なすぎると復旧の途中で尽き、多すぎると印刷・保管が雑になる（結果として漏れやすくなる）。
/// 一般的な IdP と同じ 10 本にする。
const RECOVERY_CODE_COUNT: usize = 10;
/// リカバリーコード 1 本の乱数バイト数（80 bit）。人が書き写せる長さと推測不能性の折り合い。
const RECOVERY_CODE_BYTES: usize = 10;
/// email OTP のコード桁数。
const EMAIL_OTP_DIGITS: u32 = 6;
/// email OTP の有効期間。
const EMAIL_OTP_TTL_SECS: i64 = 600;

/// 一覧に出す認証器 1 件（秘密は含めない）。
#[derive(Debug, Clone)]
pub struct AuthenticatorSummary {
    pub id: Uuid,
    pub authenticator_type: AuthenticatorType,
    pub status: AuthenticatorStatus,
    pub label: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthenticatorManagementError {
    #[error("authenticator not found")]
    NotFound,
    #[error("transition is not allowed")]
    InvalidTransition,
    #[error("email delivery is not configured")]
    MailUnavailable,
    #[error("internal error: {0}")]
    Internal(String),
}

/// リカバリーコードの発行結果。**平文はこの戻り値でしか得られない**（DB はハッシュのみ）。
pub struct IssuedRecoveryCodes {
    pub codes: Vec<String>,
}

pub struct AuthenticatorManagementService {
    authenticators: Arc<dyn UserAuthenticatorRepository>,
    users: Arc<dyn UserRepository>,
    system_settings: Arc<SystemSettingsService>,
    mailer: Arc<dyn Mailer>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
}

impl AuthenticatorManagementService {
    pub fn new(
        authenticators: Arc<dyn UserAuthenticatorRepository>,
        users: Arc<dyn UserRepository>,
        system_settings: Arc<SystemSettingsService>,
        mailer: Arc<dyn Mailer>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
    ) -> Self {
        Self {
            authenticators,
            users,
            system_settings,
            mailer,
            audit,
            clock,
            ids,
        }
    }

    /// 利用者の認証器を一覧する（失効済みは出さない — 画面に並べても操作できず、数が増えるだけ）。
    ///
    /// リカバリーコードは 1 本 1 行なので、そのまま並べると一覧が 10 行埋まる。呼び出し側が
    /// 「残り n 本」として畳めるよう、種別ごとの件数は [`Self::usable_recovery_code_count`] で別に取る。
    pub async fn list(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<AuthenticatorSummary>, AuthenticatorManagementError> {
        let rows = self
            .authenticators
            .list_for_user(user_id)
            .await
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))?;
        Ok(rows
            .into_iter()
            .filter(|a| a.status != AuthenticatorStatus::Revoked)
            .filter(|a| a.authenticator_type != AuthenticatorType::RecoveryCode)
            .map(|a| AuthenticatorSummary {
                id: a.id,
                authenticator_type: a.authenticator_type,
                status: a.status,
                label: a.label,
                created_at: a.created_at,
                last_used_at: a.last_used_at,
            })
            .collect())
    }

    /// 残っている（未使用・未失効の）リカバリーコードの本数。
    pub async fn usable_recovery_code_count(
        &self,
        user_id: Uuid,
    ) -> Result<usize, AuthenticatorManagementError> {
        let rows = self
            .authenticators
            .list_usable_for_user(
                user_id,
                Some(AuthenticatorType::RecoveryCode),
                self.clock.now(),
            )
            .await
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))?;
        Ok(rows.len())
    }

    /// 状態を変える（一時停止・再開・失効）。遷移の可否はドメインの規則で判定する。
    pub async fn set_status(
        &self,
        tenant_id: crate::domain::tenant::TenantId,
        user_id: Uuid,
        authenticator_id: Uuid,
        next: AuthenticatorStatus,
        ctx: &RequestContext,
    ) -> Result<(), AuthenticatorManagementError> {
        let current = self
            .authenticators
            .find_by_id(authenticator_id)
            .await
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))?
            .filter(|a| a.user_id == user_id)
            .ok_or(AuthenticatorManagementError::NotFound)?;

        if !current.status.can_transition_to(next) {
            return Err(AuthenticatorManagementError::InvalidTransition);
        }

        let now = self.clock.now();
        let updated = self
            .authenticators
            .update_status(authenticator_id, user_id, next, now)
            .await
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))?;
        if !updated {
            return Err(AuthenticatorManagementError::NotFound);
        }

        self.audit
            .record(
                AuditEventType::AuthenticatorStatusChanged,
                AuditResult::Success,
                Some(tenant_id),
                Some(user_id),
                None,
                Some(&format!(
                    "type={} status={next}",
                    current.authenticator_type
                )),
                ctx,
            )
            .await;
        Ok(())
    }

    /// リカバリーコードを（再）発行する。**既存の束は必ず失効させる**。
    ///
    /// 古い束を残したまま新しい束を出すと、印刷して捨てたはずのコードがずっと有効なままになる。
    /// 「今手元にある紙が唯一の束」でなければ、利用者は何が有効か管理できない。
    pub async fn issue_recovery_codes(
        &self,
        tenant_id: crate::domain::tenant::TenantId,
        user_id: Uuid,
        ctx: &RequestContext,
    ) -> Result<IssuedRecoveryCodes, AuthenticatorManagementError> {
        let now = self.clock.now();
        self.authenticators
            .revoke_all_of_type(user_id, AuthenticatorType::RecoveryCode, now)
            .await
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))?;

        let mut codes = Vec::with_capacity(RECOVERY_CODE_COUNT);
        for _ in 0..RECOVERY_CODE_COUNT {
            let code = crypto::random_hex(RECOVERY_CODE_BYTES);
            let row = UserAuthenticator {
                id: self.ids.new_id(),
                user_id,
                authenticator_type: AuthenticatorType::RecoveryCode,
                status: AuthenticatorStatus::Active,
                label: String::new(),
                // 平文は返り値でしか出さない。DB はハッシュのみ（他の bearer credential と同じ）。
                secret_encrypted: Some(crypto::sha256_hex(&code)),
                credential_ref: None,
                target: None,
                confirmed_at: Some(now),
                last_used_at: None,
                // リカバリーコードは期限を持たない（使うのは「他が全部だめなとき」なので、
                // その時点で期限切れだと手段が無くなる）。
                expires_at: None,
                revoked_at: None,
                created_at: now,
                updated_at: now,
            };
            self.authenticators
                .create(&row)
                .await
                .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))?;
            codes.push(code);
        }

        self.audit
            .record(
                AuditEventType::RecoveryCodesIssued,
                AuditResult::Success,
                Some(tenant_id),
                Some(user_id),
                None,
                Some(&format!("count={RECOVERY_CODE_COUNT}")),
                ctx,
            )
            .await;
        Ok(IssuedRecoveryCodes { codes })
    }

    /// リカバリーコードを検証して消費する（1 回きり）。成功なら `true`。
    pub async fn consume_recovery_code(
        &self,
        tenant_id: crate::domain::tenant::TenantId,
        user_id: Uuid,
        code: &str,
        ctx: &RequestContext,
    ) -> Result<bool, AuthenticatorManagementError> {
        let now = self.clock.now();
        let used = consume_single_use_code(
            self.authenticators.as_ref(),
            user_id,
            AuthenticatorType::RecoveryCode,
            code,
            now,
        )
        .await
        .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))?;
        self.audit
            .record(
                AuditEventType::RecoveryCodeUsed,
                if used {
                    AuditResult::Success
                } else {
                    AuditResult::Failure
                },
                Some(tenant_id),
                Some(user_id),
                None,
                // 残数を残すと「あと何本か」を運用側から追える（コードそのものは記録しない）。
                Some(&format!(
                    "remaining={}",
                    self.remaining_after(user_id).await
                )),
                ctx,
            )
            .await;
        Ok(used)
    }

    /// email OTP を発行して送信する。送信先は登録済みメールアドレス。
    pub async fn send_email_otp(
        &self,
        tenant_id: crate::domain::tenant::TenantId,
        user_id: Uuid,
        ctx: &RequestContext,
    ) -> Result<(), AuthenticatorManagementError> {
        let server = self
            .system_settings
            .smtp_server()
            .await
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))?
            .ok_or(AuthenticatorManagementError::MailUnavailable)?;

        let user = self
            .users
            .find_by_id(user_id)
            .await
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))?
            .ok_or(AuthenticatorManagementError::NotFound)?;

        let now = self.clock.now();
        // 前のコードは必ず失効させる。同時に複数のコードが有効だと、総当たりの成功率が本数倍になる。
        self.authenticators
            .revoke_all_of_type(user_id, AuthenticatorType::EmailOtp, now)
            .await
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))?;

        let code = numeric_code(EMAIL_OTP_DIGITS);
        let row = UserAuthenticator {
            id: self.ids.new_id(),
            user_id,
            authenticator_type: AuthenticatorType::EmailOtp,
            status: AuthenticatorStatus::Active,
            label: String::new(),
            secret_encrypted: Some(crypto::sha256_hex(&code)),
            credential_ref: None,
            target: Some(user.email.clone()),
            confirmed_at: Some(now),
            last_used_at: None,
            expires_at: Some(now + Duration::seconds(EMAIL_OTP_TTL_SECS)),
            revoked_at: None,
            created_at: now,
            updated_at: now,
        };
        self.authenticators
            .create(&row)
            .await
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))?;

        // 本文は運用言語（英語）ではなく利用者向けなので、訳出は Presentation 層が担うべきだが、
        // メール送信は Application 層で完結する必要がある（送信の成否を判定に使うため）。
        // 現状のメール文面（招待・パスワードリセット）と同じ扱いで、ここでは英語で組み立てる。
        let mail = OutgoingEmail {
            to: user.email.clone(),
            subject: "Your verification code".to_string(),
            body_text: format!(
                "Your verification code is {code}.\n\n\
                 It expires in {} minutes. If you did not request it, you can ignore this email.\n",
                EMAIL_OTP_TTL_SECS / 60
            ),
        };
        self.mailer
            .send(&server, &mail)
            .await
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))?;

        self.audit
            .record(
                AuditEventType::EmailOtpSent,
                AuditResult::Success,
                Some(tenant_id),
                Some(user_id),
                None,
                // 送信先アドレスは PII なので記録しない。
                None,
                ctx,
            )
            .await;
        Ok(())
    }

    /// email OTP を検証して消費する（1 回きり）。成功なら `true`。
    pub async fn consume_email_otp(
        &self,
        user_id: Uuid,
        code: &str,
    ) -> Result<bool, AuthenticatorManagementError> {
        consume_single_use_code(
            self.authenticators.as_ref(),
            user_id,
            AuthenticatorType::EmailOtp,
            code,
            self.clock.now(),
        )
        .await
        .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))
    }

    // ── 登録簿の同期（TOTP・WebAuthn） ──────────────────────────────────────
    //
    // 秘密は従来のテーブルに置いたままなので（expand フェーズ）、登録・削除のたびに登録簿へ
    // 同じ出来事を反映する。ここが漏れると登録簿は「実際には使えない認証器を載せた一覧」に
    // なり、一覧としても認証ポリシーの参照先としても信用できなくなる。

    /// TOTP の仮登録を登録簿へ積む（既存の TOTP 行は失効させて 1 本に保つ）。
    pub async fn register_totp_pending(
        &self,
        user_id: Uuid,
    ) -> Result<(), AuthenticatorManagementError> {
        let now = self.clock.now();
        self.authenticators
            .revoke_all_of_type(user_id, AuthenticatorType::Totp, now)
            .await
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))?;
        let row = UserAuthenticator {
            id: self.ids.new_id(),
            user_id,
            authenticator_type: AuthenticatorType::Totp,
            status: AuthenticatorStatus::Pending,
            label: String::new(),
            // TOTP のシークレットは `user_totp_secrets` にある（登録簿は状態だけを持つ）。
            secret_encrypted: None,
            credential_ref: None,
            target: None,
            confirmed_at: None,
            last_used_at: None,
            expires_at: None,
            revoked_at: None,
            created_at: now,
            updated_at: now,
        };
        self.authenticators
            .create(&row)
            .await
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))
    }

    /// TOTP の確認完了を登録簿へ反映する（`pending` → `active`）。
    pub async fn activate_totp(&self, user_id: Uuid) -> Result<(), AuthenticatorManagementError> {
        let now = self.clock.now();
        let rows = self
            .authenticators
            .list_for_user(user_id)
            .await
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))?;
        let Some(pending) = rows.into_iter().find(|a| {
            a.authenticator_type == AuthenticatorType::Totp
                && a.status == AuthenticatorStatus::Pending
        }) else {
            // 登録簿の導入前に仮登録された行が無い場合。確認済みの行として作り直す。
            return self.create_active_totp(user_id, now).await;
        };
        self.authenticators
            .update_status(pending.id, user_id, AuthenticatorStatus::Active, now)
            .await
            .map(|_| ())
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))
    }

    /// TOTP の削除を登録簿へ反映する。
    pub async fn revoke_totp(&self, user_id: Uuid) -> Result<(), AuthenticatorManagementError> {
        self.authenticators
            .revoke_all_of_type(user_id, AuthenticatorType::Totp, self.clock.now())
            .await
            .map(|_| ())
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))
    }

    /// WebAuthn クレデンシャルの登録を登録簿へ積む。
    pub async fn register_webauthn(
        &self,
        user_id: Uuid,
        credential_ref: Uuid,
        label: &str,
    ) -> Result<(), AuthenticatorManagementError> {
        let now = self.clock.now();
        let row = UserAuthenticator {
            id: self.ids.new_id(),
            user_id,
            authenticator_type: AuthenticatorType::WebAuthn,
            status: AuthenticatorStatus::Active,
            label: label.to_string(),
            secret_encrypted: None,
            credential_ref: Some(credential_ref),
            target: None,
            confirmed_at: Some(now),
            last_used_at: None,
            expires_at: None,
            revoked_at: None,
            created_at: now,
            updated_at: now,
        };
        self.authenticators
            .create(&row)
            .await
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))
    }

    /// WebAuthn クレデンシャルの削除を登録簿へ反映する（対象が無ければ何もしない）。
    pub async fn revoke_webauthn(
        &self,
        user_id: Uuid,
        credential_ref: Uuid,
    ) -> Result<(), AuthenticatorManagementError> {
        let now = self.clock.now();
        let rows = self
            .authenticators
            .list_for_user(user_id)
            .await
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))?;
        let Some(target) = rows
            .into_iter()
            .find(|a| a.credential_ref == Some(credential_ref))
        else {
            return Ok(());
        };
        self.authenticators
            .update_status(target.id, user_id, AuthenticatorStatus::Revoked, now)
            .await
            .map(|_| ())
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))
    }

    /// 管理者による MFA 解除（MT21）を登録簿へ反映する（TOTP・WebAuthn・リカバリーコードを失効）。
    ///
    /// リカバリーコードも落とすのは、端末を失った利用者の復旧手段を管理者が作り直す操作だから。
    /// 古い束が生き残っていると「解除したのに古い紙で入れる」状態になる。
    pub async fn revoke_all_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<(), AuthenticatorManagementError> {
        let now = self.clock.now();
        for authenticator_type in [
            AuthenticatorType::Totp,
            AuthenticatorType::WebAuthn,
            AuthenticatorType::RecoveryCode,
            AuthenticatorType::EmailOtp,
        ] {
            self.authenticators
                .revoke_all_of_type(user_id, authenticator_type, now)
                .await
                .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))?;
        }
        Ok(())
    }

    async fn create_active_totp(
        &self,
        user_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<(), AuthenticatorManagementError> {
        let row = UserAuthenticator {
            id: self.ids.new_id(),
            user_id,
            authenticator_type: AuthenticatorType::Totp,
            status: AuthenticatorStatus::Active,
            label: String::new(),
            secret_encrypted: None,
            credential_ref: None,
            target: None,
            confirmed_at: Some(now),
            last_used_at: None,
            expires_at: None,
            revoked_at: None,
            created_at: now,
            updated_at: now,
        };
        self.authenticators
            .create(&row)
            .await
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))
    }

    /// 監査へ載せる残数（取得に失敗しても監査を落とさないよう `-1` に倒す）。
    async fn remaining_after(&self, user_id: Uuid) -> i64 {
        match self.usable_recovery_code_count(user_id).await {
            Ok(n) => n as i64,
            Err(_) => -1,
        }
    }
}

/// 使い捨てコード（リカバリーコード・OTP）を正規化して消費する（AP9）。
///
/// ログイン経路（`MfaLoginService`）と管理ユースケースの両方が呼ぶため、**正規化の規則を 1 箇所に
/// 置く**ことが目的の関数。正規化がずれると「発行時と同じ文字列なのに一致しない」が起きる。
/// 空白と `-` を落とし、リカバリーコードは大小を無視する（紙から書き写す前提の値のため）。
pub async fn consume_single_use_code(
    repository: &dyn UserAuthenticatorRepository,
    user_id: Uuid,
    authenticator_type: AuthenticatorType,
    code: &str,
    now: DateTime<Utc>,
) -> Result<bool, crate::domain::error::DomainError> {
    let stripped = code.trim().replace([' ', '-'], "");
    let normalized = if authenticator_type == AuthenticatorType::RecoveryCode {
        stripped.to_lowercase()
    } else {
        stripped
    };
    if normalized.is_empty() {
        return Ok(false);
    }
    let consumed = repository
        .consume_single_use(
            user_id,
            authenticator_type,
            &crypto::sha256_hex(&normalized),
            now,
        )
        .await?;
    Ok(consumed.is_some())
}

/// 数字だけの使い捨てコードを作る（メール・SMS で読み上げ・転記される前提）。
///
/// 桁を落とさないよう先頭ゼロ埋めする（`012345` を `12345` にすると桁数が揺れ、検証側で
/// 正規化が要る ＝ 事故のもとになる）。
fn numeric_code(digits: u32) -> String {
    let modulus = 10u64.pow(digits);
    // 暗号学的乱数から 64bit を取り、剰余で桁に収める。10^6 は 2^64 を割り切らないため厳密な
    // 一様分布ではないが、偏りは 2^-44 未満で総当たり耐性に影響しない。
    let bytes = crypto::random_hex(8);
    let value = u64::from_str_radix(&bytes, 16).unwrap_or(0) % modulus;
    format!("{value:0width$}", width = digits as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_codes_keep_their_width() {
        for _ in 0..200 {
            let code = numeric_code(6);
            assert_eq!(code.len(), 6, "{code}");
            assert!(code.bytes().all(|b| b.is_ascii_digit()), "{code}");
        }
    }

    /// 生成されるコードは毎回違う（同じ値が返るなら乱数源の取り違え）。
    #[test]
    fn numeric_codes_are_not_constant() {
        let first = numeric_code(6);
        assert!((0..50).any(|_| numeric_code(6) != first));
    }
}
