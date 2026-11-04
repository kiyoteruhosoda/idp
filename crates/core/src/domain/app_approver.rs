//! 認証アプリで承認するログイン（「アプリで続ける」。task #892。ADR-0077）。
//!
//! 3 つのものを持つ:
//!
//! | もの | 何か | 寿命 |
//! |---|---|---|
//! | [`ApproverKey`] | 利用者の認証アプリの鍵（Android の Keystore の中・使うたびに指紋）。「自分の端末」に並ぶ | 取り消すまで |
//! | [`ApproverEnrollment`] | 鍵の登録の受付。Key Attestation → パスキーで本人の確認 → アプリの署名で有効にする | 10 分 |
//! | [`ApprovalRequest`] | 「アプリで続ける」の依頼。始めたブラウザだけが持つ印（Cookie）に結ぶ | 5 分 |
//!
//! アプリはトークンを持たない。呼ぶたびに鍵で [`signed_message`] に署名する。
//!
//! # 別の端末で始めた依頼を承認させる攻撃
//!
//! 承認すると assay は使い捨てのコード（30 秒）を**アプリへ**返し、アプリが同じスマホのブラウザで開く。
//! ログインはそのコードと、依頼を始めたブラウザの印の両方が揃ったときだけ完了する。他人の端末で
//! 始めた依頼をだまされて承認しても、コードは持ち主のスマホのブラウザへ届き、そこには印が無い。
//! 依頼を始めたブラウザの側から「承認されたか」を待って完了する口は**作らない**（作るとこの守りが消える）。

use crate::domain::crypto;
use crate::domain::key_attestation::KeySecurityLevel;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// 鍵の登録の受付の寿命。
pub const ENROLLMENT_TTL_SECS: i64 = 600;
/// 登録の確認（パスキー）から、アプリが有効にするまでのコードの寿命。
pub const ENROLLMENT_CODE_TTL_SECS: i64 = 120;
/// 「アプリで続ける」の依頼の寿命。
pub const REQUEST_TTL_SECS: i64 = 300;
/// 承認して返すコードの寿命（持ち主の決定: 30 秒）。
pub const APPROVAL_CODE_TTL_SECS: i64 = 30;
/// 取り消しの署名の時刻の許容幅。
pub const SIGNED_AT_TOLERANCE_SECS: i64 = 300;
/// 機種名の長さの上限（文字数）。アプリの自己申告で、表示にだけ使う。
pub const MAX_DEVICE_NAME_CHARS: usize = 64;
/// 署名する文の先頭（版）。
pub const SIGNED_MESSAGE_VERSION: &str = "assay-app-approver-v1";
/// 識別子・challenge・コードの乱数のバイト数。
pub const RANDOM_BYTES: usize = 32;

/// アプリが署名する操作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedAction {
    Activate,
    Approve,
    Deny,
    Revoke,
}

impl SignedAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Activate => "activate",
            Self::Approve => "approve",
            Self::Deny => "deny",
            Self::Revoke => "revoke",
        }
    }
}

/// アプリが署名する文（UTF-8）。
///
/// `assay-app-approver-v1\n<操作>\n<組織>\n<対象>\n<使い捨ての値>`。操作と対象と組織を入れるのは、
/// ある操作への署名を別の操作・別の依頼・別の組織に使い回させないため。
pub fn signed_message(action: SignedAction, tenant_id: &str, target: &str, nonce: &str) -> String {
    format!(
        "{SIGNED_MESSAGE_VERSION}\n{}\n{tenant_id}\n{target}\n{nonce}",
        action.as_str()
    )
}

/// 鍵の番号: SubjectPublicKeyInfo（DER）の SHA-256 を base64url（パディングなし・43 文字）。
pub fn key_id_of(public_key_spki: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(public_key_spki))
}

/// 識別子・challenge・コードに使う乱数（base64url・43 文字）。
pub fn random_value() -> String {
    crypto::random_token(RANDOM_BYTES)
}

/// 利用者の認証アプリの鍵。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApproverKey {
    pub id: Uuid,
    pub user_id: Uuid,
    /// [`key_id_of`]。アプリはこの値で自分の鍵を名乗る。
    pub key_id: String,
    pub public_key_spki: Vec<u8>,
    pub security_level: KeySecurityLevel,
    /// アプリの自己申告の機種名（表示だけ）。
    pub device_name: String,
    pub registered_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// 鍵の登録の受付の段階。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollmentStage {
    /// challenge を出した。証明書の鎖を待つ。
    AwaitingKey,
    /// 鍵の証明は通った。利用者のパスキーでの確認を待つ。
    AwaitingConfirmation {
        public_key_spki: Vec<u8>,
        security_level: KeySecurityLevel,
        device_name: String,
    },
    /// 利用者が確認した。アプリが鍵で署名して有効にするのを待つ（コードの SHA-256 だけを持つ）。
    Confirmed {
        public_key_spki: Vec<u8>,
        security_level: KeySecurityLevel,
        device_name: String,
        user_id: Uuid,
        code_hash: String,
        code_expires_at: DateTime<Utc>,
    },
}

/// 鍵の登録の受付。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApproverEnrollment {
    pub id: String,
    pub tenant_id: Uuid,
    /// Key Attestation に入れてもらう値（base64url）。
    pub challenge: String,
    pub stage: EnrollmentStage,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl ApproverEnrollment {
    pub fn start(tenant_id: Uuid, now: DateTime<Utc>) -> Self {
        Self {
            id: random_value(),
            tenant_id,
            challenge: random_value(),
            stage: EnrollmentStage::AwaitingKey,
            created_at: now,
            expires_at: now + Duration::seconds(ENROLLMENT_TTL_SECS),
        }
    }

    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }

    /// challenge のバイト列（Key Attestation に入っているはずの値）。
    pub fn challenge_bytes(&self) -> Option<Vec<u8>> {
        URL_SAFE_NO_PAD.decode(self.challenge.as_bytes()).ok()
    }
}

/// 「アプリで続ける」の依頼の状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalState {
    Pending,
    Approved,
    Denied,
    Completed,
    /// 印が合わないブラウザで完了しようとした（別の端末で始めた依頼を承認した疑い）。
    Refused,
}

impl ApprovalState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Completed => "completed",
            Self::Refused => "refused",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "pending" => Some(Self::Pending),
            "approved" => Some(Self::Approved),
            "denied" => Some(Self::Denied),
            "completed" => Some(Self::Completed),
            "refused" => Some(Self::Refused),
            _ => None,
        }
    }
}

/// 「アプリで続ける」の依頼。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequest {
    pub id: String,
    pub tenant_id: Uuid,
    /// 始めたブラウザの印（Cookie）の SHA-256。
    pub browser_binding_hash: String,
    /// 認可の途中から来たなら、その AuthSession（の SHA-256）。
    pub auth_session_hash: Option<String>,
    /// 認可の途中から来たなら、その RP（表示と監査）。
    pub client_id: Option<String>,
    /// アプリが署名に入れる値（依頼ごと）。
    pub challenge: String,
    pub state: ApprovalState,
    pub ip_address: Option<String>,
    pub country: Option<String>,
    /// 承認した鍵と利用者（承認の後）。
    pub approver_key: Option<Uuid>,
    pub user_id: Option<Uuid>,
    /// 承認して返したコードの SHA-256 と期限。
    pub code_hash: Option<String>,
    pub code_expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl ApprovalRequest {
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }
}

/// 依頼を始めたブラウザに渡す印を作る（平文と SHA-256）。
pub fn new_browser_binding() -> (String, String) {
    let binding = random_value();
    let hash = crypto::sha256_hex(&binding);
    (binding, hash)
}

/// 取り消しの署名の時刻（`YYYY-MM-DDTHH:MM:SSZ`）が今から許容幅の中か。
pub fn signed_at_is_fresh(signed_at: &str, now: DateTime<Utc>) -> bool {
    let Ok(at) = DateTime::parse_from_rfc3339(signed_at) else {
        return false;
    };
    (now - at.with_timezone(&Utc)).num_seconds().abs() <= SIGNED_AT_TOLERANCE_SECS
}

/// 機種名を表示に使える形にする（前後の空白を落とし、制御文字を除き、長さを切る）。空なら `None`。
pub fn normalize_device_name(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_DEVICE_NAME_CHARS)
        .collect();
    (!cleaned.is_empty()).then_some(cleaned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn signed_message_names_the_action_tenant_target_and_nonce() {
        assert_eq!(
            signed_message(SignedAction::Approve, "t", "r", "c"),
            "assay-app-approver-v1\napprove\nt\nr\nc"
        );
        assert_ne!(
            signed_message(SignedAction::Approve, "t", "r", "c"),
            signed_message(SignedAction::Deny, "t", "r", "c")
        );
    }

    #[test]
    fn key_id_is_43_characters_of_base64url() {
        let id = key_id_of(b"spki");
        assert_eq!(id.len(), 43);
        assert!(id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
    }

    #[test]
    fn enrollment_challenge_is_32_bytes() {
        let now = Utc.with_ymd_and_hms(2026, 11, 4, 0, 0, 0).unwrap();
        let e = ApproverEnrollment::start(Uuid::nil(), now);
        assert_eq!(e.challenge_bytes().map(|b| b.len()), Some(32));
        assert!(!e.is_expired_at(now + Duration::seconds(599)));
        assert!(e.is_expired_at(now + Duration::seconds(600)));
    }

    #[test]
    fn signed_at_must_be_within_five_minutes() {
        let now = Utc.with_ymd_and_hms(2026, 11, 4, 12, 0, 0).unwrap();
        assert!(signed_at_is_fresh("2026-11-04T11:56:00Z", now));
        assert!(signed_at_is_fresh("2026-11-04T12:04:59Z", now));
        assert!(!signed_at_is_fresh("2026-11-04T11:54:59Z", now));
        assert!(!signed_at_is_fresh("yesterday", now));
    }

    #[test]
    fn device_names_are_trimmed_and_bounded() {
        assert_eq!(
            normalize_device_name("  Pixel 9\u{0007} "),
            Some("Pixel 9".to_string())
        );
        assert_eq!(normalize_device_name("   "), None);
        assert_eq!(
            normalize_device_name(&"x".repeat(100)).map(|n| n.chars().count()),
            Some(MAX_DEVICE_NAME_CHARS)
        );
    }

    #[test]
    fn states_round_trip() {
        for s in [
            ApprovalState::Pending,
            ApprovalState::Approved,
            ApprovalState::Denied,
            ApprovalState::Completed,
            ApprovalState::Refused,
        ] {
            assert_eq!(ApprovalState::parse(s.as_str()), Some(s));
        }
    }
}
