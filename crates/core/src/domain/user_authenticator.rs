//! 認証器の統合管理（AP9。ユーザー認証・認証ポリシー仕様書 §5）。
//!
//! 種別（TOTP・WebAuthn・リカバリーコード・email OTP）によらない**登録簿**の 1 行を表す。
//! 「この利用者が今使える認証器はどれか」を 1 箇所で答えられるようにするためのもので、
//! 種別固有の秘密（TOTP のシークレット・WebAuthn の passkey）は従来のテーブルが持ち続ける
//! （expand フェーズ。移送はしない。理由は migration 0023 のコメント）。
//!
//! 状態遷移（§5.3）:
//!
//! ```text
//!   pending ──confirm──► active ──suspend──► suspended ──resume──► active
//!      │                   │                     │
//!      └──────revoke───────┴─────────revoke──────┴──────────────► revoked（終端）
//! ```
//!
//! `suspended` があるのは、**端末を失くしたが手元に戻るかもしれない**という現実の状況に、
//! 削除以外の答えを用意するため。削除しかないと、戻ってきても登録し直しになる。
#![allow(dead_code)]

use crate::domain::values::{string_enum, AuthenticationMethod};
use chrono::{DateTime, Utc};
use uuid::Uuid;

string_enum!(
    /// 認証器の種別（仕様 §5.1）。
    ///
    /// `SmsOtp` は本 IdP が送信手段（SMS ゲートウェイ）を持たないため**発行経路が無い**。
    /// 値だけ用意してあるのは、後から送信手段を足したときに DB の CHECK 制約と Rust 側 enum を
    /// 同時に変えずに済ませるため（既存行の互換を壊さない）。
    AuthenticatorType {
        Totp => "totp",
        WebAuthn => "webauthn",
        RecoveryCode => "recovery_code",
        EmailOtp => "email_otp",
        SmsOtp => "sms_otp",
    }
);

impl AuthenticatorType {
    /// この認証器で本人確認したときに記録する認証方式（AP4）。
    pub fn authentication_method(&self) -> AuthenticationMethod {
        match self {
            Self::Totp => AuthenticationMethod::Totp,
            Self::WebAuthn => AuthenticationMethod::WebAuthn,
            Self::RecoveryCode => AuthenticationMethod::RecoveryCode,
            Self::EmailOtp => AuthenticationMethod::EmailOtp,
            Self::SmsOtp => AuthenticationMethod::SmsOtp,
        }
    }

    /// 1 利用者につき複数登録できる種別か。
    ///
    /// TOTP は既存テーブルが `user_id` を主キーに持つため 1 本まで。WebAuthn は端末ごとに
    /// 登録するので複数。リカバリーコードは 1 コード 1 行で複数（束で発行する）。
    pub fn allows_multiple(&self) -> bool {
        !matches!(self, Self::Totp)
    }

    /// 使い捨て（1 回使ったら失効する）か。
    pub fn is_single_use(&self) -> bool {
        matches!(self, Self::RecoveryCode | Self::EmailOtp | Self::SmsOtp)
    }
}

string_enum!(
    /// 認証器の状態（仕様 §5.3）。
    AuthenticatorStatus {
        /// 登録手続きの途中（TOTP の QR を出したが確認コード未入力、など）。認証には使えない。
        Pending => "pending",
        /// 有効。認証に使える。
        Active => "active",
        /// 一時停止。行は残すが認証には使えない（端末紛失時の暫定措置）。`Active` へ戻せる。
        Suspended => "suspended",
        /// 失効（終端）。以後どの状態にも戻さない。
        Revoked => "revoked",
    }
);

impl AuthenticatorStatus {
    /// 認証に使えるか。
    pub fn is_usable(&self) -> bool {
        *self == Self::Active
    }

    /// 終端状態か（これ以上遷移しない）。
    pub fn is_terminal(&self) -> bool {
        *self == Self::Revoked
    }

    /// `self` から `next` への遷移が許されるか（仕様 §5.3）。
    ///
    /// 失効は終端。`Revoked` から戻す遷移を許すと、「失効させた認証器が復活する」経路ができる
    /// （管理者が誤って戻すことも、実装のバグで戻ることも防げなくなる）。
    pub fn can_transition_to(&self, next: Self) -> bool {
        use AuthenticatorStatus::*;
        match (self, next) {
            // 同じ状態への遷移は冪等な操作として許す（二重クリック・再送）。失効済みへの再失効も
            // ここで通す（先に `(Revoked, _) => false` を置くと、冪等なはずの再失効まで弾かれる）。
            (a, b) if *a == b => true,
            (Revoked, _) => false,
            (_, Revoked) => true,
            (Pending, Active) => true,
            (Active, Suspended) => true,
            (Suspended, Active) => true,
            _ => false,
        }
    }
}

/// 認証器の登録簿 1 行。
#[derive(Debug, Clone)]
pub struct UserAuthenticator {
    pub id: Uuid,
    pub user_id: Uuid,
    pub authenticator_type: AuthenticatorType,
    pub status: AuthenticatorStatus,
    /// 利用者が付ける表示名（未設定は空文字）。
    pub label: String,
    /// 種別固有の秘密。リカバリーコード・email OTP のみ（いずれも SHA-256）。
    pub secret_encrypted: Option<String>,
    /// WebAuthn クレデンシャルへの参照（`user_webauthn_credentials.id`）。
    pub credential_ref: Option<Uuid>,
    /// email OTP の送信先。
    pub target: Option<String>,
    pub confirmed_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    /// この認証器（コード）の有効期限。無期限なら `None`。
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl UserAuthenticator {
    /// 指定時刻に認証へ使えるか（状態が `Active` かつ期限内）。
    pub fn is_usable_at(&self, now: DateTime<Utc>) -> bool {
        self.status.is_usable() && self.expires_at.is_none_or(|exp| exp > now)
    }

    /// 第二要素として数えられるか（AP4 の強度導出と同じ基準）。
    pub fn counts_as_second_factor(&self) -> bool {
        self.authenticator_type
            .authentication_method()
            .is_second_factor()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone};

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap()
    }

    fn authenticator(
        authenticator_type: AuthenticatorType,
        status: AuthenticatorStatus,
        expires_at: Option<DateTime<Utc>>,
    ) -> UserAuthenticator {
        UserAuthenticator {
            id: Uuid::from_u128(1),
            user_id: Uuid::from_u128(2),
            authenticator_type,
            status,
            label: String::new(),
            secret_encrypted: None,
            credential_ref: None,
            target: None,
            confirmed_at: Some(now()),
            last_used_at: None,
            expires_at,
            revoked_at: None,
            created_at: now(),
            updated_at: now(),
        }
    }

    #[test]
    fn only_active_and_unexpired_authenticators_are_usable() {
        use AuthenticatorStatus::*;
        assert!(authenticator(AuthenticatorType::Totp, Active, None).is_usable_at(now()));
        for status in [Pending, Suspended, Revoked] {
            assert!(
                !authenticator(AuthenticatorType::Totp, status, None).is_usable_at(now()),
                "{status} must not be usable"
            );
        }
        // 期限切れの使い捨てコードは Active でも使えない。
        assert!(!authenticator(
            AuthenticatorType::EmailOtp,
            Active,
            Some(now() - Duration::seconds(1))
        )
        .is_usable_at(now()));
        assert!(authenticator(
            AuthenticatorType::EmailOtp,
            Active,
            Some(now() + Duration::seconds(1))
        )
        .is_usable_at(now()));
    }

    /// 失効は終端。戻す遷移は一切許さない。
    #[test]
    fn revoked_is_terminal() {
        use AuthenticatorStatus::*;
        for next in [Pending, Active, Suspended] {
            assert!(!Revoked.can_transition_to(next), "revoked -> {next}");
        }
        // 冪等な revoke は許す。
        assert!(Revoked.can_transition_to(Revoked));
    }

    #[test]
    fn suspension_is_reversible_but_pending_cannot_be_suspended() {
        use AuthenticatorStatus::*;
        assert!(Active.can_transition_to(Suspended));
        assert!(Suspended.can_transition_to(Active));
        // 確認前の認証器を「一時停止」する意味は無い（使えない状態が 2 つできるだけ）。
        assert!(!Pending.can_transition_to(Suspended));
        // どの状態からでも失効はできる。
        for from in [Pending, Active, Suspended] {
            assert!(from.can_transition_to(Revoked));
        }
    }

    #[test]
    fn types_map_to_the_authentication_method_recorded_on_the_session() {
        assert_eq!(
            AuthenticatorType::Totp.authentication_method(),
            AuthenticationMethod::Totp
        );
        assert_eq!(
            AuthenticatorType::RecoveryCode.authentication_method(),
            AuthenticationMethod::RecoveryCode
        );
        // すべての種別が第二要素として数えられる（知識要素はパスワードのみ）。
        for t in [
            AuthenticatorType::Totp,
            AuthenticatorType::WebAuthn,
            AuthenticatorType::RecoveryCode,
            AuthenticatorType::EmailOtp,
            AuthenticatorType::SmsOtp,
        ] {
            assert!(t.authentication_method().is_second_factor(), "{t}");
        }
    }

    #[test]
    fn totp_is_the_only_single_registration_type() {
        assert!(!AuthenticatorType::Totp.allows_multiple());
        for t in [
            AuthenticatorType::WebAuthn,
            AuthenticatorType::RecoveryCode,
            AuthenticatorType::EmailOtp,
        ] {
            assert!(t.allows_multiple(), "{t}");
        }
    }

    #[test]
    fn single_use_types_are_the_code_based_ones() {
        assert!(AuthenticatorType::RecoveryCode.is_single_use());
        assert!(AuthenticatorType::EmailOtp.is_single_use());
        assert!(!AuthenticatorType::Totp.is_single_use());
        assert!(!AuthenticatorType::WebAuthn.is_single_use());
    }
}
