//! SsoSessions エンティティ（設計仕様 §3.4）。
//! Cookie には `session_id`、DB には `session_hash = SHA-256(session_id)` のみ保存する。
//!
//! セッションは「いつ・どの認証方式で・どの強度で本人確認したか」も保持する
//! （ユーザー認証・認証ポリシー仕様書 §14.3・§18.1）。この記録が、MFA 経過時間による再認証
//! （§18.2 `max_authentication_age`）と Step-up 認証（§15）の唯一の判定材料になる。
#![allow(dead_code)]

use crate::domain::crypto;
use crate::domain::values::{AuthenticationMethod, AuthenticationStrength};
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct SsoSession {
    pub session_hash: String,
    pub user_id: Uuid,
    /// 初回ログイン時刻。SSO 復元時も ID Token の `auth_time` にコピーする（設計仕様 §5.1）。
    pub auth_time: DateTime<Utc>,
    pub idle_expires_at: DateTime<Utc>,
    pub absolute_expires_at: DateTime<Utc>,
    /// 本セッションを確立するために実際に検証された認証方式（仕様 §14.3）。順序は検証順。
    pub authentication_methods: Vec<AuthenticationMethod>,
    /// 認証強度（`authentication_methods` からの導出値。保存もして判定を 1 往復で済ませる）。
    pub authentication_strength: AuthenticationStrength,
    /// 第二要素の検証が完了した時刻（未完了なら `None`）。MFA 経過時間による再認証（§18.2）と
    /// Step-up（§15）はこの時刻を基準にする（`auth_time` ではない。パスワードだけ入れ直しても
    /// MFA の鮮度は回復しない）。
    pub mfa_completed_at: Option<DateTime<Utc>>,
    /// 重要操作の直前に本人確認（step-up）を通した時刻（AP5。仕様 §15）。`auth_time` は SSO の
    /// 起点で復元では動かないため、「今この操作をしてよいか」の新しさは別に測る。
    pub step_up_at: Option<DateTime<Utc>>,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SsoSession {
    /// ログイン成功時に新しい SSO セッションを組み立てる。
    ///
    /// 強度と `mfa_completed_at` は `methods` から導出する（呼び出し側に渡させない）。ログイン経路は
    /// 5 つ（OIDC・MFA・パスキー・ポータル・管理コンソール）あり、そのどれかが強度の計算を間違えると
    /// Step-up・再認証の判定が丸ごと狂うため、導出はここ 1 箇所に閉じる。
    #[allow(clippy::too_many_arguments)]
    pub fn establish(
        session_hash: String,
        user_id: Uuid,
        now: DateTime<Utc>,
        idle_ttl: Duration,
        absolute_ttl: Duration,
        methods: Vec<AuthenticationMethod>,
        user_agent: Option<String>,
        ip_address: Option<String>,
    ) -> Self {
        let strength = AuthenticationStrength::from_methods(&methods);
        Self {
            session_hash,
            user_id,
            auth_time: now,
            idle_expires_at: now + idle_ttl,
            absolute_expires_at: now + absolute_ttl,
            authentication_methods: methods,
            authentication_strength: strength,
            // 第二要素は「たった今」検証されている（ログイン経路以外からは establish しない）。
            mfa_completed_at: (strength == AuthenticationStrength::MultiFactor).then_some(now),
            // ログインそのものが本人確認なので、確立直後は step-up 済みとして扱う。
            step_up_at: Some(now),
            user_agent,
            ip_address,
            created_at: now,
            updated_at: now,
        }
    }

    /// 指定時刻時点で有効か（idle・absolute の双方が未超過）。
    pub fn is_valid_at(&self, now: DateTime<Utc>) -> bool {
        self.idle_expires_at > now && self.absolute_expires_at > now
    }

    /// 第二要素まで完了しているか（仕様 §14.3）。
    pub fn is_multi_factor(&self) -> bool {
        self.authentication_strength == AuthenticationStrength::MultiFactor
    }

    /// 指定方式で本人確認済みか。
    pub fn used_method(&self, method: AuthenticationMethod) -> bool {
        self.authentication_methods.contains(&method)
    }

    /// `max_age`（秒）を満たすか（OIDC Core §3.1.2.1 の `max_age` / 仕様 §18.2）。
    /// 満たさない場合は再認証（`prompt=login` 相当）が要る。
    pub fn satisfies_max_age(&self, max_age_secs: u64, now: DateTime<Utc>) -> bool {
        now - self.auth_time <= Duration::seconds(max_age_secs as i64)
    }

    /// MFA の完了からの経過時間が `max_age_secs` 以内か（仕様 §18.2）。
    /// MFA 未完了のセッションは常に満たさない（`false`）。
    pub fn satisfies_mfa_age(&self, max_age_secs: u64, now: DateTime<Utc>) -> bool {
        self.mfa_completed_at
            .is_some_and(|at| now - at <= Duration::seconds(max_age_secs as i64))
    }

    /// 画面に提示できるセッション識別子（セルフサービスのセッション一覧・失効。G10）。
    ///
    /// `session_hash` は Cookie の生値ではないため提示しても認証には使えないが、DB 上の主キーを
    /// そのまま画面へ出す必要も無い。ドメイン分離した非可逆の導出値を返し、照合は当人のセッション
    /// 集合に対する走査で行う（値から `session_hash` を復元する経路を作らない）。
    pub fn display_id(&self) -> String {
        display_id_of(&self.session_hash)
    }

    /// back-channel / front-channel logout と ID Token が共有するセッション識別子 `sid`
    /// （OpenID Connect Back-Channel Logout 1.0 §2.1。G5）。
    ///
    /// RP はこの値でセッション単位のログアウトを実施する。`session_hash` から非可逆に導出するため
    /// 追加のカラムは要らず、RP へ渡っても SSO セッションの乗っ取りには使えない。
    pub fn sid(&self) -> String {
        sid_of(&self.session_hash)
    }
}

/// `session_hash` から表示用 ID を導出する（[`SsoSession::display_id`] の実体）。
pub fn display_id_of(session_hash: &str) -> String {
    crypto::sha256_hex(&format!("sso-session-display:{session_hash}"))[..32].to_string()
}

/// `session_hash` から `sid` を導出する（[`SsoSession::sid`] の実体）。
///
/// ログアウト時は SSO セッション行を削除してから logout_token を組み立てるため、行が消えた後でも
/// `session_hash` さえあれば同じ `sid` を再現できる必要がある。そのため導出は関数として公開する。
pub fn sid_of(session_hash: &str) -> String {
    crypto::sha256_hex(&format!("sso-session-sid:{session_hash}"))[..32].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap()
    }

    fn session(
        methods: Vec<AuthenticationMethod>,
        mfa_completed_at: Option<DateTime<Utc>>,
    ) -> SsoSession {
        SsoSession {
            session_hash: "a".repeat(64),
            user_id: Uuid::from_u128(1),
            auth_time: now(),
            idle_expires_at: now() + Duration::hours(1),
            absolute_expires_at: now() + Duration::hours(8),
            authentication_strength: AuthenticationStrength::from_methods(&methods),
            authentication_methods: methods,
            mfa_completed_at,
            step_up_at: Some(now()),
            user_agent: None,
            ip_address: None,
            created_at: now(),
            updated_at: now(),
        }
    }

    #[test]
    fn strength_follows_the_recorded_methods() {
        assert!(!session(vec![AuthenticationMethod::Password], None).is_multi_factor());
        assert!(session(
            vec![AuthenticationMethod::Password, AuthenticationMethod::Totp],
            Some(now())
        )
        .is_multi_factor());
    }

    #[test]
    fn max_age_is_measured_from_auth_time() {
        let s = session(vec![AuthenticationMethod::Password], None);
        assert!(s.satisfies_max_age(300, now() + Duration::seconds(300)));
        assert!(!s.satisfies_max_age(300, now() + Duration::seconds(301)));
    }

    /// MFA 未完了のセッションは MFA 経過時間の要件を満たさない（パスワードだけでは回復しない）。
    #[test]
    fn mfa_age_requires_a_completed_second_factor() {
        let password_only = session(vec![AuthenticationMethod::Password], None);
        assert!(!password_only.satisfies_mfa_age(300, now()));

        let mfa = session(
            vec![AuthenticationMethod::Password, AuthenticationMethod::Totp],
            Some(now()),
        );
        assert!(mfa.satisfies_mfa_age(300, now() + Duration::seconds(300)));
        assert!(!mfa.satisfies_mfa_age(300, now() + Duration::seconds(301)));
    }

    /// 表示用 ID・`sid` はセッション毎に異なり、`session_hash` をそのまま漏らさない。
    #[test]
    fn derived_identifiers_are_stable_and_do_not_leak_the_hash() {
        let s = session(vec![AuthenticationMethod::Password], None);
        assert_eq!(s.display_id(), s.display_id());
        assert_eq!(s.sid(), sid_of(&s.session_hash));
        assert_ne!(s.display_id(), s.sid());
        assert!(!s.session_hash.contains(&s.display_id()));
        assert!(!s.session_hash.contains(&s.sid()));

        let mut other = s.clone();
        other.session_hash = "b".repeat(64);
        assert_ne!(s.display_id(), other.display_id());
        assert_ne!(s.sid(), other.sid());
    }
}
