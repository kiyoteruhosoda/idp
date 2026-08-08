//! Step-up 認証（ユーザー認証・認証ポリシー仕様書 §15。AP5）。
//!
//! ログイン済みであることと、**今この操作をしてよいと確認できていること**は別物である。
//! セッションは既定 8 時間有効で、盗まれたセッションを持つ攻撃者は、その間ずっと「ログイン済み」
//! として振る舞える。パスワード変更・MFA 設定変更のような、成功すれば**アカウントを乗っ取れる**
//! 操作については、セッションの有無ではなく「直前に本人確認を通ったか」を条件にする。
//!
//! 判定材料は AP4 で SSO セッションに記録した認証コンテキスト（認証方式・強度・MFA 完了時刻）と、
//! step-up を通した時刻。評価は純粋関数（[`evaluate_step_up`]）で、DB・フレームワークに依存しない。

use crate::domain::sso_session::SsoSession;
use crate::domain::values::AuthenticationStrength;
use chrono::{DateTime, Duration, Utc};

/// Step-up を要求する重要操作（仕様 §15）。
///
/// 「成功するとアカウントの支配権が移る」操作を対象にする。閲覧系（セッション一覧・連携アプリ
/// 一覧）は含めない — 見えるだけでは支配権は移らず、全操作に再認証を課すと利用者が確認を
/// 読まずに通すようになる（保護の実効が落ちる）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensitiveOperation {
    /// パスワードの変更（現行パスワードの提示は別途要るが、それだけでは第二要素を跨げない）。
    ChangePassword,
    /// 認証器（TOTP・パスキー）の追加・削除。攻撃者が自分の認証器を足せば、以後は正規の
    /// 資格情報として振る舞えるため、最も強く守る必要がある。
    ManageAuthenticators,
    /// 外部 IdP との紐付け・解除（AP10）。紐付けは新しいログイン経路を作る操作にあたる。
    ManageExternalIdentities,
    /// ログイン中セッションの失効（他端末の締め出し）。
    RevokeSession,
}

impl SensitiveOperation {
    /// 監査ログ・API 契約で使う安定した文字列表現。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ChangePassword => "change_password",
            Self::ManageAuthenticators => "manage_authenticators",
            Self::ManageExternalIdentities => "manage_external_identities",
            Self::RevokeSession => "revoke_session",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "change_password" => Some(Self::ChangePassword),
            "manage_authenticators" => Some(Self::ManageAuthenticators),
            "manage_external_identities" => Some(Self::ManageExternalIdentities),
            "revoke_session" => Some(Self::RevokeSession),
            _ => None,
        }
    }

    /// この操作が「利用者が第二要素を持っているなら第二要素まで求める」ものか。
    ///
    /// 認証器の管理と外部 IdP の紐付けは、単一要素で通せると「パスワードを盗んだだけの攻撃者が
    /// MFA を外して（または自分の認証器を足して）以後を乗っ取る」経路になるため、必ず第二要素を要る
    /// ものとする。パスワード変更・セッション失効は現行パスワードの提示で足りる。
    pub fn requires_second_factor(&self) -> bool {
        matches!(
            self,
            Self::ManageAuthenticators | Self::ManageExternalIdentities
        )
    }
}

/// Step-up の要件。
#[derive(Debug, Clone, Copy)]
pub struct StepUpRequirement {
    /// 直近の本人確認からこの秒数を超えていたら再確認を求める（仕様 §18.2 と同じ考え方で、
    /// 対象が「セッション全体」ではなく「この操作の直前」である点だけが違う）。
    pub max_age_secs: u64,
    /// 求める認証強度。利用者が第二要素を持たない場合の扱いは Application 層が決める
    /// （持っていない人に多要素を求めても通せないため）。
    pub required_strength: AuthenticationStrength,
}

impl StepUpRequirement {
    /// 操作と「利用者が第二要素を登録しているか」から要件を決める。
    ///
    /// 第二要素を持たない利用者へ多要素を求めても操作が永久に通らないだけなので、単一要素の
    /// 再確認へ落とす（MFA を必須にしたい組織は認証ポリシーの `require_mfa` で入口を締める）。
    pub fn for_operation(
        operation: SensitiveOperation,
        max_age_secs: u64,
        user_has_second_factor: bool,
    ) -> Self {
        let required_strength = if operation.requires_second_factor() && user_has_second_factor {
            AuthenticationStrength::MultiFactor
        } else {
            AuthenticationStrength::SingleFactor
        };
        Self {
            max_age_secs,
            required_strength,
        }
    }
}

/// Step-up の判定結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepUpDecision {
    /// 直近の本人確認が要件を満たしている。そのまま操作してよい。
    Satisfied,
    /// 本人確認が古い。同じ強度で構わないので、もう一度確認する。
    ReauthenticationRequired,
    /// 強度が足りない（第二要素を通していない）。第二要素まで確認する。
    SecondFactorRequired,
}

/// 直近の本人確認時刻。`step_up_at` があればそれを、無ければログイン時刻（`auth_time`）を使う。
///
/// ログイン直後は step-up 済みとみなす（ログインそのものが本人確認であり、直後にもう一度
/// 同じことを求めるのは利用者にとって無意味な繰り返しになる）。
fn last_verified_at(session: &SsoSession, step_up_at: Option<DateTime<Utc>>) -> DateTime<Utc> {
    match step_up_at {
        Some(at) if at > session.auth_time => at,
        _ => session.auth_time,
    }
}

/// Step-up を評価する（仕様 §15）。
///
/// - 強度が足りなければ `SecondFactorRequired`（新しさに関わらず。古い単一要素の確認を
///   「新しいから」で通してしまわない）。
/// - 強度は足りるが古ければ `ReauthenticationRequired`。
/// - 多要素を要求する場合の「新しさ」は**第二要素の完了時刻**で測る。パスワードだけ入れ直しても
///   第二要素の鮮度は回復しないため。
pub fn evaluate_step_up(
    session: &SsoSession,
    step_up_at: Option<DateTime<Utc>>,
    requirement: StepUpRequirement,
    now: DateTime<Utc>,
) -> StepUpDecision {
    if !session
        .authentication_strength
        .satisfies(requirement.required_strength)
    {
        return StepUpDecision::SecondFactorRequired;
    }

    let max_age = Duration::seconds(requirement.max_age_secs as i64);
    let fresh = if requirement.required_strength == AuthenticationStrength::MultiFactor {
        // 第二要素の鮮度で測る。step-up で第二要素を通し直した場合は `mfa_completed_at` も
        // 更新されるため、この 1 本で「ログイン時の MFA」と「step-up の MFA」の両方を見られる。
        session
            .mfa_completed_at
            .is_some_and(|at| now - at <= max_age)
    } else {
        now - last_verified_at(session, step_up_at) <= max_age
    };

    if fresh {
        StepUpDecision::Satisfied
    } else {
        StepUpDecision::ReauthenticationRequired
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::values::AuthenticationMethod;
    use chrono::TimeZone;
    use uuid::Uuid;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap()
    }

    fn session(methods: Vec<AuthenticationMethod>, auth_time: DateTime<Utc>) -> SsoSession {
        let mut s = SsoSession::establish(
            "hash".to_string(),
            Uuid::from_u128(1),
            auth_time,
            Duration::hours(1),
            Duration::hours(8),
            methods,
            None,
            None,
        );
        s.idle_expires_at = now() + Duration::hours(1);
        s.absolute_expires_at = now() + Duration::hours(8);
        s
    }

    fn single_factor(max_age_secs: u64) -> StepUpRequirement {
        StepUpRequirement {
            max_age_secs,
            required_strength: AuthenticationStrength::SingleFactor,
        }
    }

    fn multi_factor(max_age_secs: u64) -> StepUpRequirement {
        StepUpRequirement {
            max_age_secs,
            required_strength: AuthenticationStrength::MultiFactor,
        }
    }

    /// ログイン直後は step-up 済みとみなす（同じことをもう一度求めない）。
    #[test]
    fn a_fresh_login_satisfies_step_up() {
        let s = session(vec![AuthenticationMethod::Password], now());
        assert_eq!(
            evaluate_step_up(&s, None, single_factor(300), now()),
            StepUpDecision::Satisfied
        );
    }

    #[test]
    fn an_old_login_requires_reauthentication() {
        let s = session(
            vec![AuthenticationMethod::Password],
            now() - Duration::seconds(301),
        );
        assert_eq!(
            evaluate_step_up(&s, None, single_factor(300), now()),
            StepUpDecision::ReauthenticationRequired
        );
    }

    /// step-up を通した時刻が新しければ、ログインが古くても満たす。
    #[test]
    fn a_recent_step_up_refreshes_an_old_login() {
        let s = session(
            vec![AuthenticationMethod::Password],
            now() - Duration::hours(4),
        );
        assert_eq!(
            evaluate_step_up(
                &s,
                Some(now() - Duration::seconds(60)),
                single_factor(300),
                now()
            ),
            StepUpDecision::Satisfied
        );
    }

    /// 単一要素のセッションは、どれだけ新しくても多要素の要件を満たさない。
    #[test]
    fn a_single_factor_session_never_satisfies_a_multi_factor_requirement() {
        let s = session(vec![AuthenticationMethod::Password], now());
        assert_eq!(
            evaluate_step_up(&s, Some(now()), multi_factor(300), now()),
            StepUpDecision::SecondFactorRequired
        );
    }

    /// 多要素の要件では、パスワードだけの step-up では鮮度が回復しない
    /// （`mfa_completed_at` で測るため）。
    #[test]
    fn multi_factor_freshness_is_measured_from_the_second_factor() {
        let mut s = session(
            vec![AuthenticationMethod::Password, AuthenticationMethod::Totp],
            now() - Duration::hours(4),
        );
        s.mfa_completed_at = Some(now() - Duration::hours(4));
        // パスワードだけ入れ直した（step_up_at は新しい）が、第二要素は 4 時間前のまま。
        assert_eq!(
            evaluate_step_up(&s, Some(now()), multi_factor(300), now()),
            StepUpDecision::ReauthenticationRequired
        );
        // 第二要素まで通し直せば満たす。
        s.mfa_completed_at = Some(now() - Duration::seconds(10));
        assert_eq!(
            evaluate_step_up(&s, Some(now()), multi_factor(300), now()),
            StepUpDecision::Satisfied
        );
    }

    /// 第二要素を持たない利用者には多要素を求めない（求めても永久に通らないため）。
    #[test]
    fn requirement_falls_back_to_single_factor_without_an_enrolled_authenticator() {
        let with =
            StepUpRequirement::for_operation(SensitiveOperation::ManageAuthenticators, 300, true);
        assert_eq!(with.required_strength, AuthenticationStrength::MultiFactor);
        let without =
            StepUpRequirement::for_operation(SensitiveOperation::ManageAuthenticators, 300, false);
        assert_eq!(
            without.required_strength,
            AuthenticationStrength::SingleFactor
        );
        // 第二要素を要求しない操作は、認証器を持っていても単一要素で足りる。
        let password =
            StepUpRequirement::for_operation(SensitiveOperation::ChangePassword, 300, true);
        assert_eq!(
            password.required_strength,
            AuthenticationStrength::SingleFactor
        );
    }

    #[test]
    fn operation_round_trips_through_str() {
        for op in [
            SensitiveOperation::ChangePassword,
            SensitiveOperation::ManageAuthenticators,
            SensitiveOperation::ManageExternalIdentities,
            SensitiveOperation::RevokeSession,
        ] {
            assert_eq!(SensitiveOperation::parse(op.as_str()), Some(op));
        }
        assert_eq!(SensitiveOperation::parse("delete_everything"), None);
    }
}
