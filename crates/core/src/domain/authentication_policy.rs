//! 認証ポリシー（ユーザー認証・認証ポリシー仕様書 §7〜§9）。
//!
//! 認証ポリシーは「認証時に満たすべき条件（拒否・MFA 必須）」を決定する規則であり、
//! 本人確認（パスワード・TOTP 等の認証器）とは分離する（同仕様 §2.3）。ポリシーを満たしても
//! 本人確認に成功していなければ認証成功にはならない。評価は純粋関数（[`evaluate_policies`]）で、
//! DB・フレームワークに依存しない。
#![allow(dead_code)]

use crate::domain::error::DomainError;
use crate::domain::tenant::TenantId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// ポリシーの効果（仕様 §7.4 のサブセット）。
///
/// `require_additional_authentication` は現行の追加認証手段が TOTP のみのため `RequireMfa` として
/// 表現する。`require_specific_method` は認証方式が増えた段階で追加する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyEffect {
    /// 条件を満たした場合に認証を許可する。
    Allow,
    /// 条件を満たした場合に認証を拒否する（拒否は常に許可より優先。仕様 §9.3）。
    Deny,
    /// 条件を満たした場合に MFA（追加認証）を必須とする。
    RequireMfa,
}

impl PolicyEffect {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::RequireMfa => "require_mfa",
        }
    }

    /// DB 保存値（`VARCHAR` + CHECK 制約）から復元する。許可値の単一の出所は本 enum。
    pub fn parse(s: &str) -> Result<Self, DomainError> {
        match s {
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            "require_mfa" => Ok(Self::RequireMfa),
            other => Err(DomainError::InvalidValue(format!(
                "unknown policy effect: {other}"
            ))),
        }
    }
}

/// ポリシーの適用条件（仕様 §8。JSON カラムに保存する）。
///
/// 各条件は **空 = 制限しない（全てに一致）**、非空 = いずれかに一致で成立。複数の条件は AND。
/// ユーザー特定前に評価できる条件（`client_ids`）とユーザー特定後にのみ評価できる条件
/// （`user_ids`）が混在するため、評価はユーザー特定後に行う（仕様 §9.1）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConditions {
    /// 対象クライアント（OAuth/OIDC の `client_id`）。空 = 全クライアント。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub client_ids: Vec<String>,
    /// 対象ユーザー（内部ユーザー ID）。空 = 全ユーザー。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub user_ids: Vec<Uuid>,
}

impl PolicyConditions {
    /// 認証コンテキストに一致するか（空の条件は常に一致）。
    pub fn matches(&self, ctx: &AuthenticationContext) -> bool {
        let client_ok = self.client_ids.is_empty()
            || ctx
                .client_id
                .is_some_and(|c| self.client_ids.iter().any(|allowed| allowed == c));
        let user_ok = self.user_ids.is_empty() || self.user_ids.contains(&ctx.user_id);
        client_ok && user_ok
    }
}

/// ポリシー評価の入力（認証コンテキスト。仕様 §9.1「ユーザー特定後」時点の情報）。
#[derive(Debug, Clone, Copy)]
pub struct AuthenticationContext<'a> {
    /// フローのクライアント（ポータルログイン等、クライアント非依存の経路では `None`）。
    pub client_id: Option<&'a str>,
    /// 特定済みユーザーの内部 ID。
    pub user_id: Uuid,
}

/// 認証ポリシー 1 件（`authentication_policies` テーブル。仕様 §7.3 のサブセット）。
#[derive(Debug, Clone)]
pub struct AuthenticationPolicy {
    pub id: Uuid,
    /// ポリシーはテナント単位で管理する（テナント越しに適用されない）。
    pub tenant_id: TenantId,
    /// テナント内一意の識別コード（例: `deny-legacy-client`）。
    pub policy_code: String,
    pub policy_name: String,
    /// 評価順（昇順 = 小さいほど優先。仕様 §9.2）。
    pub priority: i32,
    pub enabled: bool,
    pub effect: PolicyEffect,
    pub conditions: PolicyConditions,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl AuthenticationPolicy {
    /// `policy_code` の形式検証（英数字・`-`・`_`・`.`、1〜100 文字）。
    /// URL パスセグメント・監査ログにそのまま載せられる安全な文字に限定する。
    pub fn validate_code(code: &str) -> Result<(), DomainError> {
        if code.is_empty() || code.len() > 100 {
            return Err(DomainError::InvalidValue(
                "policy code must be 1-100 characters".to_string(),
            ));
        }
        if !code
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
        {
            return Err(DomainError::InvalidValue(
                "policy code must contain only ASCII alphanumerics, '-', '_' or '.'".to_string(),
            ));
        }
        Ok(())
    }

    /// `policy_name` の検証（空でない・200 文字以内）。
    pub fn validate_name(name: &str) -> Result<(), DomainError> {
        if name.trim().is_empty() || name.chars().count() > 200 {
            return Err(DomainError::InvalidValue(
                "policy name must be 1-200 characters".to_string(),
            ));
        }
        Ok(())
    }
}

/// ポリシー評価の結論。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// 認証を継続してよい（`matched_policy_code` = 一致した許可ポリシー。既定許可なら `None`）。
    Allow { matched_policy_code: Option<String> },
    /// 認証を拒否する（仕様 §9.3: 拒否は他の全てに優先する）。
    Deny { policy_code: String },
    /// MFA（追加認証）を完了しなければ認証成功にしない。
    RequireMfa { policy_code: String },
}

/// 一致するポリシーが 1 件も無いときの既定動作（仕様 §9.4「明示的に設定する」）。
///
/// 既定は `Allow`（ポリシー未設定の既存環境の挙動を変えない）。デフォルト拒否へ倒す場合は
/// 設定（`AUTH_POLICY_DEFAULT_EFFECT`）で `deny` を指定する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultPolicyEffect {
    Allow,
    Deny,
}

impl DefaultPolicyEffect {
    pub fn parse(s: &str) -> Result<Self, DomainError> {
        match s {
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            other => Err(DomainError::InvalidValue(format!(
                "unknown default policy effect: {other}"
            ))),
        }
    }
}

/// アカウントロックのポリシー（仕様 §17。失敗許容回数・ロック時間）。
///
/// 従来は各ログインサービスにハードコードされていた値（10 回 / 15 分）を、設定
/// （`LOGIN_MAX_FAILED_ATTEMPTS` / `LOGIN_LOCK_DURATION_SECS`）から注入する単一の値表現に集約する。
/// ロックはユーザー単位（仕様 §17.2）。恒久ロックは避ける（期限付きロックのみ）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockoutPolicy {
    /// 連続失敗の許容回数（この回数に達したらロック）。
    pub max_failed_attempts: i32,
    /// ロック時間（秒）。
    pub lock_duration_secs: u64,
}

impl LockoutPolicy {
    /// 失敗カウントが `failed_count` に達した時点でロックすべきなら、ロック期限を返す。
    pub fn locked_until_after_failure(
        &self,
        failed_count: i32,
        now: DateTime<Utc>,
    ) -> Option<DateTime<Utc>> {
        (failed_count >= self.max_failed_attempts)
            .then(|| now + chrono::Duration::seconds(self.lock_duration_secs as i64))
    }
}

/// 認証ポリシーを評価する（仕様 §9）。
///
/// - 対象は `enabled` かつ条件一致のポリシーのみ。
/// - `Deny` が 1 件でも一致したら**常に**拒否（優先順位に関わらず。仕様 §9.3「拒否優先」）。
/// - 次いで `RequireMfa` が一致していれば MFA を要求する（許可ポリシーと同時一致でも MFA 優先）。
/// - 残りは `Allow`。最優先（priority 最小、同値は `policy_code` 昇順で安定）の一致を記録する。
/// - 1 件も一致しなければ `default_effect` に従う（既定拒否時の `policy_code` は固定値
///   `(default)` として監査に残す）。
pub fn evaluate_policies(
    policies: &[AuthenticationPolicy],
    ctx: &AuthenticationContext<'_>,
    default_effect: DefaultPolicyEffect,
) -> PolicyDecision {
    let mut matched: Vec<&AuthenticationPolicy> = policies
        .iter()
        .filter(|p| p.enabled && p.conditions.matches(ctx))
        .collect();
    // 優先順位の昇順（同値は policy_code 昇順で決定的に）。
    matched.sort_by(|a, b| {
        a.priority
            .cmp(&b.priority)
            .then_with(|| a.policy_code.cmp(&b.policy_code))
    });

    if let Some(deny) = matched.iter().find(|p| p.effect == PolicyEffect::Deny) {
        return PolicyDecision::Deny {
            policy_code: deny.policy_code.clone(),
        };
    }
    if let Some(mfa) = matched
        .iter()
        .find(|p| p.effect == PolicyEffect::RequireMfa)
    {
        return PolicyDecision::RequireMfa {
            policy_code: mfa.policy_code.clone(),
        };
    }
    if let Some(allow) = matched.iter().find(|p| p.effect == PolicyEffect::Allow) {
        return PolicyDecision::Allow {
            matched_policy_code: Some(allow.policy_code.clone()),
        };
    }
    match default_effect {
        DefaultPolicyEffect::Allow => PolicyDecision::Allow {
            matched_policy_code: None,
        },
        DefaultPolicyEffect::Deny => PolicyDecision::Deny {
            policy_code: "(default)".to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn fixed_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0).unwrap()
    }

    fn tenant() -> TenantId {
        TenantId::from(Uuid::from_u128(0x0197_0000_0000_7000_8000_0000_0000_0001))
    }

    fn policy(
        code: &str,
        priority: i32,
        effect: PolicyEffect,
        conditions: PolicyConditions,
    ) -> AuthenticationPolicy {
        AuthenticationPolicy {
            id: Uuid::new_v4(),
            tenant_id: tenant(),
            policy_code: code.to_string(),
            policy_name: code.to_string(),
            priority,
            enabled: true,
            effect,
            conditions,
            created_at: fixed_now(),
            updated_at: fixed_now(),
        }
    }

    fn ctx(user_id: Uuid, client_id: Option<&str>) -> AuthenticationContext<'_> {
        AuthenticationContext { client_id, user_id }
    }

    #[test]
    fn no_policies_falls_back_to_default_effect() {
        let user = Uuid::new_v4();
        assert_eq!(
            evaluate_policies(&[], &ctx(user, None), DefaultPolicyEffect::Allow),
            PolicyDecision::Allow {
                matched_policy_code: None
            }
        );
        assert_eq!(
            evaluate_policies(&[], &ctx(user, None), DefaultPolicyEffect::Deny),
            PolicyDecision::Deny {
                policy_code: "(default)".to_string()
            }
        );
    }

    #[test]
    fn empty_conditions_match_everything() {
        let user = Uuid::new_v4();
        let p = policy(
            "all",
            100,
            PolicyEffect::RequireMfa,
            PolicyConditions::default(),
        );
        assert_eq!(
            evaluate_policies(&[p], &ctx(user, Some("app")), DefaultPolicyEffect::Allow),
            PolicyDecision::RequireMfa {
                policy_code: "all".to_string()
            }
        );
    }

    /// 仕様 §9.3: 拒否は許可・MFA より常に優先する（優先順位の値に関わらず）。
    #[test]
    fn deny_wins_over_allow_and_mfa_regardless_of_priority() {
        let user = Uuid::new_v4();
        let policies = vec![
            policy(
                "allow-any",
                1,
                PolicyEffect::Allow,
                PolicyConditions::default(),
            ),
            policy(
                "mfa-any",
                2,
                PolicyEffect::RequireMfa,
                PolicyConditions::default(),
            ),
            policy(
                "deny-any",
                999,
                PolicyEffect::Deny,
                PolicyConditions::default(),
            ),
        ];
        assert_eq!(
            evaluate_policies(&policies, &ctx(user, None), DefaultPolicyEffect::Allow),
            PolicyDecision::Deny {
                policy_code: "deny-any".to_string()
            }
        );
    }

    /// 仕様 §9.3: 追加認証（MFA）ポリシーは通常許可より優先する。
    #[test]
    fn require_mfa_wins_over_allow() {
        let user = Uuid::new_v4();
        let policies = vec![
            policy(
                "allow-any",
                1,
                PolicyEffect::Allow,
                PolicyConditions::default(),
            ),
            policy(
                "mfa-any",
                100,
                PolicyEffect::RequireMfa,
                PolicyConditions::default(),
            ),
        ];
        assert_eq!(
            evaluate_policies(&policies, &ctx(user, None), DefaultPolicyEffect::Allow),
            PolicyDecision::RequireMfa {
                policy_code: "mfa-any".to_string()
            }
        );
    }

    #[test]
    fn disabled_policies_are_ignored() {
        let user = Uuid::new_v4();
        let mut p = policy(
            "deny-any",
            1,
            PolicyEffect::Deny,
            PolicyConditions::default(),
        );
        p.enabled = false;
        assert_eq!(
            evaluate_policies(&[p], &ctx(user, None), DefaultPolicyEffect::Allow),
            PolicyDecision::Allow {
                matched_policy_code: None
            }
        );
    }

    #[test]
    fn client_condition_limits_scope() {
        let user = Uuid::new_v4();
        let p = policy(
            "deny-legacy",
            1,
            PolicyEffect::Deny,
            PolicyConditions {
                client_ids: vec!["legacy-app".to_string()],
                user_ids: vec![],
            },
        );
        // 対象クライアントのみ拒否。
        assert!(matches!(
            evaluate_policies(
                std::slice::from_ref(&p),
                &ctx(user, Some("legacy-app")),
                DefaultPolicyEffect::Allow
            ),
            PolicyDecision::Deny { .. }
        ));
        // 他クライアント・クライアント無し（ポータル）は一致しない。
        assert!(matches!(
            evaluate_policies(
                std::slice::from_ref(&p),
                &ctx(user, Some("other-app")),
                DefaultPolicyEffect::Allow
            ),
            PolicyDecision::Allow { .. }
        ));
        assert!(matches!(
            evaluate_policies(
                std::slice::from_ref(&p),
                &ctx(user, None),
                DefaultPolicyEffect::Allow
            ),
            PolicyDecision::Allow { .. }
        ));
    }

    #[test]
    fn user_condition_limits_scope_and_conditions_are_anded() {
        let target = Uuid::new_v4();
        let other = Uuid::new_v4();
        let p = policy(
            "mfa-target-on-app",
            1,
            PolicyEffect::RequireMfa,
            PolicyConditions {
                client_ids: vec!["app".to_string()],
                user_ids: vec![target],
            },
        );
        // 両条件一致で成立（AND）。
        assert!(matches!(
            evaluate_policies(
                std::slice::from_ref(&p),
                &ctx(target, Some("app")),
                DefaultPolicyEffect::Allow
            ),
            PolicyDecision::RequireMfa { .. }
        ));
        // 片方だけでは不成立。
        assert!(matches!(
            evaluate_policies(
                std::slice::from_ref(&p),
                &ctx(other, Some("app")),
                DefaultPolicyEffect::Allow
            ),
            PolicyDecision::Allow { .. }
        ));
        assert!(matches!(
            evaluate_policies(
                std::slice::from_ref(&p),
                &ctx(target, Some("another")),
                DefaultPolicyEffect::Allow
            ),
            PolicyDecision::Allow { .. }
        ));
    }

    /// 同効果のポリシーが複数一致した場合は priority 昇順の先頭を記録する（監査で追跡するため）。
    #[test]
    fn lowest_priority_value_wins_within_same_effect() {
        let user = Uuid::new_v4();
        let policies = vec![
            policy(
                "mfa-low",
                100,
                PolicyEffect::RequireMfa,
                PolicyConditions::default(),
            ),
            policy(
                "mfa-high",
                10,
                PolicyEffect::RequireMfa,
                PolicyConditions::default(),
            ),
        ];
        assert_eq!(
            evaluate_policies(&policies, &ctx(user, None), DefaultPolicyEffect::Allow),
            PolicyDecision::RequireMfa {
                policy_code: "mfa-high".to_string()
            }
        );
    }

    #[test]
    fn effect_round_trips_through_str() {
        for effect in [
            PolicyEffect::Allow,
            PolicyEffect::Deny,
            PolicyEffect::RequireMfa,
        ] {
            assert_eq!(PolicyEffect::parse(effect.as_str()).unwrap(), effect);
        }
        assert!(PolicyEffect::parse("unknown").is_err());
    }

    #[test]
    fn policy_code_validation_rejects_unsafe_values() {
        assert!(AuthenticationPolicy::validate_code("deny-high_risk.v2").is_ok());
        assert!(AuthenticationPolicy::validate_code("").is_err());
        assert!(AuthenticationPolicy::validate_code(&"a".repeat(101)).is_err());
        assert!(AuthenticationPolicy::validate_code("スペース入り code").is_err());
        assert!(AuthenticationPolicy::validate_code("slash/code").is_err());
    }

    #[test]
    fn lockout_policy_locks_only_at_threshold() {
        let policy = LockoutPolicy {
            max_failed_attempts: 5,
            lock_duration_secs: 900,
        };
        let now = fixed_now();
        assert_eq!(policy.locked_until_after_failure(4, now), None);
        assert_eq!(
            policy.locked_until_after_failure(5, now),
            Some(now + chrono::Duration::seconds(900))
        );
        assert!(policy.locked_until_after_failure(6, now).is_some());
    }

    #[test]
    fn conditions_serde_round_trip() {
        let user = Uuid::new_v4();
        let conditions = PolicyConditions {
            client_ids: vec!["app".to_string()],
            user_ids: vec![user],
        };
        let json = serde_json::to_string(&conditions).unwrap();
        assert_eq!(
            serde_json::from_str::<PolicyConditions>(&json).unwrap(),
            conditions
        );
        // 空条件は `{}` に落ちる（DB の JSON カラムを簡潔に保つ）。
        assert_eq!(
            serde_json::to_string(&PolicyConditions::default()).unwrap(),
            "{}"
        );
        // 未知のキーは拒否する（タイポで条件が無視され全許可になる事故を防ぐ）。
        assert!(serde_json::from_str::<PolicyConditions>(r#"{"clientIds": []}"#).is_err());
    }
}
