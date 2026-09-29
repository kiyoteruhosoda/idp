//! 認証ポリシーの評価の入口（ユーザー認証・認証ポリシー仕様書 §9、AP2/AP3、ADR-0054 の決定 5）。
//!
//! 評価そのものはドメインの純粋関数（[`evaluate_policies`]）が担う。ここが持つのは、その材料を
//! 揃える手順だけである:
//!
//! 1. 宛先の読み替え —— フローが持っているのは `client_id` だけなので、アプリへ読み替える
//!    （ポリシーの `conditions.application_ids` はアプリを指す）。まだアプリへ繋がっていない
//!    client は `None` で、`application_ids` を持つポリシーは一致しない
//! 2. 一致するポリシーが無いときの既定の効果（テナントの値を参照のたびに引く。ADR-0058 §4）
//! 3. テナントの有効なポリシー
//!
//! ログイン・MFA・パスキー・パスワード変更・外部 IdP・SSO 復元・管理コンソール・ポータルの
//! 8 経路が同じ手順を写していたのを、ここへ寄せた。結論（`PolicyDecision`）をどう扱うか
//! （拒否の監査の書き方、第二要素を要求するか）は経路ごとに違うので、呼び出し側に残す。

use crate::application::application_access::ApplicationAccessService;
use crate::domain::authentication_policy::{
    evaluate_policies, AuthenticationContext, PolicyDecision,
};
use crate::domain::effective_tenant_settings::EffectiveTenantSettings;
use crate::domain::error::DomainError;
use crate::domain::repositories::AuthenticationPolicyRepository;
use crate::domain::tenant::TenantId;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use uuid::Uuid;

/// ポリシーの宛先。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAudience<'a> {
    /// OIDC の認可要求を出したクライアント（アプリへ読み替えて評価する）。
    OidcClient(&'a str),
    /// 認可要求の外（管理コンソール・ポータル・アカウント設定から始めた外部 IdP 連携）。
    /// 宛先が無いので、`application_ids` を持つポリシーは一致しない。
    Unaddressed,
}

/// 評価の問い: 誰が・どこへ・どこから・いつ。
#[derive(Debug, Clone, Copy)]
pub struct PolicyQuery<'a> {
    pub tenant_id: TenantId,
    pub audience: PolicyAudience<'a>,
    pub user_id: Uuid,
    pub ip_address: Option<&'a str>,
    /// 認可要求の `acr_values`（AP3 の `requested_acr` 条件が参照する）。認可要求の外では空。
    pub requested_acr: &'a [String],
    pub now: DateTime<Utc>,
}

pub struct AuthenticationPolicyGate {
    policies: Arc<dyn AuthenticationPolicyRepository>,
    settings: Arc<dyn EffectiveTenantSettings>,
    applications: Arc<ApplicationAccessService>,
}

impl AuthenticationPolicyGate {
    pub fn new(
        policies: Arc<dyn AuthenticationPolicyRepository>,
        settings: Arc<dyn EffectiveTenantSettings>,
        applications: Arc<ApplicationAccessService>,
    ) -> Self {
        Self {
            policies,
            settings,
            applications,
        }
    }

    /// 問いに対する結論を出す。材料のどれかが引けなければ `Err`（呼び出し側は内部エラーとして扱う）。
    pub async fn decide(&self, query: PolicyQuery<'_>) -> Result<PolicyDecision, DomainError> {
        let application_id = match query.audience {
            PolicyAudience::OidcClient(client_id) => {
                self.applications
                    .policy_target_for_oidc_client(query.tenant_id, client_id)
                    .await?
            }
            PolicyAudience::Unaddressed => None,
        };
        let default_effect = self.settings.policy_default_effect(query.tenant_id).await?;
        let policies = self
            .policies
            .list_enabled_for_tenant(query.tenant_id)
            .await?;
        Ok(evaluate_policies(
            &policies,
            &AuthenticationContext {
                application_id,
                user_id: query.user_id,
                ip_address: query.ip_address,
                now: query.now,
                requested_acr: query.requested_acr,
            },
            default_effect,
        ))
    }
}

/// 試験で評価の入口を組み立てる部品（アプリの読み替えはすべて「アプリ無し」）。
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::application::audit::AuditService;

    pub fn gate(
        policies: Arc<dyn AuthenticationPolicyRepository>,
        settings: Arc<dyn EffectiveTenantSettings>,
        audit: Arc<AuditService>,
    ) -> Arc<AuthenticationPolicyGate> {
        Arc::new(AuthenticationPolicyGate::new(
            policies,
            settings,
            crate::application::application_access::test_support::allow_everything(audit),
        ))
    }
}
