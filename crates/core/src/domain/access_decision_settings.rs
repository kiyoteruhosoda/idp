//! 判定そのものを決める 2 キーを、テナントについて引く口（ADR-0058 §4・§10）。
//!
//! - `AUTH_POLICY_DEFAULT_EFFECT` —— 認証ポリシーが 1 件も一致しないときの既定動作
//! - `APPLICATION_ASSIGNMENT_ENFORCEMENT` —— アプリの割り当て判定で断るか、記録するだけか
//!
//! どちらも**テナントが決める**。名簿が整ったテナントから `enforce` へ倒せるようにするためで、
//! 全体 1 枚だと「全テナントの名簿が揃うまで倒せない」。
//!
//! # 判定する側は `Config` を読まない
//!
//! 認証の 8 経路（OIDC のログイン・MFA・パスキー・外部 IdP・パスワード変更・SSO 復元、管理
//! コンソール、ポータル）と割り当ての門は、起動時の `Config` ではなくこの口からテナントの値を引く。
//! ⚠ **1 経路でも `Config` を読み残すと、その経路だけ全体の値で動き、しかも静かに間違える。**
//! 判定する側がトレイトしか持たないようにしてあるのは、それを型で塞ぐためである。
//! 実装は `application::access_decision_settings`（テナント設定の解決に乗せる）。
//!
//! # web は値を持たない
//!
//! 管理コンソールが既定動作・強制の有無を示すときも、web はこの値を持たず、api の応答に
//! 載ったテナントの値を描くだけにする（ADR-0013 の起動時スナップショットには載せない）。

use crate::domain::authentication_policy::DefaultPolicyEffect;
use crate::domain::error::Result;
use crate::domain::tenant::TenantId;
use crate::domain::values::AssignmentEnforcement;
use async_trait::async_trait;

pub const AUTH_POLICY_DEFAULT_EFFECT: &str = "AUTH_POLICY_DEFAULT_EFFECT";
pub const APPLICATION_ASSIGNMENT_ENFORCEMENT: &str = "APPLICATION_ASSIGNMENT_ENFORCEMENT";

/// 判定の既定を、テナントについて返す。
#[async_trait]
pub trait AccessDecisionSettings: Send + Sync {
    /// 認証ポリシーが 1 件も一致しないときの既定動作。
    async fn policy_default_effect(&self, tenant_id: TenantId) -> Result<DefaultPolicyEffect>;
    /// アプリの割り当て判定をどこまでやるか。
    async fn assignment_enforcement(&self, tenant_id: TenantId) -> Result<AssignmentEnforcement>;
}
