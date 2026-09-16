//! テナントについて効いている設定値を引く口（ADR-0058）。
//!
//! テナントが上書きできるキーを読む側（認証の各経路・パスワードポリシー・アプリの門・リンクの
//! 発行など）は、起動時の `Config` でも解決器の具象でもなく、**このトレイト 1 本**から値を引く。
//! 実装は `application::tenant_settings::TenantSettingsService`（テナントの行 → 全体の行 →
//! 環境変数 → 組み込み既定）。
//!
//! ⚠ **1 経路でも `Config` を読み残すと、その経路だけ全体の値で動き、しかも静かに間違える。**
//! 読む側がトレイトしか持たないようにしてあるのは、それを型で塞ぐためである。
//!
//! # 口が 2 本あった
//!
//! 判定の既定 2 キー（#22）と、パスワード・ロックアウト・SSO・step-up など（#24）が別々に
//! 足され、同じ解決器へ別の口（トレイトと具象）で届いていた。どちらも同じ解決に乗るので 1 本に
//! まとめた。書き込み（`set` / `clear`）と画面向けの一覧は管理の口であり、ここには載せない。
//!
//! # どのテナントを渡すか（ADR-0058 §13）
//!
//! | まとまり | 渡すテナント |
//! |---|---|
//! | パスワードポリシー・ロックアウト・SSO セッションの寿命・step-up | 利用者の**所属元** |
//! | パスワード再設定・メール検証のリンク | 利用者の**所属元** |
//! | 招待のリンク | 招待した**参加先** |
//! | 認証ポリシーの既定動作・アプリ割り当ての強制 | 判定しているテナント |
//!
//! # 判定の既定 2 キー
//!
//! - `AUTH_POLICY_DEFAULT_EFFECT` —— 認証ポリシーが 1 件も一致しないときの既定動作
//! - `APPLICATION_ASSIGNMENT_ENFORCEMENT` —— アプリの割り当て判定で断るか、記録するだけか
//!
//! どちらも**テナントが決める**（§4・§10）。名簿が整ったテナントから `enforce` へ倒せるように
//! するためで、全体 1 枚だと「全テナントの名簿が揃うまで倒せない」。行の無いテナントの既定は
//! `allow` と `record_only` で、⚠ 名簿の無いテナントが勝手に断る側へ倒れることは無い。
//!
//! 管理コンソールが既定動作・強制の有無を示すときも、web はこの値を持たず、api の応答に
//! 載ったテナントの値を描くだけにする（ADR-0013 の起動時スナップショットには載せない）。

use crate::domain::authentication_policy::{DefaultPolicyEffect, LockoutPolicy};
use crate::domain::error::Result;
use crate::domain::password_policy::PasswordPolicy;
use crate::domain::tenant::TenantId;
use crate::domain::values::AssignmentEnforcement;
use async_trait::async_trait;
use chrono::Duration;

pub const AUTH_POLICY_DEFAULT_EFFECT: &str = "AUTH_POLICY_DEFAULT_EFFECT";
pub const APPLICATION_ASSIGNMENT_ENFORCEMENT: &str = "APPLICATION_ASSIGNMENT_ENFORCEMENT";

/// SSO セッションの寿命（`SSO_IDLE_TTL_SECS` / `SSO_ABSOLUTE_TTL_SECS`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SsoSessionLifetime {
    pub idle: Duration,
    pub absolute: Duration,
}

/// テナントについて効いている値を、型付きで返す。
///
/// 読む側はキーの綴りと型変換をここに任せる（呼び出し側で文字列を解釈させない）。⚠ 保存値が
/// 型に合わないときは全体へ黙って落とさずにエラーを返す。
#[async_trait]
pub trait EffectiveTenantSettings: Send + Sync {
    /// パスワードポリシー（`PASSWORD_*`）。
    async fn password_policy(&self, tenant_id: TenantId) -> Result<PasswordPolicy>;
    /// ロックアウト（`LOGIN_*`）。
    async fn login_lockout(&self, tenant_id: TenantId) -> Result<LockoutPolicy>;
    /// SSO セッションの寿命（確立と idle 延長の両方で使う）。
    async fn sso_session_lifetime(&self, tenant_id: TenantId) -> Result<SsoSessionLifetime>;
    /// step-up（重要操作の直前の本人確認）の有効秒数。
    async fn step_up_max_age_secs(&self, tenant_id: TenantId) -> Result<u64>;
    /// 招待リンクの有効期間。
    async fn invitation_ttl(&self, tenant_id: TenantId) -> Result<Duration>;
    /// パスワード再設定リンクの有効期間。
    async fn password_reset_ttl(&self, tenant_id: TenantId) -> Result<Duration>;
    /// SMTP で送れないとき、再設定リンクをサーバのコンソールへ出してよいか。
    async fn password_reset_console_link_enabled(&self, tenant_id: TenantId) -> Result<bool>;
    /// メール検証リンクの有効期間。
    async fn email_verification_ttl(&self, tenant_id: TenantId) -> Result<Duration>;
    /// 認証ポリシーが 1 件も一致しないときの既定動作。
    async fn policy_default_effect(&self, tenant_id: TenantId) -> Result<DefaultPolicyEffect>;
    /// アプリの割り当て判定をどこまでやるか。
    async fn assignment_enforcement(&self, tenant_id: TenantId) -> Result<AssignmentEnforcement>;
}
