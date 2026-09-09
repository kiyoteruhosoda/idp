//! セルフサービスのパスワード変更ユースケース（ログイン済みユーザーの設定画面。MT15）。
//!
//! ログインフロー中の強制変更（[`crate::application::change_password`]、`auth_session` ベース）とは別に、
//! **SSO セッションを持つログイン済みユーザー**が自分の意思でパスワードを変更する経路を提供する。
//! SSO セッション Cookie から本人を解決し、現行パスワードを再検証したうえで新パスワードを設定する。
//! OIDC フローの一部ではないため code 再発行や redirect は行わない（成功後は設定画面に留まる）。

use crate::application::audit::{AuditService, RequestContext};
use crate::application::password_policy::PasswordPolicyService;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::password::PasswordHasher;
use crate::domain::password_policy::PasswordRejection;
use crate::domain::repositories::{
    AuthorizationCodeRepository, RefreshTokenRepository, SsoSessionRepository, UserRepository,
};
use std::sync::Arc;

pub struct AccountPasswordCommand {
    /// SSO セッション Cookie の生値（SHA-256 ハッシュで DB 検索する）。
    pub sso_session_id: String,
    pub current_password: String,
    pub new_password: String,
}

pub enum AccountPasswordOutcome {
    Ok,
    /// SSO セッションが無い・期限切れ（未ログイン扱い）。
    SessionExpired,
    /// 現行パスワードが不一致。
    InvalidCurrentPassword,
    /// 新パスワードがポリシーを満たさない（長さ・漏えい済み・再利用。AP7）。
    WeakPassword(PasswordRejection),
    Internal(String),
}

pub struct AccountPasswordService {
    sso_sessions: Arc<dyn SsoSessionRepository>,
    users: Arc<dyn UserRepository>,
    /// 変更後に他端末ぶんを落とすために引く（ADR-0045）。
    refresh_tokens: Arc<dyn RefreshTokenRepository>,
    codes: Arc<dyn AuthorizationCodeRepository>,
    hasher: Arc<dyn PasswordHasher>,
    password_policy: Arc<PasswordPolicyService>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
}

impl AccountPasswordService {
    // 依存の注入で、束ねると却って読めなくなる（`LogoutService::new` と同じ扱い）。
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sso_sessions: Arc<dyn SsoSessionRepository>,
        users: Arc<dyn UserRepository>,
        refresh_tokens: Arc<dyn RefreshTokenRepository>,
        codes: Arc<dyn AuthorizationCodeRepository>,
        hasher: Arc<dyn PasswordHasher>,
        password_policy: Arc<PasswordPolicyService>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            sso_sessions,
            users,
            refresh_tokens,
            codes,
            hasher,
            password_policy,
            audit,
            clock,
        }
    }

    pub async fn change(
        &self,
        cmd: AccountPasswordCommand,
        ctx: &RequestContext,
    ) -> AccountPasswordOutcome {
        let now = self.clock.now();

        // 1. SSO セッションから本人を解決する（有効期限も確認）。
        let session_hash = crypto::sha256_hex(&cmd.sso_session_id);
        let session = match self.sso_sessions.find_by_hash(&session_hash).await {
            Ok(Some(s)) if s.is_valid_at(now) => s,
            Ok(_) => return AccountPasswordOutcome::SessionExpired,
            Err(e) => return AccountPasswordOutcome::Internal(e.to_string()),
        };
        let user = match self.users.find_by_id(session.user_id).await {
            Ok(Some(u)) if u.is_active() => u,
            Ok(_) => return AccountPasswordOutcome::SessionExpired,
            Err(e) => return AccountPasswordOutcome::Internal(e.to_string()),
        };

        // 2. 現行パスワードを再検証する。
        let verified = match self
            .hasher
            .verify(&cmd.current_password, &user.password_hash)
        {
            Ok(v) => v,
            Err(e) => return AccountPasswordOutcome::Internal(e.to_string()),
        };
        if !verified {
            return AccountPasswordOutcome::InvalidCurrentPassword;
        }

        // 3. 新パスワードがポリシーを満たすか検証し（長さ・漏えい済み・再利用。AP7）、
        //    ハッシュ化して保存する。
        match self
            .password_policy
            .validate(Some(user.id), Some(&user.password_hash), &cmd.new_password)
            .await
        {
            Ok(Ok(())) => {}
            Ok(Err(rejection)) => return AccountPasswordOutcome::WeakPassword(rejection),
            Err(e) => return AccountPasswordOutcome::Internal(e.to_string()),
        }
        let new_hash = match self.hasher.hash(&cmd.new_password) {
            Ok(h) => h,
            Err(e) => return AccountPasswordOutcome::Internal(e.to_string()),
        };
        // 現行ハッシュを条件にした置き換え（AP7）。`false` は読んでから書くまでの間に別の要求が
        // パスワードを変えたことを意味する。ここで書き込むと相手の変更を消したうえ、履歴には
        // 既に退役したハッシュを積むことになるので、やり直させる。
        match self
            .users
            .update_password(user.id, &user.password_hash, &new_hash)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!("password change lost a concurrent update; asking to retry");
                return AccountPasswordOutcome::InvalidCurrentPassword;
            }
            Err(e) => return AccountPasswordOutcome::Internal(e.to_string()),
        }
        self.password_policy
            .record_change(user.id, &user.password_hash)
            .await;

        // 4. 変えたら、他の端末とアプリを切る（ADR-0045）。
        //
        // ここが無いと、リンク経由のリセット（`password_reset`。全部落として画面も
        // 「既存のセッションはすべてサインアウトされています」と明言する）と食い違う。
        // 「漏れたかもしれないから変える」という動機の人にとって、**変えたのに前の
        // パスワードで入られた側が居座り続ける**のは、この操作の意味を失わせる。
        //
        // **今のセッションだけは残す。** `delete_all_for_user` を呼ぶと変えた本人が
        // その場で締め出される。リセット経路が全部消してよいのは、あれが「忘れた人」の
        // 経路で手元にセッションが無いからで、ここは事情が違う。
        //
        // refresh token は**残さず全部落とす**。SSO セッションと違い、これはアプリが
        // 持っている合鍵で、パスワードを変えた以上は取り直させてよい。手元のセッションが
        // 生きているので取り直しは SSO で素通りする。
        //
        // 失敗しても止めない（fail-open）。**パスワードは既に変わっており**、旧パスワードでの
        // ログインはもうできない。ここで `Internal` を返すと「変わっていない」と読める応答に
        // なる。リセット経路も同じ判断で警告ログに留めている。
        match self
            .sso_sessions
            .delete_all_for_user_except(user.id, &session_hash)
            .await
        {
            Ok(count) => tracing::info!(sessions = count, "signed out other sessions"),
            Err(e) => {
                tracing::warn!(error = %e, "failed to sign out other sessions after password change")
            }
        }
        match self.refresh_tokens.revoke_all_for_user(user.id, now).await {
            Ok(count) => tracing::info!(refresh_tokens = count, "revoked refresh tokens"),
            Err(e) => {
                tracing::warn!(error = %e, "failed to revoke refresh tokens after password change")
            }
        }
        if let Err(e) = self.codes.revoke_all_active_for_user(user.id, now).await {
            tracing::warn!(error = %e, "failed to revoke authorization codes after password change");
        }

        self.audit
            .record(
                AuditEventType::PasswordChanged,
                AuditResult::Success,
                Some(user.tenant_id),
                Some(user.id),
                None,
                None,
                ctx,
            )
            .await;

        AccountPasswordOutcome::Ok
    }
}
