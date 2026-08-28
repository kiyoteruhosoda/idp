//! 管理コンソール（web）のログイン・ホーム・ログアウト・強制パスワード変更
//! （ADR-0006 §6・ADR-0007 §4・ADR-0009 §5・§6）。
//!
//! web は画面描画のみを担い、認証・認可・セッション失効は api に委ねる:
//! - ログインは api の `POST /internal/authenticate/admin`（サービストークン保護）。
//! - 認証状態と身元は api の `GET /{tenant_id}/admin/whoami`（管理者の SSO Cookie を転送。
//!   `RequirePerms<IdpAdmin>`）。
//! - ログアウトは api の `POST /internal/logout`（SSO セッション失効）。
//! - 強制パスワード変更（`must_change_password`。ADR-0009 §5）は SSO をまだ持たないため、
//!   `POST /internal/authenticate/admin/change-password` で現行パスワードを含め再検証する。
//!
//! Cookie 組み立て（SSO 発行・失効、CSRF 種）は web が行う。CSRF は web 内で完結する（`crate::csrf`）。

use super::{internal_call_status, locale};
use crate::api_client::{AdminIdentity, AdminSession};
use crate::client_ip::ClientIp;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::admin_csrf_token;
use crate::dto::{ForcedPasswordChangeForm, FormPageQuery, LoginForm};
use crate::error_pages;
use crate::handlers::{form_retry_error_key, forwarded_context, found, see_other};
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{
    render, ConsoleAdmin, ConsoleHome, ConsoleLogin, ForcedPasswordChange, MessagePage,
    SwitchTenant,
};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use idp_contracts::auth::{
    InternalAccountTenantsRequest, InternalAccountTenantsResponse,
    InternalAdminAuthenticateRequest, InternalAdminAuthenticateResponse,
    InternalAdminChangePasswordRequest, InternalAdminChangePasswordResponse, InternalLogoutRequest,
};
use uuid::Uuid;

/// 管理コンソールのホーム（`GET /{tenant_id}/admin`）。SSO を api へ転送して認可を確認する。
pub async fn home(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(context) => context,
        AdminResolution::Reject(resp) => return resp,
    };
    let messages = Messages::new(locale(&headers));
    Html(render(&ConsoleHome {
        messages: &messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
    }))
    .into_response()
}

/// テナント切り替え画面（`GET /{tenant_id}/admin/switch-tenant`）。ログイン中ユーザーが `ACTIVE` な
/// メンバーシップを持つテナントを一覧し、対象テナントの管理コンソールへ遷移できる。SSO はホスト共有の
/// ため再ログインは不要（ADR-0009 §8）。
pub async fn switch_tenant(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(context) => context,
        AdminResolution::Reject(resp) => return resp,
    };
    // 所属テナント一覧を api から取得する（SSO Cookie 転送）。取得に失敗しても画面は描画し、注意文言を出す。
    let sso = cookies::get(&headers, cookies::SSO_SESSION_COOKIE).unwrap_or_default();
    let (tenants, load_failed) = match state
        .api
        .account_tenants(&InternalAccountTenantsRequest {
            sso_session_id: sso,
        })
        .await
    {
        Ok(InternalAccountTenantsResponse::Ok { tenants }) => (tenants, false),
        Ok(_) => (Vec::new(), false),
        Err(e) => {
            tracing::error!(error = %e, "account tenants list call to api failed");
            (Vec::new(), true)
        }
    };
    let messages = Messages::new(locale(&headers));
    Html(render(&SwitchTenant {
        messages: &messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        tenants: &tenants,
        current_tenant_id: &tenant.0,
        load_failed,
    }))
    .into_response()
}

/// 管理ログインフォーム（`GET /{tenant_id}/admin/login`）。既にログイン済みならホームへ 302 する。
/// `?error=csrf` は CSRF 不一致の POST から PRG で戻ったときのエラーバナー表示。
pub async fn login_page(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    Query(query): Query<FormPageQuery>,
    headers: HeaderMap,
) -> Response {
    // 既に有効な SSO ＋ 権限を持つならホームへ。
    if let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) {
        if let AdminSession::Authenticated(_) = state
            .api
            .admin_whoami(&correlation.0, &tenant.0, &sso)
            .await
        {
            return found(&admin_home_path(&tenant));
        }
    }

    let messages = Messages::new(locale(&headers));
    // CSRF の種（推測不能な乱数）を Cookie とフォーム双方へ渡す。既に有効な種 Cookie があれば
    // 使い回して TTL を延長する（GET のたびに回転させると複数タブで開いた古いフォームが必ず
    // CSRF 不一致になる。種はセッション非依存の乱数であり、使い回しても保護強度は変わらない）。
    let csrf_id = cookies::get(
        &headers,
        &state.origin_bound_cookie(cookies::ADMIN_CSRF_COOKIE),
    )
    .filter(|s| !s.is_empty())
    .unwrap_or_else(|| Uuid::new_v4().simple().to_string());
    let csrf = admin_csrf_token(&csrf_id, state.config.csrf_secret());
    let set_cookies = state.set_cookies().set_local(
        &state.origin_bound_cookie(cookies::ADMIN_CSRF_COOKIE),
        &csrf_id,
        3600,
    );
    (
        set_cookies.into_headers(),
        Html(render_login_form(
            &messages,
            &tenant.prefix(),
            &csrf,
            form_retry_error_key(query.error.as_deref()),
        )),
    )
        .into_response()
}

/// 管理ログイン処理（`POST /{tenant_id}/admin/login`）。CSRF を web で検証し、資格情報は api へ委ねる。
pub async fn login(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    // CSRF 検証（Cookie の種からトークンを再計算して照合）。FluentBundle は Send でないため各分岐で生成。
    let csrf_id = cookies::get(
        &headers,
        &state.origin_bound_cookie(cookies::ADMIN_CSRF_COOKIE),
    );
    let csrf_ok = csrf_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|id| admin_csrf_token(id, state.config.csrf_secret()) == form.csrf_token)
        .unwrap_or(false);
    if !csrf_ok {
        // PRG: 303 で GET へ付け替え、新しい種 Cookie とトークンでフォームを自動再表示する
        //（従来は空の CSRF を埋めたフォームを再描画するため、再送信しても復帰できなかった）。
        tracing::warn!(
            correlation_id = %correlation.0,
            "admin login failed: csrf token mismatch or seed cookie expired; redirecting to fresh form"
        );
        return see_other(&format!("{}/admin/login?error=csrf", tenant.prefix()));
    }
    let csrf = admin_csrf_token(&csrf_id.unwrap_or_default(), state.config.csrf_secret());

    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let request = InternalAdminAuthenticateRequest {
        tenant_id: Some(tenant.0.clone()),
        username: form.username,
        password: form.password,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let outcome = match state
        .api
        .authenticate_admin(&ctx.correlation_id, &request)
        .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "admin internal authenticate call to api failed");
            return internal_call_status(&e).into_response();
        }
    };

    let messages = Messages::new(locale(&headers));
    match outcome {
        InternalAdminAuthenticateResponse::Success {
            sso_session_id,
            sso_absolute_ttl_secs,
        } => {
            let set_cookies = state
                .set_cookies()
                .set_session(
                    cookies::SSO_SESSION_COOKIE,
                    &sso_session_id,
                    sso_absolute_ttl_secs,
                )
                .expire_local(&state.origin_bound_cookie(cookies::ADMIN_CSRF_COOKIE));
            (set_cookies.into_headers(), found(&admin_home_path(&tenant))).into_response()
        }
        InternalAdminAuthenticateResponse::PasswordChangeRequired { username } => {
            // 強制パスワード変更（ADR-0009 §5）。SSO はまだ発行されていない。CSRF Cookie は維持し、
            // 変更フォームへ同じ csrf を埋め込む（ブラウザに残る Cookie で照合できる）。
            Html(render_password_change_form(
                &messages,
                &tenant.prefix(),
                &csrf,
                &username,
                None,
            ))
            .into_response()
        }
        InternalAdminAuthenticateResponse::RateLimited => reshow_login(
            &messages,
            &tenant.prefix(),
            StatusCode::TOO_MANY_REQUESTS,
            &csrf,
            "login-error-rate-limited",
        ),
        InternalAdminAuthenticateResponse::InvalidCredentials => reshow_login(
            &messages,
            &tenant.prefix(),
            StatusCode::UNAUTHORIZED,
            &csrf,
            "login-error-invalid-credentials",
        ),
        InternalAdminAuthenticateResponse::Locked => reshow_login(
            &messages,
            &tenant.prefix(),
            StatusCode::FORBIDDEN,
            &csrf,
            "login-error-locked",
        ),
        InternalAdminAuthenticateResponse::Forbidden => reshow_login(
            &messages,
            &tenant.prefix(),
            StatusCode::FORBIDDEN,
            &csrf,
            "admin-login-error-forbidden",
        ),
        // 認証ポリシー（AP2）。資格情報は検証済みなので、資格情報エラーとは別の文言を出す。
        InternalAdminAuthenticateResponse::PolicyDenied => reshow_login(
            &messages,
            &tenant.prefix(),
            StatusCode::FORBIDDEN,
            &csrf,
            "login-error-policy-denied",
        ),
        InternalAdminAuthenticateResponse::MfaEnrollmentRequired => reshow_login(
            &messages,
            &tenant.prefix(),
            StatusCode::FORBIDDEN,
            &csrf,
            "login-error-mfa-enrollment-required",
        ),
        InternalAdminAuthenticateResponse::MfaRequired => reshow_login(
            &messages,
            &tenant.prefix(),
            StatusCode::FORBIDDEN,
            &csrf,
            "admin-login-error-mfa-required",
        ),
        InternalAdminAuthenticateResponse::Internal => {
            (StatusCode::INTERNAL_SERVER_ERROR, Html(String::new())).into_response()
        }
    }
}

/// 強制パスワード変更ページ（`GET /{tenant_id}/admin/password-change`）。ブックマーク・再読込対策として
/// 直接アクセスはログイン画面へ誘導する（本人性は `POST /admin/login` からのフォーム遷移で確認済みの
/// username（ログイン識別子）を要するため、GET 単独では変更を開始できない）。
pub async fn password_change_page(Extension(tenant): Extension<WebTenant>) -> Response {
    found(&format!("{}/admin/login", tenant.prefix()))
}

/// 強制パスワード変更の実行（`POST /{tenant_id}/admin/password-change`、ADR-0009 §5）。
pub async fn password_change(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<ForcedPasswordChangeForm>,
) -> Response {
    let csrf_id = cookies::get(
        &headers,
        &state.origin_bound_cookie(cookies::ADMIN_CSRF_COOKIE),
    );
    let csrf_ok = csrf_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|id| admin_csrf_token(id, state.config.csrf_secret()) == form.csrf_token)
        .unwrap_or(false);
    if !csrf_ok {
        // PRG: 強制変更フォームは `POST /admin/login` からのフォーム遷移でしか開始できない
        //（username を運ぶ）ため、ログイン画面へ 303 で戻して最初からやり直させる。
        tracing::warn!(
            correlation_id = %correlation.0,
            "admin forced password change failed: csrf token mismatch or seed cookie expired; redirecting to login"
        );
        return see_other(&format!("{}/admin/login?error=csrf", tenant.prefix()));
    }
    let csrf = admin_csrf_token(&csrf_id.unwrap_or_default(), state.config.csrf_secret());

    if form.new_password != form.new_password_confirm {
        let messages = Messages::new(locale(&headers));
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Html(render_password_change_form(
                &messages,
                &tenant.prefix(),
                &csrf,
                &form.username,
                Some("password-change-error-mismatch"),
            )),
        )
            .into_response();
    }

    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let request = InternalAdminChangePasswordRequest {
        tenant_id: Some(tenant.0.clone()),
        username: form.username.clone(),
        current_password: form.current_password,
        new_password: form.new_password,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let outcome = match state
        .api
        .admin_change_password(&ctx.correlation_id, &request)
        .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "admin change-password call to api failed");
            return internal_call_status(&e).into_response();
        }
    };

    let messages = Messages::new(locale(&headers));
    match outcome {
        InternalAdminChangePasswordResponse::Success {
            sso_session_id,
            sso_absolute_ttl_secs,
        } => {
            let set_cookies = state
                .set_cookies()
                .set_session(
                    cookies::SSO_SESSION_COOKIE,
                    &sso_session_id,
                    sso_absolute_ttl_secs,
                )
                .expire_local(&state.origin_bound_cookie(cookies::ADMIN_CSRF_COOKIE));
            (set_cookies.into_headers(), found(&admin_home_path(&tenant))).into_response()
        }
        InternalAdminChangePasswordResponse::RateLimited => reshow_password_change(
            &messages,
            &tenant.prefix(),
            StatusCode::TOO_MANY_REQUESTS,
            &csrf,
            &form.username,
            "login-error-rate-limited",
        ),
        InternalAdminChangePasswordResponse::InvalidCredentials => reshow_password_change(
            &messages,
            &tenant.prefix(),
            StatusCode::UNAUTHORIZED,
            &csrf,
            &form.username,
            "password-change-error-invalid-current",
        ),
        InternalAdminChangePasswordResponse::Locked => reshow_password_change(
            &messages,
            &tenant.prefix(),
            StatusCode::FORBIDDEN,
            &csrf,
            &form.username,
            "login-error-locked",
        ),
        InternalAdminChangePasswordResponse::Forbidden => reshow_password_change(
            &messages,
            &tenant.prefix(),
            StatusCode::FORBIDDEN,
            &csrf,
            &form.username,
            "admin-login-error-forbidden",
        ),
        InternalAdminChangePasswordResponse::WeakPassword { reason } => reshow_password_change(
            &messages,
            &tenant.prefix(),
            StatusCode::UNPROCESSABLE_ENTITY,
            &csrf,
            &form.username,
            super::password_rejection_key(reason, "password-change-error-weak"),
        ),
        InternalAdminChangePasswordResponse::PolicyDenied => reshow_password_change(
            &messages,
            &tenant.prefix(),
            StatusCode::FORBIDDEN,
            &csrf,
            &form.username,
            "login-error-policy-denied",
        ),
        InternalAdminChangePasswordResponse::MfaEnrollmentRequired => reshow_password_change(
            &messages,
            &tenant.prefix(),
            StatusCode::FORBIDDEN,
            &csrf,
            &form.username,
            "login-error-mfa-enrollment-required",
        ),
        InternalAdminChangePasswordResponse::MfaRequired => reshow_password_change(
            &messages,
            &tenant.prefix(),
            StatusCode::FORBIDDEN,
            &csrf,
            &form.username,
            "admin-login-error-mfa-required",
        ),
        InternalAdminChangePasswordResponse::Internal => {
            (StatusCode::INTERNAL_SERVER_ERROR, Html(String::new())).into_response()
        }
    }
}

/// ログアウト（`POST /{tenant_id}/admin/logout`）。api で SSO を失効させ、Cookie を失効してログインへ 302。
pub async fn logout(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
) -> Response {
    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    if let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) {
        let _ = state
            .api
            .logout(
                &ctx.correlation_id,
                &InternalLogoutRequest {
                    tenant_id: Some(tenant.0.clone()),
                    sso_session_id: sso,
                    ip_address: ctx.ip_address,
                    user_agent: ctx.user_agent,
                },
            )
            .await;
    }
    let set_cookies = state
        .set_cookies()
        .expire_session(cookies::SSO_SESSION_COOKIE);
    (set_cookies.into_headers(), redirect_to_login(&tenant)).into_response()
}

/// 認可済み管理者の解決結果。`Reject` は誘導/エラーの完成済み Response を持つ。
pub(crate) enum AdminResolution {
    Ok(AdminContext),
    Reject(Response),
}

/// 認可済み管理者と操作中テナントの文脈。各コンソール画面がヘッダ描画のために持ち回る
/// （`ConsoleAdmin` の所有版。テンプレートへは [`Self::chrome`] で借用として渡す）。
pub(crate) struct AdminContext {
    identity: AdminIdentity,
}

impl AdminContext {
    /// 画面描画テスト用の文脈。実行時は必ず api の whoami 応答から組み立てる。
    #[cfg(test)]
    pub(crate) fn for_test(label: &str, tenant_name: Option<&str>) -> Self {
        Self {
            identity: AdminIdentity::for_test(label, tenant_name),
        }
    }

    /// 共通レイアウトのヘッダに渡す文脈（管理者ラベル＋テナント表示名）。
    pub(crate) fn chrome(&self) -> ConsoleAdmin<'_> {
        ConsoleAdmin {
            label: &self.identity.label,
            tenant_name: self.identity.tenant_name.as_deref(),
            permissions: self.identity.permissions(),
        }
    }
}

/// SSO Cookie を api へ転送して管理者を解決する（未認証→ログイン誘導、権限不足→403 HTML）。
/// 各管理コンソール画面はこれで保護する（api の `AdminHtmlSession` に相当）。
pub(crate) async fn resolve_admin(
    state: &WebState,
    correlation: &CorrelationId,
    tenant: &WebTenant,
    headers: &HeaderMap,
) -> AdminResolution {
    let sso = cookies::get(headers, cookies::SSO_SESSION_COOKIE).unwrap_or_default();
    let session = state
        .api
        .admin_whoami(&correlation.0, &tenant.0, &sso)
        .await;
    admin_resolution(session, tenant, headers)
}

/// whoami の結果 → 画面応答の写像（api 呼び出しから分離してテスト可能にする）。
///
/// テナントが解決できない（`NotFound`）ときは 404 ページを返す。ここを `Error` と同じ 502 に倒すと、
/// 存在しないテナントの URL がゲートウェイ障害に見えてしまう（原因の切り分けを誤らせる）。
fn admin_resolution(
    session: AdminSession,
    tenant: &WebTenant,
    headers: &HeaderMap,
) -> AdminResolution {
    match session {
        AdminSession::Authenticated(identity) => AdminResolution::Ok(AdminContext { identity }),
        AdminSession::Unauthenticated => AdminResolution::Reject(redirect_to_login(tenant)),
        AdminSession::Forbidden => AdminResolution::Reject(forbidden_response(headers)),
        AdminSession::NotFound => {
            AdminResolution::Reject(error_pages::page(StatusCode::NOT_FOUND, headers))
        }
        AdminSession::Error => {
            AdminResolution::Reject((StatusCode::BAD_GATEWAY, Html(String::new())).into_response())
        }
    }
}

/// 管理コンソールのホーム経路（`/{tenant_id}/admin`）。
pub(crate) fn admin_home_path(tenant: &WebTenant) -> String {
    format!("{}/admin", tenant.prefix())
}

/// ログイン画面への 302 リダイレクト。
pub(crate) fn redirect_to_login(tenant: &WebTenant) -> Response {
    found(&format!("{}/admin/login", tenant.prefix()))
}

/// 権限不足を伝える最小限の HTML ページ(403)。管理コンソール各画面から再利用する。
pub(crate) fn forbidden_response(headers: &HeaderMap) -> Response {
    let messages = Messages::new(locale(headers));
    let body = render(&MessagePage {
        title: messages.get("admin-forbidden-title"),
        message: messages.get("admin-forbidden-message"),
    });
    (StatusCode::FORBIDDEN, Html(body)).into_response()
}

fn reshow_login(
    messages: &Messages,
    tenant_prefix: &str,
    status: StatusCode,
    csrf: &str,
    error_key: &str,
) -> Response {
    (
        status,
        Html(render_login_form(
            messages,
            tenant_prefix,
            csrf,
            Some(error_key),
        )),
    )
        .into_response()
}

fn reshow_password_change(
    messages: &Messages,
    tenant_prefix: &str,
    status: StatusCode,
    csrf: &str,
    username: &str,
    error_key: &str,
) -> Response {
    (
        status,
        Html(render_password_change_form(
            messages,
            tenant_prefix,
            csrf,
            username,
            Some(error_key),
        )),
    )
        .into_response()
}

/// 管理ログインフォームの HTML をテンプレートから描画する（埋め込む値は自動 HTML エスケープされる）。
fn render_login_form(
    messages: &Messages,
    tenant_prefix: &str,
    csrf: &str,
    error_key: Option<&str>,
) -> String {
    render(&ConsoleLogin {
        messages,
        tenant_prefix,
        csrf,
        error_key,
    })
}

/// 強制パスワード変更フォームの HTML を共有テンプレート（[`ForcedPasswordChange`]）から描画する。
/// 送信先は管理コンソールの `POST /{tenant_id}/admin/password-change`（ポータルは別ハンドラで別 action）。
fn render_password_change_form(
    messages: &Messages,
    tenant_prefix: &str,
    csrf: &str,
    username: &str,
    error_key: Option<&str>,
) -> String {
    render(&ForcedPasswordChange {
        messages,
        action: &format!("{tenant_prefix}/admin/password-change"),
        csrf,
        username,
        error_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::Locale;

    #[test]
    fn login_form_has_csrf_and_credential_fields() {
        let messages = Messages::new(Locale::Ja);
        let tenant_prefix = "/00000000-0000-7000-8000-000000000000";
        let html = render_login_form(&messages, tenant_prefix, "deadbeef", None);
        assert!(html.contains("name=\"csrf_token\" value=\"deadbeef\""));
        assert!(html.contains("name=\"username\""));
        assert!(html.contains("name=\"password\""));
        assert!(!html.contains("role=\"alert\""));
        // パスワードを忘れた管理者の自己復旧導線（利用者ログイン画面と同じ経路）。
        assert!(html.contains(&format!("href=\"{tenant_prefix}/forgot-password\"")));
    }

    #[test]
    fn home_lists_sections_and_logout_for_signed_in_admin() {
        let messages = Messages::new(Locale::Ja);
        let html = render(&ConsoleHome {
            messages: &messages,
            tenant: "/00000000-0000-7000-8000-000000000000",
            admin: Some(crate::templates::ConsoleAdmin {
                label: "user-123",
                tenant_name: Some("ROOT"),
                permissions: &[],
            }),
        });
        assert!(html.contains("user-123"));
        assert!(html.contains("ROOT"));
        assert!(html.contains("action=\"/00000000-0000-7000-8000-000000000000/admin/logout\""));
        assert!(html.contains("/00000000-0000-7000-8000-000000000000/admin/clients"));
    }

    fn reject_status(session: AdminSession) -> StatusCode {
        let tenant = WebTenant("019f8ea8-f5dd-7fc7-ac15-a7d4337e4610".to_string());
        match admin_resolution(session, &tenant, &HeaderMap::new()) {
            AdminResolution::Ok(_) => panic!("expected a rejection"),
            AdminResolution::Reject(response) => response.status(),
        }
    }

    /// api がテナントを解決できない（404）ときは 404 ページを返す。502（ゲートウェイ障害）に
    /// 倒すと、存在しないテナントの URL が障害に見えて切り分けを誤らせるための回帰テスト。
    #[test]
    fn unknown_tenant_is_rejected_as_not_found_not_bad_gateway() {
        assert_eq!(reject_status(AdminSession::NotFound), StatusCode::NOT_FOUND);
    }

    /// 他の分岐は従来どおり（未認証→ログインへ 302、権限不足→403、api 障害→502）。
    #[test]
    fn other_sessions_keep_their_responses() {
        assert_eq!(
            reject_status(AdminSession::Unauthenticated),
            StatusCode::FOUND
        );
        assert_eq!(
            reject_status(AdminSession::Forbidden),
            StatusCode::FORBIDDEN
        );
        assert_eq!(reject_status(AdminSession::Error), StatusCode::BAD_GATEWAY);
    }
}
