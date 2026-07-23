//! エンドユーザー・ポータルのログイン（`/{tenant_id}/login` の OIDC 非依存経路）。
//!
//! `/{tenant_id}/login` は OIDC 連携アプリからの遷移（`auth_session_id` Cookie あり）では通常の OIDC
//! ログイン（[`crate::handlers::login`]）として働く。`auth_session_id` を持たない直接アクセスでは、本
//! モジュールの **ポータルログイン**（IdP 自身のアカウント画面 `/{tenant_id}/settings` へ入るための直接
//! ログイン）として働く。振り分けは [`crate::handlers::login`] が Cookie の有無で行い、本モジュールへ委譲する。
//!
//! 認証・SSO 発行・TOTP 検証は api（`/internal/authenticate/portal*`）に委ね、web は CSRF（同期トークン）
//! と Cookie 組み立て・画面描画・リダイレクトのみを担う（管理コンソールのログインと同じ責務分担）。

use super::locale;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::portal_csrf_token;
use crate::dto::{ForcedPasswordChangeForm, LoginForm, PortalTotpForm};
use crate::handlers::{forwarded_context, found};
use crate::i18n::{Locale, Messages};
use crate::state::WebState;
use crate::templates::{render, ForcedPasswordChange, MessagePage, PortalLogin, PortalMfa};
use crate::tenant::WebTenant;
use axum::extract::{Extension, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{AppendHeaders, Html, IntoResponse, Response};
use axum::Form;
use idp_contracts::auth::{
    InternalPortalAuthenticateRequest, InternalPortalAuthenticateResponse,
    InternalPortalChangePasswordRequest, InternalPortalChangePasswordResponse,
    InternalPortalMfaRequest, InternalPortalMfaResponse,
};

/// ポータル CSRF 種 Cookie の寿命（秒）。ログイン〜TOTP 入力までを覆う。
const PORTAL_CSRF_TTL_SECS: u64 = 900;
/// `mfa_ticket` Cookie の寿命（秒）。api 側チケットの有効期間（5 分）に合わせる。
const PORTAL_MFA_TTL_SECS: u64 = 300;

/// ポータルのログインフォーム（`GET /{tenant_id}/login`、`auth_session_id` 無し）。
pub async fn login_page(state: &WebState, tenant: &WebTenant, headers: &HeaderMap) -> Response {
    let messages = Messages::new(locale(headers));
    // CSRF の種（推測不能な乱数）を新規発行し、Cookie とフォーム双方へ渡す（admin ログインと同方式）。
    let csrf_id = uuid::Uuid::new_v4().simple().to_string();
    let csrf = portal_csrf_token(&csrf_id, state.config.csrf_secret());
    let csrf_cookie = cookies::build(
        cookies::PORTAL_CSRF_COOKIE,
        &csrf_id,
        PORTAL_CSRF_TTL_SECS,
        state.config.cookie_secure(),
    );
    (
        AppendHeaders([(header::SET_COOKIE, csrf_cookie)]),
        Html(render(&PortalLogin {
            messages: &messages,
            tenant_prefix: &tenant.prefix(),
            csrf: &csrf,
            error_key: None,
        })),
    )
        .into_response()
}

/// ポータルのログイン実行（`POST /{tenant_id}/login`、`auth_session_id` 無し）。
pub async fn login(
    state: &WebState,
    correlation: &CorrelationId,
    tenant: &WebTenant,
    headers: &HeaderMap,
    form: LoginForm,
) -> Response {
    // CSRF 検証（Cookie の種からトークンを再計算して照合）。
    let csrf_id = cookies::get(headers, cookies::PORTAL_CSRF_COOKIE);
    let csrf_ok = csrf_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|id| portal_csrf_token(id, state.config.csrf_secret()) == form.csrf_token)
        .unwrap_or(false);
    if !csrf_ok {
        let messages = Messages::new(locale(headers));
        return (
            StatusCode::BAD_REQUEST,
            Html(render_login_form(
                &messages,
                &tenant.prefix(),
                "",
                Some("login-error-csrf"),
            )),
        )
            .into_response();
    }
    let csrf = portal_csrf_token(&csrf_id.unwrap_or_default(), state.config.csrf_secret());

    let ctx = forwarded_context(headers, correlation);
    let request = InternalPortalAuthenticateRequest {
        tenant_id: Some(tenant.0.clone()),
        username: form.username,
        password: form.password,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let outcome = match state
        .api
        .authenticate_portal(&ctx.correlation_id, &request)
        .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "portal authenticate call to api failed");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    let messages = Messages::new(locale(headers));
    let secure = state.config.cookie_secure();
    match outcome {
        InternalPortalAuthenticateResponse::Success {
            sso_session_id,
            sso_absolute_ttl_secs,
            user_language,
        } => sso_success_response(
            &sso_session_id,
            sso_absolute_ttl_secs,
            user_language.as_deref(),
            tenant,
            secure,
            &[cookies::PORTAL_CSRF_COOKIE],
        ),
        InternalPortalAuthenticateResponse::MfaRequired { mfa_ticket } => {
            // `mfa_ticket` を Cookie 化して TOTP 入力画面へ。portal_csrf Cookie は MFA フォームで再利用する。
            let ticket_cookie = cookies::build(
                cookies::PORTAL_MFA_COOKIE,
                &mfa_ticket,
                PORTAL_MFA_TTL_SECS,
                secure,
            );
            (
                AppendHeaders([(header::SET_COOKIE, ticket_cookie)]),
                found(&format!("{}/login/mfa", tenant.prefix())),
            )
                .into_response()
        }
        InternalPortalAuthenticateResponse::EmailVerificationRequired => message_page(
            &messages,
            "login-error-email-not-verified",
            StatusCode::FORBIDDEN,
        ),
        InternalPortalAuthenticateResponse::PasswordChangeRequired { username } => {
            // 強制パスワード変更（ADR-0009 §5）。管理コンソールと同じ共有画面を流用し、SSO はまだ
            // 発行しない。portal_csrf Cookie は維持し、変更フォームへ同じ csrf を埋め込む。
            Html(render_password_change_form(
                &messages,
                &tenant.prefix(),
                &csrf,
                &username,
                None,
            ))
            .into_response()
        }
        InternalPortalAuthenticateResponse::RateLimited => reshow_login(
            &messages,
            &tenant.prefix(),
            StatusCode::TOO_MANY_REQUESTS,
            &csrf,
            "login-error-rate-limited",
        ),
        InternalPortalAuthenticateResponse::InvalidCredentials => reshow_login(
            &messages,
            &tenant.prefix(),
            StatusCode::UNAUTHORIZED,
            &csrf,
            "login-error-invalid-credentials",
        ),
        InternalPortalAuthenticateResponse::Locked => reshow_login(
            &messages,
            &tenant.prefix(),
            StatusCode::FORBIDDEN,
            &csrf,
            "login-error-locked",
        ),
        InternalPortalAuthenticateResponse::Internal => {
            (StatusCode::INTERNAL_SERVER_ERROR, Html(String::new())).into_response()
        }
    }
}

/// ポータルの強制パスワード変更ページ（`GET /{tenant_id}/login/password-change`、ADR-0009 §5）。
/// ブックマーク・再読込対策として直接アクセスはログイン画面へ誘導する（本人性は `POST /login` からの
/// フォーム遷移で確認済みの username を要するため、GET 単独では変更を開始できない。管理コンソールと同方式）。
pub async fn password_change_page(Extension(tenant): Extension<WebTenant>) -> Response {
    found(&format!("{}/login", tenant.prefix()))
}

/// ポータルの強制パスワード変更の実行（`POST /{tenant_id}/login/password-change`、ADR-0009 §5）。
/// 成功時は SSO Cookie を発行してアカウント画面へ 302 する（管理コンソールと同じ共有画面を流用）。
pub async fn password_change(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<ForcedPasswordChangeForm>,
) -> Response {
    let secure = state.config.cookie_secure();

    // CSRF 検証（ログイン時と同じ portal_csrf の種で照合する）。
    let csrf_id = cookies::get(&headers, cookies::PORTAL_CSRF_COOKIE);
    let csrf_ok = csrf_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|id| portal_csrf_token(id, state.config.csrf_secret()) == form.csrf_token)
        .unwrap_or(false);
    if !csrf_ok {
        let messages = Messages::new(locale(&headers));
        return (
            StatusCode::BAD_REQUEST,
            Html(render_password_change_form(
                &messages,
                &tenant.prefix(),
                "",
                &form.username,
                Some("login-error-csrf"),
            )),
        )
            .into_response();
    }
    let csrf = portal_csrf_token(&csrf_id.unwrap_or_default(), state.config.csrf_secret());

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

    let ctx = forwarded_context(&headers, &correlation);
    let request = InternalPortalChangePasswordRequest {
        tenant_id: Some(tenant.0.clone()),
        username: form.username.clone(),
        current_password: form.current_password,
        new_password: form.new_password,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let outcome = match state
        .api
        .authenticate_portal_change_password(&ctx.correlation_id, &request)
        .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "portal change-password call to api failed");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    let messages = Messages::new(locale(&headers));
    match outcome {
        InternalPortalChangePasswordResponse::Success {
            sso_session_id,
            sso_absolute_ttl_secs,
            user_language,
        } => sso_success_response(
            &sso_session_id,
            sso_absolute_ttl_secs,
            user_language.as_deref(),
            &tenant,
            secure,
            &[cookies::PORTAL_CSRF_COOKIE],
        ),
        InternalPortalChangePasswordResponse::MfaRequired { mfa_ticket } => {
            // パスワード変更成功・MFA 必要（MFA ゲート）: `mfa_ticket` を Cookie 化して TOTP 入力画面へ。
            // portal_csrf Cookie は MFA フォームで再利用する（login の MfaRequired と同方式）。
            let ticket_cookie = cookies::build(
                cookies::PORTAL_MFA_COOKIE,
                &mfa_ticket,
                PORTAL_MFA_TTL_SECS,
                secure,
            );
            (
                AppendHeaders([(header::SET_COOKIE, ticket_cookie)]),
                found(&format!("{}/login/mfa", tenant.prefix())),
            )
                .into_response()
        }
        InternalPortalChangePasswordResponse::EmailVerificationRequired => message_page(
            &messages,
            "login-error-email-not-verified",
            StatusCode::FORBIDDEN,
        ),
        InternalPortalChangePasswordResponse::RateLimited => reshow_password_change(
            &messages,
            &tenant.prefix(),
            StatusCode::TOO_MANY_REQUESTS,
            &csrf,
            &form.username,
            "login-error-rate-limited",
        ),
        InternalPortalChangePasswordResponse::InvalidCredentials => reshow_password_change(
            &messages,
            &tenant.prefix(),
            StatusCode::UNAUTHORIZED,
            &csrf,
            &form.username,
            "password-change-error-invalid-current",
        ),
        InternalPortalChangePasswordResponse::Locked => reshow_password_change(
            &messages,
            &tenant.prefix(),
            StatusCode::FORBIDDEN,
            &csrf,
            &form.username,
            "login-error-locked",
        ),
        InternalPortalChangePasswordResponse::WeakPassword => reshow_password_change(
            &messages,
            &tenant.prefix(),
            StatusCode::UNPROCESSABLE_ENTITY,
            &csrf,
            &form.username,
            "password-change-error-weak",
        ),
        InternalPortalChangePasswordResponse::Internal => {
            (StatusCode::INTERNAL_SERVER_ERROR, Html(String::new())).into_response()
        }
    }
}

/// ポータルの TOTP 入力ページ（`GET /{tenant_id}/login/mfa`）。`mfa_ticket` Cookie が必要。
pub async fn mfa_page(
    State(state): State<WebState>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
) -> Response {
    // チケットが無ければログインからやり直し。
    if cookies::get(&headers, cookies::PORTAL_MFA_COOKIE).is_none() {
        return found(&format!("{}/login", tenant.prefix()));
    }
    let messages = Messages::new(locale(&headers));
    let csrf_id = cookies::get(&headers, cookies::PORTAL_CSRF_COOKIE).unwrap_or_default();
    let csrf = portal_csrf_token(&csrf_id, state.config.csrf_secret());
    Html(render(&PortalMfa {
        messages: &messages,
        tenant_prefix: &tenant.prefix(),
        csrf: &csrf,
        error_key: None,
    }))
    .into_response()
}

/// ポータルの TOTP 検証（`POST /{tenant_id}/login/mfa`）。
pub async fn mfa_submit(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<PortalTotpForm>,
) -> Response {
    // 注: `Messages`（FluentBundle）は !Send のため、api の await をまたいで保持しない
    //（各分岐で必要時に生成する）。
    let secure = state.config.cookie_secure();

    let csrf_id = cookies::get(&headers, cookies::PORTAL_CSRF_COOKIE);
    let csrf_ok = csrf_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|id| portal_csrf_token(id, state.config.csrf_secret()) == form.csrf_token)
        .unwrap_or(false);
    if !csrf_ok {
        let messages = Messages::new(locale(&headers));
        let csrf = portal_csrf_token(&csrf_id.unwrap_or_default(), state.config.csrf_secret());
        return reshow_mfa(
            &messages,
            &tenant.prefix(),
            StatusCode::BAD_REQUEST,
            &csrf,
            "login-error-csrf",
        );
    }
    let csrf = portal_csrf_token(&csrf_id.unwrap_or_default(), state.config.csrf_secret());

    let Some(mfa_ticket) = cookies::get(&headers, cookies::PORTAL_MFA_COOKIE) else {
        return found(&format!("{}/login", tenant.prefix()));
    };

    let ctx = forwarded_context(&headers, &correlation);
    let request = InternalPortalMfaRequest {
        tenant_id: Some(tenant.0.clone()),
        mfa_ticket,
        totp_code: form.totp_code,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let outcome = match state
        .api
        .authenticate_portal_mfa(&ctx.correlation_id, &request)
        .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "portal mfa call to api failed");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    // await 後に Messages を生成する（!Send を await にまたがせない）。
    let messages = Messages::new(locale(&headers));
    match outcome {
        InternalPortalMfaResponse::Success {
            sso_session_id,
            sso_absolute_ttl_secs,
            user_language,
        } => sso_success_response(
            &sso_session_id,
            sso_absolute_ttl_secs,
            user_language.as_deref(),
            &tenant,
            secure,
            &[cookies::PORTAL_CSRF_COOKIE, cookies::PORTAL_MFA_COOKIE],
        ),
        InternalPortalMfaResponse::InvalidCode => reshow_mfa(
            &messages,
            &tenant.prefix(),
            StatusCode::UNAUTHORIZED,
            &csrf,
            "mfa-error-invalid-code",
        ),
        // チケット切れ・レート制限はログインからやり直させる（チケット Cookie を失効）。
        InternalPortalMfaResponse::TicketExpired | InternalPortalMfaResponse::RateLimited => {
            let expire = cookies::expire(cookies::PORTAL_MFA_COOKIE, secure);
            (
                AppendHeaders([(header::SET_COOKIE, expire)]),
                found(&format!("{}/login", tenant.prefix())),
            )
                .into_response()
        }
        InternalPortalMfaResponse::Internal => {
            (StatusCode::INTERNAL_SERVER_ERROR, Html(String::new())).into_response()
        }
    }
}

/// エンドユーザーのログアウト（`POST /{tenant_id}/logout`）。api で SSO を失効させ、Cookie を失効して
/// ログイン画面へ 302 する。
pub async fn logout(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
) -> Response {
    let ctx = forwarded_context(&headers, &correlation);
    if let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) {
        let _ = state
            .api
            .logout(
                &ctx.correlation_id,
                &idp_contracts::auth::InternalLogoutRequest {
                    tenant_id: Some(tenant.0.clone()),
                    sso_session_id: sso,
                    ip_address: ctx.ip_address,
                    user_agent: ctx.user_agent,
                },
            )
            .await;
    }
    let expire = cookies::expire(cookies::SSO_SESSION_COOKIE, state.config.cookie_secure());
    (
        AppendHeaders([(header::SET_COOKIE, expire)]),
        found(&format!("{}/login", tenant.prefix())),
    )
        .into_response()
}

/// SSO Cookie を発行し、任意の一時 Cookie を失効させてアカウント画面へ 302 する共通処理。
fn sso_success_response(
    sso_session_id: &str,
    sso_absolute_ttl_secs: u64,
    user_language: Option<&str>,
    tenant: &WebTenant,
    secure: bool,
    expire_cookies: &[&str],
) -> Response {
    let mut set_cookies: Vec<(header::HeaderName, String)> = Vec::new();
    set_cookies.push((
        header::SET_COOKIE,
        cookies::build(
            cookies::SSO_SESSION_COOKIE,
            sso_session_id,
            sso_absolute_ttl_secs,
            secure,
        ),
    ));
    for name in expire_cookies {
        set_cookies.push((header::SET_COOKIE, cookies::expire(name, secure)));
    }
    // ユーザーの DB 言語設定があれば lang Cookie に同期する（MT20: DB > Cookie）。
    if let Some(lang) = user_language.and_then(Locale::from_tag) {
        set_cookies.push((
            header::SET_COOKIE,
            cookies::build(
                cookies::LANG_COOKIE,
                lang.as_tag(),
                cookies::LANG_COOKIE_MAX_AGE_SECS,
                secure,
            ),
        ));
    }
    (
        AppendHeaders(set_cookies),
        found(&format!("{}/settings", tenant.prefix())),
    )
        .into_response()
}

fn render_login_form(
    messages: &Messages,
    tenant_prefix: &str,
    csrf: &str,
    error_key: Option<&str>,
) -> String {
    render(&PortalLogin {
        messages,
        tenant_prefix,
        csrf,
        error_key,
    })
}

/// 強制パスワード変更フォームの HTML を共有テンプレート（[`ForcedPasswordChange`]）から描画する。
/// 送信先はポータルの `POST /{tenant_id}/login/password-change`（管理コンソールは別 action）。
fn render_password_change_form(
    messages: &Messages,
    tenant_prefix: &str,
    csrf: &str,
    username: &str,
    error_key: Option<&str>,
) -> String {
    render(&ForcedPasswordChange {
        messages,
        action: &format!("{tenant_prefix}/login/password-change"),
        csrf,
        username,
        error_key,
    })
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

fn reshow_mfa(
    messages: &Messages,
    tenant_prefix: &str,
    status: StatusCode,
    csrf: &str,
    error_key: &str,
) -> Response {
    (
        status,
        Html(render(&PortalMfa {
            messages,
            tenant_prefix,
            csrf,
            error_key: Some(error_key),
        })),
    )
        .into_response()
}

fn message_page(messages: &Messages, key: &str, status: StatusCode) -> Response {
    let body = render(&MessagePage {
        title: messages.get("portal-login-title"),
        message: messages.get(key),
    });
    (status, Html(body)).into_response()
}
