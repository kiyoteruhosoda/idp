//! 「アプリで続ける」と認証アプリの鍵の登録の画面（task #892。ADR-0077）。
//!
//! | 口 | 何をする |
//! |---|---|
//! | `POST /{t}/login/app/start` | 依頼を始め、このブラウザに依頼の印（Cookie）を置き、認証アプリを開く画面を出す |
//! | `GET /{t}/login/app/complete` | 認証アプリが開いたブラウザ。コードと印を api で照らし、合えばログイン |
//! | `GET・POST /{t}/settings/app-approver/confirm` | 認証アプリの Auth Tab が開く登録の確認（ログイン＋パスキー） |
//! | `POST /{t}/settings/security/revoke-approver-key` | 「端末」の欄の「認証アプリ」を取り消す |
//!
//! ⚠ 依頼を始めたタブは待つだけで、ここから完了させる口は作らない（`domain::app_approver`）。

use super::{api_internal_error, internal_call_status};
use crate::client_ip::ClientIp;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::{console_csrf_token, console_csrf_valid, login_csrf_valid};
use crate::handlers::{forwarded_context, found, locale, see_other, step_up};
use crate::i18n::{Locale, Messages};
use crate::state::WebState;
use crate::templates::{render, AppApprovalWaitPage, AppApproverConfirmPage, MessagePage};
use crate::tenant::WebTenant;
use assay_contracts::auth::{
    InternalAccountApproverConfirmResponse, InternalAccountApproverEnrollmentRequest,
    InternalAccountApproverEnrollmentResponse, InternalAccountRevokeApproverKeyRequest,
    InternalAccountRevokeApproverKeyResponse, InternalAppApprovalCompleteRequest,
    InternalAppApprovalCompleteResponse, InternalAppApprovalStartRequest,
    InternalAppApprovalStartResponse,
};
use axum::extract::{Extension, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

/// 受付・依頼の識別子の形（base64url の 43 文字）。戻り先に載せる前に確かめる。
pub(crate) fn is_enrollment_id(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// ⚠ `Messages`（FluentBundle）は `Send` でないので、ハンドラでは `await` をまたいで持たない。
/// 言語（`Locale`）だけを持ち、描く直前に作る。
fn message_page(locale: Locale, key: &str, status: StatusCode) -> Response {
    let messages = &Messages::new(locale);
    let body = render(&MessagePage {
        lang: messages.lang(),
        title: messages.get("app-approval-title"),
        message: messages.get(key),
    });
    (status, Html(body)).into_response()
}

/// 依頼の印・コードを含む URL を、外へ漏らさない（リファラーにもキャッシュにも残さない）。
fn private(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

fn country(state: &WebState, headers: &HeaderMap) -> Option<String> {
    if !state.config.trust_forwarded_headers() {
        return None;
    }
    headers
        .get("cf-ipcountry")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

// ─── ログイン画面 ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct StartForm {
    #[serde(default)]
    pub csrf_token: String,
}

/// 「アプリで続ける」（`POST /{tenant_id}/login/app/start`）。
///
/// 認可の途中のログイン画面からだけ来る（ログイン画面の CSRF トークンで確かめる）。
pub async fn start(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<StartForm>,
) -> Response {
    let loc = locale(&headers);
    if !state.config.app_approver_enabled() {
        return message_page(loc, "app-approval-error-unavailable", StatusCode::NOT_FOUND);
    }
    let Some(auth_session_id) = cookies::get(&headers, cookies::AUTH_SESSION_COOKIE) else {
        return message_page(loc, "app-approval-error-restart", StatusCode::BAD_REQUEST);
    };
    if !login_csrf_valid(
        &auth_session_id,
        &form.csrf_token,
        state.config.csrf_secret(),
    ) {
        tracing::warn!(correlation_id = %correlation.0, "app approval start rejected: csrf token mismatch");
        return message_page(loc, "app-approval-error-restart", StatusCode::BAD_REQUEST);
    }
    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let request = InternalAppApprovalStartRequest {
        tenant_id: Some(tenant.0.clone()),
        auth_session_id: Some(auth_session_id),
        country: country(&state, &headers),
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    match state
        .api
        .app_approval_start(&ctx.correlation_id, &request)
        .await
    {
        Ok(InternalAppApprovalStartResponse::Started {
            request_id,
            browser_binding,
        }) => {
            let approve_url = format!(
                "{}/app/approve?tenant={}&request={}",
                state.config.issuer().trim_end_matches('/'),
                tenant.0,
                request_id
            );
            let messages = Messages::new(loc);
            let body = render(&AppApprovalWaitPage {
                messages: &messages,
                approve_url: &approve_url,
                tenant_prefix: &tenant.prefix(),
            });
            private(
                (
                    state
                        .set_cookies()
                        .set_local(
                            &state.origin_bound_cookie(cookies::APP_APPROVAL_BINDING_COOKIE),
                            &browser_binding,
                            cookies::APP_APPROVAL_BINDING_MAX_AGE_SECS,
                        )
                        .into_headers(),
                    Html(body),
                )
                    .into_response(),
            )
        }
        Ok(InternalAppApprovalStartResponse::Disabled) => {
            message_page(loc, "app-approval-error-unavailable", StatusCode::NOT_FOUND)
        }
        Ok(InternalAppApprovalStartResponse::RateLimited) => message_page(
            loc,
            "login-error-rate-limited",
            StatusCode::TOO_MANY_REQUESTS,
        ),
        Ok(InternalAppApprovalStartResponse::Internal) => api_internal_error("app_approval_start"),
        Err(e) => {
            tracing::error!(error = %e, "app approval start call to api failed");
            internal_call_status(&e).into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CompleteQuery {
    #[serde(default)]
    pub request: String,
    #[serde(default)]
    pub code: String,
}

/// 認証アプリが開いたブラウザ（`GET /{tenant_id}/login/app/complete`）。
pub async fn complete(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<CompleteQuery>,
) -> Response {
    let loc = locale(&headers);
    if !is_enrollment_id(&query.request) || query.code.is_empty() || query.code.len() > 64 {
        return private(message_page(
            loc,
            "app-approval-error-invalid",
            StatusCode::BAD_REQUEST,
        ));
    }
    let binding_cookie = state.origin_bound_cookie(cookies::APP_APPROVAL_BINDING_COOKIE);
    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let request = InternalAppApprovalCompleteRequest {
        tenant_id: Some(tenant.0.clone()),
        request_id: query.request,
        code: query.code,
        browser_binding: cookies::get(&headers, &binding_cookie),
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let outcome = match state
        .api
        .app_approval_complete(&ctx.correlation_id, &request)
        .await
    {
        Ok(outcome) => outcome,
        Err(e) => {
            tracing::error!(error = %e, "app approval complete call to api failed");
            return internal_call_status(&e).into_response();
        }
    };
    // 印は 1 回きり。成否にかかわらず消す。
    let set_cookies = state.set_cookies().expire_local(&binding_cookie);
    let response = match outcome {
        InternalAppApprovalCompleteResponse::Success {
            redirect_to,
            form_post,
            sso_session_id,
            sso_absolute_ttl_secs,
        } => {
            let destination =
                redirect_to.unwrap_or_else(|| format!("{}/settings", tenant.prefix()));
            (
                set_cookies
                    .set_session(
                        cookies::SSO_SESSION_COOKIE,
                        &sso_session_id,
                        sso_absolute_ttl_secs,
                    )
                    .expire_session(cookies::AUTH_SESSION_COOKIE)
                    .into_headers(),
                crate::authorization_response::respond(
                    &Messages::new(loc),
                    &destination,
                    form_post,
                ),
            )
                .into_response()
        }
        InternalAppApprovalCompleteResponse::ConsentRequired {
            auth_session_id,
            sso_session_id,
            sso_absolute_ttl_secs,
        } => (
            set_cookies
                .set_session(
                    cookies::SSO_SESSION_COOKIE,
                    &sso_session_id,
                    sso_absolute_ttl_secs,
                )
                .set_session(
                    cookies::AUTH_SESSION_COOKIE,
                    &auth_session_id,
                    state.config.auth_session_ttl_secs(),
                )
                .into_headers(),
            see_other(&format!("{}/consent", tenant.prefix())),
        )
            .into_response(),
        InternalAppApprovalCompleteResponse::ApplicationNotPermitted {
            application_name,
            sso_session_id,
            sso_absolute_ttl_secs,
        } => (
            set_cookies
                .set_session(
                    cookies::SSO_SESSION_COOKIE,
                    &sso_session_id,
                    sso_absolute_ttl_secs,
                )
                .expire_session(cookies::AUTH_SESSION_COOKIE)
                .into_headers(),
            crate::application_denied::page(
                &Messages::new(loc),
                &tenant.prefix(),
                &application_name,
            ),
        )
            .into_response(),
        InternalAppApprovalCompleteResponse::Invalid => (
            set_cookies.into_headers(),
            message_page(loc, "app-approval-error-invalid", StatusCode::BAD_REQUEST),
        )
            .into_response(),
        InternalAppApprovalCompleteResponse::AnotherBrowser => (
            set_cookies.into_headers(),
            message_page(
                loc,
                "app-approval-error-another-browser",
                StatusCode::FORBIDDEN,
            ),
        )
            .into_response(),
        InternalAppApprovalCompleteResponse::PolicyDenied => (
            set_cookies.into_headers(),
            message_page(loc, "login-error-policy-denied", StatusCode::FORBIDDEN),
        )
            .into_response(),
        InternalAppApprovalCompleteResponse::UserUnavailable => (
            set_cookies.into_headers(),
            message_page(
                loc,
                "app-approval-error-user-unavailable",
                StatusCode::FORBIDDEN,
            ),
        )
            .into_response(),
        InternalAppApprovalCompleteResponse::Internal => {
            api_internal_error("app_approval_complete")
        }
    };
    private(response)
}

// ─── 鍵の登録の確認（アカウント） ─────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ConfirmQuery {
    #[serde(default)]
    pub enrollment: String,
}

#[derive(Debug, Deserialize)]
pub struct ConfirmForm {
    #[serde(default)]
    pub enrollment: String,
    #[serde(default)]
    pub csrf_token: String,
    /// `register`（登録する）/ `cancel`（やめる）
    #[serde(default)]
    pub decision: String,
}

/// 認証アプリの Auth Tab が戻る先（`https://<発行者>/app/enrolled`）。
fn enrolled_url(state: &WebState, enrollment: &str, result: &str) -> String {
    format!(
        "{}/app/enrolled?enrollment={enrollment}&{result}",
        state.config.issuer().trim_end_matches('/')
    )
}

/// 登録の確認（`GET /{tenant_id}/settings/app-approver/confirm?enrollment=…`）。
pub async fn confirm_page(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<ConfirmQuery>,
) -> Response {
    let loc = locale(&headers);
    if !is_enrollment_id(&query.enrollment) {
        return message_page(
            loc,
            "app-approver-error-enrollment-gone",
            StatusCode::NOT_FOUND,
        );
    }
    let enrollment_cookie = state.origin_bound_cookie(cookies::APP_APPROVER_ENROLLMENT_COOKIE);
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        // まだログインしていない: 受付を覚えてログインへ。ログインの後にここへ戻す（portal）。
        return (
            state
                .set_cookies()
                .set_local(
                    &enrollment_cookie,
                    &query.enrollment,
                    cookies::APP_APPROVER_ENROLLMENT_MAX_AGE_SECS,
                )
                .into_headers(),
            found(&format!("{}/login", tenant.prefix())),
        )
            .into_response();
    };
    let request = InternalAccountApproverEnrollmentRequest {
        tenant_id: Some(tenant.0.clone()),
        sso_session_id: sso.clone(),
        enrollment_id: query.enrollment.clone(),
    };
    match state
        .api
        .account_approver_enrollment(&correlation.0, &request)
        .await
    {
        Ok(InternalAccountApproverEnrollmentResponse::Ready {
            device_name,
            security_level,
            created_at,
        }) => {
            let level_key = match security_level.as_str() {
                "strongbox" => "app-approver-level-strongbox",
                "tee" => "app-approver-level-tee",
                _ => "app-approver-level-software",
            };
            let messages = Messages::new(loc);
            let body = render(&AppApproverConfirmPage {
                messages: &messages,
                tenant_prefix: &tenant.prefix(),
                csrf: &console_csrf_token(&sso, state.config.csrf_secret()),
                enrollment: &query.enrollment,
                device_name: &device_name,
                level_key,
                created_at: &created_at,
            });
            // 「登録する」の送信は、発行者のホストの戻り先（`/app/enrolled`。Auth Tab がアプリへ返す）への
            // 302 で終わる。Chrome は `form-action` を送信の後のリダイレクトにも当てるので、この画面だけ
            // 戻り先のオリジンを許す（ログイン画面が RP のオリジンを許すのと同じ。SEC3）。
            let enrolled = enrolled_url(&state, &query.enrollment, "");
            private(
                (
                    state
                        .set_cookies()
                        .expire_local(&enrollment_cookie)
                        .into_headers(),
                    crate::security_headers::html_with_form_action_csp(&enrolled, body),
                )
                    .into_response(),
            )
        }
        Ok(InternalAccountApproverEnrollmentResponse::NotFound) => message_page(
            loc,
            "app-approver-error-enrollment-gone",
            StatusCode::NOT_FOUND,
        ),
        Ok(InternalAccountApproverEnrollmentResponse::SessionExpired) => (
            state
                .set_cookies()
                .set_local(
                    &enrollment_cookie,
                    &query.enrollment,
                    cookies::APP_APPROVER_ENROLLMENT_MAX_AGE_SECS,
                )
                .into_headers(),
            found(&format!("{}/login", tenant.prefix())),
        )
            .into_response(),
        Ok(InternalAccountApproverEnrollmentResponse::Internal) => {
            api_internal_error("approver_enrollment")
        }
        Err(e) => {
            tracing::error!(error = %e, "approver enrollment call to api failed");
            internal_call_status(&e).into_response()
        }
    }
}

/// 登録する・やめる（`POST /{tenant_id}/settings/app-approver/confirm`）。
///
/// **パスキーで確かめてから 5 分以内**だけ通す（端末の登録と同じ。まだなら本人確認の画面へ回し、
/// 戻ってきたら利用者がもう一度押す）。
pub async fn confirm(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<ConfirmForm>,
) -> Response {
    let loc = locale(&headers);
    if !is_enrollment_id(&form.enrollment) {
        return message_page(
            loc,
            "app-approver-error-enrollment-gone",
            StatusCode::NOT_FOUND,
        );
    }
    let page = format!(
        "{}/settings/app-approver/confirm?enrollment={}",
        tenant.prefix(),
        form.enrollment
    );
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{}/login", tenant.prefix()));
    };
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        tracing::warn!(correlation_id = %correlation.0, "approver confirmation rejected: csrf token mismatch");
        return see_other(&page);
    }
    if form.decision != "register" {
        // やめた: アプリへ「断られた」を返す（受付は 10 分で消える）。
        return private(found(&enrolled_url(
            &state,
            &form.enrollment,
            "error=denied",
        )));
    }
    if let Err(response) = step_up::require_step_up(
        &state,
        &correlation,
        &tenant,
        &headers,
        step_up::REGISTER_DEVICE,
        &page,
    )
    .await
    {
        return response;
    }
    let request = InternalAccountApproverEnrollmentRequest {
        tenant_id: Some(tenant.0.clone()),
        sso_session_id: sso,
        enrollment_id: form.enrollment.clone(),
    };
    match state
        .api
        .account_approver_confirm(&correlation.0, &request)
        .await
    {
        Ok(InternalAccountApproverConfirmResponse::Confirmed { code }) => private(found(
            &enrolled_url(&state, &form.enrollment, &format!("code={code}")),
        )),
        Ok(InternalAccountApproverConfirmResponse::PasskeyRequired) => see_other(&page),
        Ok(InternalAccountApproverConfirmResponse::NotFound) => message_page(
            loc,
            "app-approver-error-enrollment-gone",
            StatusCode::NOT_FOUND,
        ),
        Ok(InternalAccountApproverConfirmResponse::SessionExpired) => {
            found(&format!("{}/login", tenant.prefix()))
        }
        Ok(InternalAccountApproverConfirmResponse::Internal) => {
            api_internal_error("approver_confirm")
        }
        Err(e) => {
            tracing::error!(error = %e, "approver confirmation call to api failed");
            internal_call_status(&e).into_response()
        }
    }
}

// ─── 「端末」の欄の「認証アプリ」 ─────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RevokeKeyForm {
    pub key_id: String,
    pub csrf_token: String,
}

/// 認証アプリの鍵を取り消す（`POST /{tenant_id}/settings/security/revoke-approver-key`）。
///
/// その鍵で承認したログイン状態も切るので、端末の取り消しと同じく本人確認を挟む。
pub async fn revoke_key(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<RevokeKeyForm>,
) -> Response {
    let base = format!("{}/settings/security", tenant.prefix());
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{}/login", tenant.prefix()));
    };
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        tracing::warn!(correlation_id = %correlation.0, "approver key revocation rejected: csrf token mismatch");
        return see_other(&format!("{base}?error=csrf"));
    }
    if let Err(response) = step_up::require_step_up(
        &state,
        &correlation,
        &tenant,
        &headers,
        step_up::REVOKE_SESSION,
        &format!("{base}#devices"),
    )
    .await
    {
        return response;
    }
    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let request = InternalAccountRevokeApproverKeyRequest {
        tenant_id: Some(tenant.0.clone()),
        sso_session_id: sso,
        key_id: form.key_id,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    match state
        .api
        .account_revoke_approver_key(&ctx.correlation_id, &request)
        .await
    {
        Ok(InternalAccountRevokeApproverKeyResponse::Revoked { .. }) => {
            see_other(&format!("{base}?saved=approver-key-revoked#devices"))
        }
        Ok(InternalAccountRevokeApproverKeyResponse::NotFound) => {
            see_other(&format!("{base}?error=approver-key-not-found#devices"))
        }
        Ok(InternalAccountRevokeApproverKeyResponse::SessionExpired) => {
            found(&format!("{}/login", tenant.prefix()))
        }
        Ok(InternalAccountRevokeApproverKeyResponse::Internal) => {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "approver key revocation call to api failed");
            internal_call_status(&e).into_response()
        }
    }
}
