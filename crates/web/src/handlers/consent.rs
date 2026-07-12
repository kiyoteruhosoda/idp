//! 同意画面（`GET /consent`）と同意処理（`POST /consent`、F3）。
//!
//! ADR-0007: web はフォーム描画とリダイレクトのみを担い、同意の記録・code 発行は api の
//! `/internal/consent-info`・`/internal/consent/approve`・`/internal/consent/deny` に委ねる。

use crate::cookies;
use crate::correlation::CorrelationId;
use crate::dto::ConsentForm;
use crate::handlers::{forwarded_context, found};
use crate::i18n::{Locale, Messages};
use crate::state::WebState;
use crate::templates::{render, ConsentTemplate, MessagePage};
use crate::tenant::WebTenant;
use axum::extract::{Extension, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use idp_contracts::auth::{
    InternalConsentApproveRequest, InternalConsentApproveResponse, InternalConsentDenyRequest,
    InternalConsentDenyResponse, InternalConsentInfoResponse,
};
use idp_contracts::csrf::consent_csrf_token;

/// 同意画面を表示する。`auth_session_id` Cookie（`/authorize` または `/login` が発行）が必要。
pub async fn consent_page(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
) -> Response {
    let Some(auth_session_id) = cookies::get(&headers, cookies::AUTH_SESSION_COOKIE) else {
        let messages = Messages::new(locale(&headers));
        return error_page(&messages, StatusCode::BAD_REQUEST, "consent-error-session-expired");
    };

    // FluentBundle は Send でないため、await をまたがないようここで生成する。
    let result = state
        .api
        .consent_info(&correlation.0, &tenant.0, &auth_session_id)
        .await;
    let messages = Messages::new(locale(&headers));

    match result {
        Ok(InternalConsentInfoResponse::Ok {
            auth_session_id: session_id,
            client_name,
            client_id: _,
            requested_scopes,
        }) => {
            let csrf = consent_csrf_token(&session_id);
            Html(render(&ConsentTemplate {
                messages: &messages,
                csrf: &csrf,
                auth_session_id: &session_id,
                client_name: &client_name,
                requested_scopes: &requested_scopes,
            }))
            .into_response()
        }
        Ok(InternalConsentInfoResponse::SessionExpired) => {
            error_page(&messages, StatusCode::BAD_REQUEST, "consent-error-session-expired")
        }
        Err(e) => {
            tracing::error!(error = %e, "consent_page: api call failed");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

/// 同意フォームを処理する。`action` が `approve` なら同意付与、`deny` なら拒否。
pub async fn consent(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<ConsentForm>,
) -> Response {
    let ctx = forwarded_context(&headers, &correlation);
    let secure = state.config.cookie_secure();

    // CSRF チェック（FluentBundle を await 前に使わないよう先に行う）。
    let expected_csrf = consent_csrf_token(&form.auth_session_id);
    if form.csrf_token != expected_csrf {
        let messages = Messages::new(locale(&headers));
        return error_page(&messages, StatusCode::BAD_REQUEST, "consent-error-csrf");
    }

    if form.action == "approve" {
        let req = InternalConsentApproveRequest {
            tenant_id: Some(tenant.0.clone()),
            auth_session_id: form.auth_session_id.clone(),
            ip_address: ctx.ip_address,
            user_agent: ctx.user_agent,
        };
        let result = state.api.consent_approve(&ctx.correlation_id, &req).await;
        let messages = Messages::new(locale(&headers));
        match result {
            Ok(InternalConsentApproveResponse::Success { redirect_to }) => {
                let expire_auth = cookies::expire(cookies::AUTH_SESSION_COOKIE, secure);
                (
                    [(header::SET_COOKIE, expire_auth)],
                    found(&redirect_to),
                )
                    .into_response()
            }
            Ok(InternalConsentApproveResponse::SessionExpired) => {
                error_page(&messages, StatusCode::BAD_REQUEST, "consent-error-session-expired")
            }
            Ok(InternalConsentApproveResponse::Internal) | Err(_) => {
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    } else {
        // deny
        let req = InternalConsentDenyRequest {
            tenant_id: Some(tenant.0.clone()),
            auth_session_id: form.auth_session_id.clone(),
            ip_address: ctx.ip_address,
            user_agent: ctx.user_agent,
        };
        let result = state.api.consent_deny(&ctx.correlation_id, &req).await;
        let messages = Messages::new(locale(&headers));
        match result {
            Ok(InternalConsentDenyResponse::Ok { redirect_to }) => {
                let expire_auth = cookies::expire(cookies::AUTH_SESSION_COOKIE, secure);
                (
                    [(header::SET_COOKIE, expire_auth)],
                    found(&redirect_to),
                )
                    .into_response()
            }
            Ok(InternalConsentDenyResponse::SessionExpired) => {
                error_page(&messages, StatusCode::BAD_REQUEST, "consent-error-session-expired")
            }
            Ok(InternalConsentDenyResponse::Internal) | Err(_) => {
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

fn locale(headers: &HeaderMap) -> Locale {
    Locale::from_accept_language(
        headers
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok()),
    )
}

fn error_page(messages: &Messages, status: StatusCode, error_key: &str) -> Response {
    let body = render(&MessagePage {
        title: messages.get("consent-title"),
        message: messages.get(error_key),
    });
    (status, Html(body)).into_response()
}
