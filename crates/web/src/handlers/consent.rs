//! 同意画面（`GET /consent`）と同意処理（`POST /consent`、F3）。
//!
//! ADR-0007: web はフォーム描画とリダイレクトのみを担い、同意の記録・code 発行は api の
//! `/internal/consent-info`・`/internal/consent/approve`・`/internal/consent/deny` に委ねる。

use super::locale;
use crate::client_ip::ClientIp;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::dto::ConsentForm;
use crate::handlers::{forwarded_context, see_other};
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, ConsentTemplate, MessagePage};
use crate::tenant::WebTenant;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use idp_contracts::auth::{
    InternalConsentApproveRequest, InternalConsentApproveResponse, InternalConsentDenyRequest,
    InternalConsentDenyResponse, InternalConsentInfoResponse,
};
use idp_contracts::csrf::consent_csrf_token;

/// 同意画面を表示する。`auth_session_id` Cookie（`/authorize` ハンドオフの受領時またはログイン成功時に
/// web が発行した host-only Cookie。ADR-0018 決定 2）が必要。
pub async fn consent_page(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
) -> Response {
    let Some(auth_session_id) = cookies::get(&headers, cookies::AUTH_SESSION_COOKIE) else {
        let messages = Messages::new(locale(&headers));
        return error_page(
            &messages,
            StatusCode::BAD_REQUEST,
            "consent-error-session-expired",
        );
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
            let csrf = consent_csrf_token(&session_id, state.config.csrf_secret());
            Html(render(&ConsentTemplate {
                messages: &messages,
                csrf: &csrf,
                auth_session_id: &session_id,
                client_name: &client_name,
                requested_scopes: &requested_scopes,
            }))
            .into_response()
        }
        Ok(InternalConsentInfoResponse::SessionExpired) => error_page(
            &messages,
            StatusCode::BAD_REQUEST,
            "consent-error-session-expired",
        ),
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
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<ConsentForm>,
) -> Response {
    let ctx = forwarded_context(&headers, &correlation, &client_ip);

    // 同意はフォーム値ではなく **Cookie の `auth_session_id`** に対して行う（SEC12）。
    // フォーム値だけで動かしていたため、攻撃者が用意した認可セッションの id をフォームに
    // 仕込んで踏ませれば、被害者のブラウザに「攻撃者のフローへの同意」を出せた。
    // Cookie を権威にし、フォーム値はそれと一致する場合だけ受け付ける（値の運搬経路が 2 つある
    // ことを利用した取り違えを塞ぐ）。
    let Some(auth_session_id) = cookies::get(&headers, cookies::AUTH_SESSION_COOKIE) else {
        let messages = Messages::new(locale(&headers));
        return error_page(
            &messages,
            StatusCode::BAD_REQUEST,
            "consent-error-session-expired",
        );
    };
    if !idp_contracts::csrf::verify(&auth_session_id, &form.auth_session_id) {
        tracing::warn!(
            correlation_id = %ctx.correlation_id,
            "consent rejected: form auth_session_id does not match the cookie"
        );
        return see_other(&format!("{}/consent", tenant.prefix()));
    }

    // CSRF チェック（FluentBundle を await 前に使わないよう先に行う）。
    let expected_csrf = consent_csrf_token(&auth_session_id, state.config.csrf_secret());
    if !idp_contracts::csrf::verify(&expected_csrf, &form.csrf_token) {
        // PRG: 303 で同意画面の GET へ付け替え、新しいトークンのフォームを自動で再表示する
        //（従来はエラーページを返すだけで、リロードすると POST が再送されて復帰できなかった）。
        tracing::warn!(
            correlation_id = %ctx.correlation_id,
            "consent failed: csrf token mismatch; redirecting to fresh consent form"
        );
        return see_other(&format!("{}/consent", tenant.prefix()));
    }

    if form.action == "approve" {
        let req = InternalConsentApproveRequest {
            tenant_id: Some(tenant.0.clone()),
            auth_session_id: auth_session_id.clone(),
            ip_address: ctx.ip_address,
            user_agent: ctx.user_agent,
        };
        let result = state.api.consent_approve(&ctx.correlation_id, &req).await;
        let messages = Messages::new(locale(&headers));
        match result {
            Ok(InternalConsentApproveResponse::Success {
                redirect_to,
                form_post,
            }) => {
                let set_cookies = state
                    .set_cookies()
                    .expire_session(cookies::AUTH_SESSION_COOKIE);
                (
                    set_cookies.into_headers(),
                    crate::authorization_response::respond(&messages, &redirect_to, form_post),
                )
                    .into_response()
            }
            Ok(InternalConsentApproveResponse::SessionExpired) => error_page(
                &messages,
                StatusCode::BAD_REQUEST,
                "consent-error-session-expired",
            ),
            Ok(InternalConsentApproveResponse::Internal) | Err(_) => {
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    } else {
        // deny
        let req = InternalConsentDenyRequest {
            tenant_id: Some(tenant.0.clone()),
            auth_session_id: auth_session_id.clone(),
            ip_address: ctx.ip_address,
            user_agent: ctx.user_agent,
        };
        let result = state.api.consent_deny(&ctx.correlation_id, &req).await;
        let messages = Messages::new(locale(&headers));
        match result {
            Ok(InternalConsentDenyResponse::Ok {
                redirect_to,
                form_post,
            }) => {
                let set_cookies = state
                    .set_cookies()
                    .expire_session(cookies::AUTH_SESSION_COOKIE);
                (
                    set_cookies.into_headers(),
                    crate::authorization_response::respond(&messages, &redirect_to, form_post),
                )
                    .into_response()
            }
            Ok(InternalConsentDenyResponse::SessionExpired) => error_page(
                &messages,
                StatusCode::BAD_REQUEST,
                "consent-error-session-expired",
            ),
            Ok(InternalConsentDenyResponse::Internal) | Err(_) => {
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

fn error_page(messages: &Messages, status: StatusCode, error_key: &str) -> Response {
    let body = render(&MessagePage {
        title: messages.get("consent-title"),
        message: messages.get(error_key),
    });
    (status, Html(body)).into_response()
}
