//! Account setup link screens (web. ADR-0062).
//!
//! Landing point of the one-time link handed out when an admin creates a user or reissues a password.
//! The person is not signed in yet, so **the token is the only proof of identity** (unauthenticated path;
//! same setup as resetting a forgotten password).
//!
//! - `GET /{tenant_id}/account-setup?token=...` — shows what can be done. ⚠ **Merely opening it does not
//!   consume it** (even if a chat preview bot fetches it first, the link stays alive).
//! - `POST /{tenant_id}/account-setup` — sets the password (same api as the reset).
//! - `POST /{tenant_id}/account-setup/passkey/begin|complete` — registers a passkey (from JS).
//! - `GET /{tenant_id}/account-setup/done` — completion view (landing point of passkey registration).
//!
//! The forms carry no CSRF token for the same reason as the reset screen — the screen has no session,
//! execution relies on possessing the token itself, and a third party forcing it gains no state change.

use super::locale;
use crate::client_ip::ClientIp;
use crate::correlation::CorrelationId;
use crate::handlers::forwarded_context;
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, AccountSetup};
use crate::tenant::WebTenant;
use assay_contracts::auth::{
    InternalAccountSetupDescribeRequest, InternalAccountSetupDescribeResponse,
    InternalAccountSetupPasskeyBeginRequest, InternalAccountSetupPasskeyBeginResponse,
    InternalAccountSetupPasskeyCompleteRequest, InternalAccountSetupPasskeyCompleteResponse,
    InternalPasswordResetCompleteRequest, InternalPasswordResetCompleteResponse,
};
use axum::extract::{Extension, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::{Form, Json};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct SetupQuery {
    pub token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PasswordForm {
    pub token: String,
    pub new_password: String,
    pub new_password_confirm: String,
}

#[derive(Debug, Deserialize)]
pub struct PasskeyBeginBody {
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct PasskeyCompleteBody {
    pub token: String,
    pub challenge_id: String,
    pub name: String,
    pub credential: serde_json::Value,
}

/// Screen opened from the link (`GET /{tenant_id}/account-setup`).
pub async fn setup_page(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<SetupQuery>,
) -> Response {
    // ⚠ `Messages` (the fluent bundle) is not `Send`, so **do not create it before awaiting the api**.
    // Doing so would hold it across the await, and the handler could no longer be used with axum.
    let token = query.token.unwrap_or_default();
    if token.is_empty() {
        let messages = Messages::new(locale(&headers));
        return view(&messages, &tenant, Fatal, "", None, false, None);
    }

    let request = InternalAccountSetupDescribeRequest {
        tenant_id: Some(tenant.0.clone()),
        token: token.clone(),
    };
    let described = state
        .api
        .account_setup_describe(&correlation.0, &request)
        .await;
    let messages = Messages::new(locale(&headers));
    match described {
        Ok(InternalAccountSetupDescribeResponse::Ok {
            email,
            allows_passkey,
            ..
        }) => view(
            &messages,
            &tenant,
            Open,
            &token,
            Some(&email),
            allows_passkey,
            None,
        ),
        Ok(InternalAccountSetupDescribeResponse::InvalidOrExpired) => {
            view(&messages, &tenant, Fatal, "", None, false, None)
        }
        _ => view(
            &messages,
            &tenant,
            Open,
            &token,
            None,
            false,
            Some("account-setup-error-internal"),
        ),
    }
}

/// Completion view (`GET /{tenant_id}/account-setup/done`). Landing point of passkey registration.
pub async fn done_page(Extension(tenant): Extension<WebTenant>, headers: HeaderMap) -> Response {
    let messages = Messages::new(locale(&headers));
    view(&messages, &tenant, Done, "", None, false, None)
}

/// Sets the password (`POST /{tenant_id}/account-setup`).
///
/// Uses the same api as the forgotten-password reset (tokens in the same table, so they pass as is). No
/// dedicated endpoint, so policy validation, session revocation and auditing are not duplicated.
pub async fn set_password(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<PasswordForm>,
) -> Response {
    if form.new_password != form.new_password_confirm {
        let messages = Messages::new(locale(&headers));
        return view(
            &messages,
            &tenant,
            Open,
            &form.token,
            None,
            true,
            Some("account-setup-error-mismatch"),
        );
    }

    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let request = InternalPasswordResetCompleteRequest {
        tenant_id: Some(tenant.0.clone()),
        token: form.token.clone(),
        new_password: form.new_password,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let completed = state
        .api
        .password_reset_complete(&ctx.correlation_id, &request)
        .await;
    let messages = Messages::new(locale(&headers));
    match completed {
        Ok(InternalPasswordResetCompleteResponse::Ok) => {
            view(&messages, &tenant, Done, "", None, false, None)
        }
        Ok(InternalPasswordResetCompleteResponse::InvalidOrExpired) => {
            view(&messages, &tenant, Fatal, "", None, false, None)
        }
        Ok(InternalPasswordResetCompleteResponse::WeakPassword { reason }) => view(
            &messages,
            &tenant,
            Open,
            &form.token,
            None,
            true,
            Some(super::password_rejection_key(
                reason,
                "account-setup-error-weak",
            )),
        ),
        _ => view(
            &messages,
            &tenant,
            Open,
            &form.token,
            None,
            true,
            Some("account-setup-error-internal"),
        ),
    }
}

/// Starts passkey registration (`POST /{tenant_id}/account-setup/passkey/begin`). Called from JS.
pub async fn passkey_begin(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    Json(body): Json<PasskeyBeginBody>,
) -> Response {
    let request = InternalAccountSetupPasskeyBeginRequest {
        tenant_id: Some(tenant.0.clone()),
        token: body.token,
    };
    match state
        .api
        .account_setup_passkey_begin(&correlation.0, &request)
        .await
    {
        Ok(response) => {
            let status = match response {
                InternalAccountSetupPasskeyBeginResponse::Ok { .. } => StatusCode::OK,
                _ => StatusCode::BAD_REQUEST,
            };
            (status, Json(response)).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "account setup passkey begin failed");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

/// Completes passkey registration (`POST /{tenant_id}/account-setup/passkey/complete`). Called from JS.
pub async fn passkey_complete(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Json(body): Json<PasskeyCompleteBody>,
) -> Response {
    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let request = InternalAccountSetupPasskeyCompleteRequest {
        tenant_id: Some(tenant.0.clone()),
        token: body.token,
        challenge_id: body.challenge_id,
        name: body.name,
        credential: body.credential,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    match state
        .api
        .account_setup_passkey_complete(&ctx.correlation_id, &request)
        .await
    {
        Ok(response) => {
            let status = match response {
                InternalAccountSetupPasskeyCompleteResponse::Ok => StatusCode::OK,
                _ => StatusCode::BAD_REQUEST,
            };
            (status, Json(response)).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "account setup passkey complete failed");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

/// Screen state. **When the link is dead (`Fatal`), the reason is not distinguished** (ADR-0062).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Open,
    Done,
    Fatal,
}
use Stage::{Done, Fatal, Open};

fn view(
    messages: &Messages,
    tenant: &WebTenant,
    stage: Stage,
    token: &str,
    email: Option<&str>,
    allows_passkey: bool,
    error_key: Option<&'static str>,
) -> Response {
    let status = match stage {
        Stage::Fatal => StatusCode::BAD_REQUEST,
        _ if error_key.is_some() => StatusCode::BAD_REQUEST,
        _ => StatusCode::OK,
    };
    let html = render(&AccountSetup {
        messages,
        tenant: &tenant.prefix(),
        token,
        email,
        allows_passkey,
        done: stage == Stage::Done,
        fatal_key: match stage {
            Stage::Fatal => Some("account-setup-error-invalid"),
            _ => None,
        },
        error_key,
    });
    (status, Html(html)).into_response()
}
