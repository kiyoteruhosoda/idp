//! SAML SSO endpoint (`GET/POST /{tenant_id}/saml/sso`) and resume API
//! (`POST /internal/saml/resume`).
//!
//! Implements the SingleSignOnService advertised by the metadata ([`super::discovery::saml_idp_metadata`]).
//! Does not read or write browser cookies; hands off to web with the same single-use, short-lived handle as
//! OIDC's `/authorize` (ADR-0018 decision 2). SSO decisions and response issuance happen in `/internal/saml/resume`
//! called by web, and web renders the auto-POST form to the ACS.

use crate::application::audit::RequestContext;
use crate::application::saml_sso::{
    SamlBeginCommand, SamlBeginOutcome, SamlResumeCommand, SamlResumeOutcome, SamlSsoBinding,
};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::handlers::{found, request_context};
use crate::presentation::state::AppState;
use crate::presentation::tenant::{require_internal_tenant, ResolvedTenant};
use assay_contracts::auth::{InternalSamlResumeRequest, InternalSamlResumeResponse};
use axum::extract::{Extension, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};

/// Query parameters of the HTTP-Redirect binding (SAML Bindings §3.4; parameter names are capitalized).
#[derive(Debug, Deserialize, IntoParams)]
pub struct SamlSsoQuery {
    #[serde(rename = "SAMLRequest")]
    pub saml_request: Option<String>,
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
}

/// Form parameters of the HTTP-POST binding (SAML Bindings §3.5).
#[derive(Debug, Deserialize, ToSchema)]
pub struct SamlSsoForm {
    #[serde(rename = "SAMLRequest")]
    pub saml_request: Option<String>,
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
}

/// SAML SSO (HTTP-Redirect binding). Validates the AuthnRequest and 302s to web's
/// `/saml/continue` with a single-use handle.
#[utoipa::path(
    get,
    path = "/{tenant_id}/saml/sso",
    tag = "saml",
    params(SamlSsoQuery),
    responses(
        (status = 302, description = "web の /saml/continue（単回ハンドル付き）へリダイレクト"),
        (status = 400, description = "AuthnRequest が不正（未登録 SP・ACS 不一致・解析失敗）"),
    )
)]
pub async fn sso_redirect(
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    Extension(correlation): Extension<CorrelationId>,
    headers: HeaderMap,
    Query(query): Query<SamlSsoQuery>,
) -> Response {
    begin(
        state,
        tenant,
        correlation,
        headers,
        SamlSsoBinding::Redirect,
        query.saml_request,
        query.relay_state,
    )
    .await
}

/// SAML SSO (HTTP-POST binding). Behaves the same as the Redirect binding.
#[utoipa::path(
    post,
    path = "/{tenant_id}/saml/sso",
    tag = "saml",
    request_body(content = SamlSsoForm, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 302, description = "web の /saml/continue（単回ハンドル付き）へリダイレクト"),
        (status = 400, description = "AuthnRequest が不正（未登録 SP・ACS 不一致・解析失敗）"),
    )
)]
pub async fn sso_post(
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    Extension(correlation): Extension<CorrelationId>,
    headers: HeaderMap,
    Form(form): Form<SamlSsoForm>,
) -> Response {
    begin(
        state,
        tenant,
        correlation,
        headers,
        SamlSsoBinding::Post,
        form.saml_request,
        form.relay_state,
    )
    .await
}

async fn begin(
    state: AppState,
    tenant: ResolvedTenant,
    correlation: CorrelationId,
    headers: HeaderMap,
    binding: SamlSsoBinding,
    saml_request: Option<String>,
    relay_state: Option<String>,
) -> Response {
    let Some(saml_request) = saml_request.filter(|s| !s.is_empty()) else {
        // Protocol errors are fixed English text for RP (SP) developers (CLAUDE.md "翻訳の対象外").
        return (StatusCode::BAD_REQUEST, "SAMLRequest is required").into_response();
    };
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let outcome = state
        .saml_sso
        .begin(
            tenant.context(),
            SamlBeginCommand {
                binding,
                saml_request,
                relay_state,
            },
            &ctx,
        )
        .await;
    match outcome {
        // web renders the login and auto-POST forms. On receipt web immediately exchanges the handle
        // and strips it from the URL (single-use, short-lived; ADR-0018 decisions 2, 3).
        SamlBeginOutcome::HandoffToWeb { handle } => found(&format!(
            "{}/{}/saml/continue?handle={}",
            state.config.public_web_base_url(),
            tenant.id(),
            handle
        )),
        SamlBeginOutcome::BadRequest { reason } => {
            (StatusCode::BAD_REQUEST, reason).into_response()
        }
        SamlBeginOutcome::Internal(e) => {
            tracing::error!(error = %e, "SAML SSO begin failed with internal error");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Resumes the SAML SSO flow (`POST /internal/saml/resume`).
///
/// web forwards the handle (first time) or `saml_request_id` (after login) and the value of its own domain's
/// host-only `sso_session_id` cookie. If SSO is valid, returns a signed SAML Response.
pub async fn saml_resume(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalSamlResumeRequest>,
) -> Result<Json<InternalSamlResumeResponse>, Response> {
    // Client connection info is forwarded by web (the api is not directly behind the proxy, so it doesn't read X-Forwarded-For itself).
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .saml_sso
        .resume(
            tenant,
            SamlResumeCommand {
                handle: req.handle,
                saml_request_id: req.saml_request_id,
                sso_session_id: req.sso_session_id,
            },
            &ctx,
        )
        .await;
    Ok(Json(match outcome {
        SamlResumeOutcome::Completed {
            acs_url,
            saml_response,
            relay_state,
        } => InternalSamlResumeResponse::Completed {
            acs_url,
            saml_response,
            relay_state,
        },
        SamlResumeOutcome::LoginRequired { saml_request_id } => {
            InternalSamlResumeResponse::LoginRequired { saml_request_id }
        }
        SamlResumeOutcome::ApplicationNotPermitted { application_name } => {
            InternalSamlResumeResponse::ApplicationNotPermitted { application_name }
        }
        SamlResumeOutcome::Expired => InternalSamlResumeResponse::Expired,
        SamlResumeOutcome::Internal(e) => {
            tracing::error!(error = %e, "SAML resume failed with internal error");
            InternalSamlResumeResponse::Internal
        }
    }))
}
