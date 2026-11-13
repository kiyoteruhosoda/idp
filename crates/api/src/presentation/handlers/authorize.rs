//! Authorization endpoint (`GET /authorize`, design spec §4.2, ADR-0018 decision 2).

use crate::application::audit::RequestContext;
use crate::application::authorize::{
    AuthorizeOutcome, ContinueCommand, LoginContextOutcome, ResumeCommand, ResumeOutcome,
};
use crate::domain::authorization_request::AuthorizationParameters;
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::{AuthorizeParams, OAuthErrorResponse};
use crate::presentation::handlers::found;
use crate::presentation::state::AppState;
use crate::presentation::tenant::{require_internal_tenant, ResolvedTenant};
use assay_contracts::auth::{
    InternalAuthorizeContinueRequest, InternalAuthorizeLoginContextRequest,
    InternalAuthorizeLoginContextResponse, InternalAuthorizeResumeRequest,
    InternalAuthorizeResumeResponse,
};
use axum::extract::{Extension, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

/// OIDC authorization endpoint. Does not read or write browser cookies (ADR-0018 decision 2).
/// On successful validation it creates an AuthSession and 302s to web's `/login` with a single-use, short-lived handle in the URL.
/// SSO restoration and evaluation of `prompt` / `max_age` happen in `/internal/authorize/resume`, called by web.
#[utoipa::path(
    get,
    path = "/{tenant_id}/authorize",
    tag = "oidc",
    params(AuthorizeParams),
    responses(
        (status = 302, description = "redirect_uri（error 付与）または web の /login（単回ハンドル付き）へリダイレクト"),
        (status = 400, description = "client_id / redirect_uri が無効（リダイレクトしない）", body = OAuthErrorResponse),
    )
)]
pub async fn authorize(
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    Query(params): Query<AuthorizeParams>,
) -> Response {
    // Silent round trips (no screen shown) are opened by each app in a hidden frame (task #888, ADR-0076)
    let silent = params.prompt.as_deref() == Some("none");
    let request = AuthorizationParameters {
        response_type: params.response_type,
        client_id: params.client_id,
        redirect_uri: params.redirect_uri,
        scope: params.scope,
        state: params.state,
        nonce: params.nonce,
        code_challenge: params.code_challenge,
        code_challenge_method: params.code_challenge_method,
        prompt: params.prompt,
        max_age: params.max_age,
        acr_values: params.acr_values,
        login_hint: params.login_hint,
        ui_locales: params.ui_locales,
        response_mode: params.response_mode,
    };

    let mut response = match state.authorize.authorize(tenant.context(), request).await {
        AuthorizeOutcome::ErrorRedirect { location } => found(&location),
        // web renders the login and consent screens. On receipt web immediately moves the handle into a
        // host-only cookie on its own domain and strips it from the URL (single-use, short-lived; ADR-0018 decisions 2, 3).
        AuthorizeOutcome::HandoffToWeb { handle } => found(&format!(
            "{}/{}/login?auth_session={}",
            state.config.public_web_base_url(),
            tenant.id(),
            handle
        )),
        AuthorizeOutcome::FatalError { error, description } => (
            StatusCode::BAD_REQUEST,
            Json(OAuthErrorResponse {
                error: error.as_str().to_string(),
                error_description: Some(description),
            }),
        )
            .into_response(),
    };
    // Framing is allowed only for 302 (a 400 body gets rendered)
    if silent && response.status() == StatusCode::FOUND {
        crate::presentation::security_headers::allow_silent_auth_framing(
            &mut response,
            state.config.silent_auth_frame_ancestors(),
        );
    }
    response
}

/// Resumes the authorization flow (`POST /internal/authorize/resume`, ADR-0018 decision 2).
///
/// web forwards the single-use handle from the handoff URL and the value of its own domain's host-only `sso_session_id` cookie.
/// The api consumes the handle once and performs SSO restoration -> `max_age` -> consent check -> code issuance,
/// returning the same response pattern as `/internal/authenticate`.
pub async fn authorize_resume(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalAuthorizeResumeRequest>,
) -> Result<Json<InternalAuthorizeResumeResponse>, Response> {
    // Client connection info is forwarded by web (the api is not directly behind the proxy, so it doesn't read X-Forwarded-For itself).
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .authorize
        .resume(
            tenant,
            ResumeCommand {
                handle: req.handle,
                sso_session_id: req.sso_session_id,
            },
            &ctx,
        )
        .await;
    Ok(Json(resume_response(outcome)))
}

/// Continues the authorization flow (`POST /internal/authorize/continue`).
///
/// When the login screen is reopened, web forwards its `auth_session_id` and `sso_session_id`.
/// If an SSO session established in another tab can restore it, a code is returned in the same response as resume.
pub async fn authorize_continue(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalAuthorizeContinueRequest>,
) -> Result<Json<InternalAuthorizeResumeResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .authorize
        .continue_with_sso(
            tenant,
            ContinueCommand {
                auth_session_id: req.auth_session_id,
                sso_session_id: req.sso_session_id,
            },
            &ctx,
        )
        .await;
    Ok(Json(resume_response(outcome)))
}

/// Maps the resume / continue result to the internal API response.
fn resume_response(outcome: ResumeOutcome) -> InternalAuthorizeResumeResponse {
    match outcome {
        ResumeOutcome::Redirect {
            location,
            form_post,
            sso_absolute_ttl_secs,
        } => InternalAuthorizeResumeResponse::Redirect {
            form_post,
            redirect_to: location,
            sso_absolute_ttl_secs,
        },
        ResumeOutcome::ErrorRedirect {
            location,
            form_post,
        } => InternalAuthorizeResumeResponse::ErrorRedirect {
            redirect_to: location,
            form_post,
        },
        ResumeOutcome::ConsentRequired {
            auth_session_id,
            sso_absolute_ttl_secs,
        } => InternalAuthorizeResumeResponse::ConsentRequired {
            auth_session_id,
            sso_absolute_ttl_secs,
        },
        ResumeOutcome::LoginRequired { auth_session_id } => {
            InternalAuthorizeResumeResponse::LoginRequired { auth_session_id }
        }
        ResumeOutcome::ApplicationNotPermitted { application_name } => {
            InternalAuthorizeResumeResponse::ApplicationNotPermitted { application_name }
        }
        ResumeOutcome::ExpiredHandle => InternalAuthorizeResumeResponse::ExpiredHandle,
        ResumeOutcome::Internal(e) => {
            tracing::error!(error = %e, "authorize resume/continue failed with internal error");
            InternalAuthorizeResumeResponse::Internal
        }
    }
}

/// Login screen context (`POST /internal/authorize/login-context`, G12).
///
/// Looks up the `login_hint` / `ui_locales` brought by the authorization request again from web's `auth_session_id`.
/// web cannot keep these across resume's 303, so it re-fetches them here on every login screen render.
/// It also returns display names (client name, tenant name) so the screen can show "where you are signing in to".
pub async fn authorize_login_context(
    State(state): State<AppState>,
    Json(req): Json<InternalAuthorizeLoginContextRequest>,
) -> Result<Json<InternalAuthorizeLoginContextResponse>, Response> {
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    Ok(Json(
        match state
            .authorize
            .login_context(tenant, &req.auth_session_id)
            .await
        {
            LoginContextOutcome::Ok {
                login_hint,
                ui_locales,
                redirect_uri,
                client_name,
                tenant_name,
            } => InternalAuthorizeLoginContextResponse::Ok {
                login_hint,
                ui_locales,
                redirect_uri: Some(redirect_uri),
                client_name,
                tenant_name,
            },
            LoginContextOutcome::SessionExpired => {
                InternalAuthorizeLoginContextResponse::SessionExpired
            }
            LoginContextOutcome::Internal(e) => {
                tracing::error!(error = %e, "authorize login-context failed with internal error");
                InternalAuthorizeLoginContextResponse::Internal
            }
        },
    ))
}
