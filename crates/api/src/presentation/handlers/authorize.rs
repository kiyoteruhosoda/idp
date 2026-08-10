//! 認可エンドポイント（`GET /authorize`、設計仕様 §4.2、ADR-0018 決定 2）。

use crate::application::audit::RequestContext;
use crate::application::authorize::{
    AuthorizeOutcome, AuthorizeRequest, LoginContextOutcome, ResumeCommand, ResumeOutcome,
};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::{AuthorizeParams, OAuthErrorResponse};
use crate::presentation::handlers::found;
use crate::presentation::state::AppState;
use crate::presentation::tenant::{require_internal_tenant, ResolvedTenant};
use axum::extract::{Extension, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use idp_contracts::auth::{
    InternalAuthorizeLoginContextRequest, InternalAuthorizeLoginContextResponse,
    InternalAuthorizeResumeRequest, InternalAuthorizeResumeResponse,
};

/// OIDC 認可エンドポイント。ブラウザ Cookie は読み書きしない（ADR-0018 決定 2）。
/// 検証成功時は AuthSession を作成し、単回・短命のハンドルを URL に載せて web の `/login` へ 302 する。
/// SSO 復元・`prompt` / `max_age` の評価は web が呼ぶ `/internal/authorize/resume` で行う。
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
    let request = AuthorizeRequest {
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

    match state.authorize.authorize(tenant.context(), request).await {
        AuthorizeOutcome::ErrorRedirect { location } => found(&location),
        // ログイン・同意画面は web が描画する。ハンドルは web が受領後ただちに自ドメインの
        // host-only Cookie へ移して URL から除去する（単回・短命。ADR-0018 決定 2・3）。
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
    }
}

/// 認可フローの再開（`POST /internal/authorize/resume`、ADR-0018 決定 2）。
///
/// web がハンドオフ URL の単回ハンドルと、自ドメインの host-only `sso_session_id` Cookie の値を
/// 転送する。api はハンドルを単回消費して SSO 復元 → `max_age` → 同意チェック → code 発行を行い、
/// `/internal/authenticate` と同じ応答パターンで返す。
pub async fn authorize_resume(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalAuthorizeResumeRequest>,
) -> Result<Json<InternalAuthorizeResumeResponse>, Response> {
    // 接続元情報は web が転送する（api はプロキシ直下ではないため自前で X-Forwarded-For を見ない）。
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant = require_internal_tenant(req.tenant_id.as_deref())?;
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
    // SSO 復元成功時、web が手元の `sso_session_id` を host-only で再発行するための TTL
    // （ログイン成功時の発行と同じ値。旧 Domain Cookie の移行にも使われる）。
    let ttl = state.config.sso_absolute_ttl().as_secs();
    Ok(Json(match outcome {
        ResumeOutcome::Redirect {
            location,
            form_post,
        } => InternalAuthorizeResumeResponse::Redirect {
            form_post,
            redirect_to: location,
            sso_absolute_ttl_secs: ttl,
        },
        ResumeOutcome::ErrorRedirect { location } => {
            InternalAuthorizeResumeResponse::ErrorRedirect {
                redirect_to: location,
            }
        }
        ResumeOutcome::ConsentRequired { auth_session_id } => {
            InternalAuthorizeResumeResponse::ConsentRequired {
                auth_session_id,
                sso_absolute_ttl_secs: ttl,
            }
        }
        ResumeOutcome::LoginRequired { auth_session_id } => {
            InternalAuthorizeResumeResponse::LoginRequired { auth_session_id }
        }
        ResumeOutcome::ExpiredHandle => InternalAuthorizeResumeResponse::ExpiredHandle,
        ResumeOutcome::Internal(e) => {
            tracing::error!(error = %e, "authorize resume failed with internal error");
            InternalAuthorizeResumeResponse::Internal
        }
    }))
}

/// ログイン画面の文脈（`POST /internal/authorize/login-context`。G12）。
///
/// 認可要求が持ち込んだ `login_hint` / `ui_locales` を、web が持つ `auth_session_id` から引き直す。
/// web は resume の 303 でこれらを手元に残せないため、ログイン画面の描画のたびにここで取り直す。
pub async fn authorize_login_context(
    State(state): State<AppState>,
    Json(req): Json<InternalAuthorizeLoginContextRequest>,
) -> Result<Json<InternalAuthorizeLoginContextResponse>, Response> {
    let tenant = require_internal_tenant(req.tenant_id.as_deref())?;
    Ok(Json(
        match state
            .authorize
            .login_context(tenant, &req.auth_session_id)
            .await
        {
            LoginContextOutcome::Ok {
                login_hint,
                ui_locales,
            } => InternalAuthorizeLoginContextResponse::Ok {
                login_hint,
                ui_locales,
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
