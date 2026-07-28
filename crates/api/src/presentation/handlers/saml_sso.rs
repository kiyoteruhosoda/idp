//! SAML SSO エンドポイント（`GET/POST /{tenant_id}/saml/sso`）と再開 API
//! （`POST /internal/saml/resume`）。
//!
//! メタデータ（[`super::discovery::saml_idp_metadata`]）が広告する SingleSignOnService の実装。
//! ブラウザ Cookie は読み書きせず、OIDC の `/authorize` と同じ単回・短命ハンドルで web へ
//! ハンドオフする（ADR-0018 決定 2）。SSO 判定・応答発行は web が呼ぶ `/internal/saml/resume`
//! で行い、web が ACS への自動 POST フォームを描画する。

use crate::application::audit::RequestContext;
use crate::application::saml_sso::{
    SamlBeginCommand, SamlBeginOutcome, SamlResumeCommand, SamlResumeOutcome, SamlSsoBinding,
};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::handlers::{found, request_context};
use crate::presentation::state::AppState;
use crate::presentation::tenant::{require_internal_tenant, ResolvedTenant};
use axum::extract::{Extension, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use idp_contracts::auth::{InternalSamlResumeRequest, InternalSamlResumeResponse};
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};

/// HTTP-Redirect binding のクエリパラメータ（SAML Bindings §3.4。パラメータ名は大文字始まり）。
#[derive(Debug, Deserialize, IntoParams)]
pub struct SamlSsoQuery {
    #[serde(rename = "SAMLRequest")]
    pub saml_request: Option<String>,
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
}

/// HTTP-POST binding のフォームパラメータ（SAML Bindings §3.5）。
#[derive(Debug, Deserialize, ToSchema)]
pub struct SamlSsoForm {
    #[serde(rename = "SAMLRequest")]
    pub saml_request: Option<String>,
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
}

/// SAML SSO（HTTP-Redirect binding）。AuthnRequest を検証し、単回ハンドル付きで web の
/// `/saml/continue` へ 302 する。
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

/// SAML SSO（HTTP-POST binding）。挙動は Redirect binding と同じ。
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
        // プロトコルエラーは RP（SP）開発者向けの固定英語文言（CLAUDE.md「翻訳の対象外」）。
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
        // ログイン・自動 POST フォームは web が描画する。ハンドルは web が受領後ただちに
        // 交換し URL から除去する（単回・短命。ADR-0018 決定 2・3）。
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

/// SAML SSO フローの再開（`POST /internal/saml/resume`）。
///
/// web がハンドル（初回）または `saml_request_id`（ログイン後）と、自ドメインの host-only
/// `sso_session_id` Cookie の値を転送する。SSO 有効なら署名付き SAML Response を返す。
pub async fn saml_resume(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalSamlResumeRequest>,
) -> Result<Json<InternalSamlResumeResponse>, Response> {
    // 接続元情報は web が転送する（api はプロキシ直下ではないため自前で X-Forwarded-For を見ない）。
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant = require_internal_tenant(req.tenant_id.as_deref())?;
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
        SamlResumeOutcome::Expired => InternalSamlResumeResponse::Expired,
        SamlResumeOutcome::Internal(e) => {
            tracing::error!(error = %e, "SAML resume failed with internal error");
            InternalSamlResumeResponse::Internal
        }
    }))
}
