//! UserInfo endpoint (`GET /userinfo`, design spec §4.7).

use crate::application::userinfo::{PresentedAccessToken, UserInfoError};
use crate::presentation::dto::{OAuthErrorResponse, UserInfoResponse};
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

/// Validates the Bearer Access Token (`typ=at+jwt`) and returns claims according to scope.
#[utoipa::path(
    get,
    path = "/{tenant_id}/userinfo",
    tag = "oidc",
    security(("bearer_token" = [])),
    responses(
        (status = 200, description = "scope に応じたユーザークレーム", body = UserInfoResponse),
        (status = 401, description = "トークン不正", body = OAuthErrorResponse),
        (status = 403, description = "openid scope なし", body = OAuthErrorResponse),
    )
)]
pub async fn userinfo(
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    headers: HeaderMap,
) -> Response {
    // `Bearer` and `DPoP` (RFC 9449 §7.1, ADR-0075 decision 8). Which is used is decided by the token's `cnf`,
    // and mismatches are rejected by the use case.
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let proof = headers.get("dpop").and_then(|v| v.to_str().ok());
    let presented = match authorization {
        Some(v) if v.starts_with("Bearer ") => PresentedAccessToken::Bearer(&v["Bearer ".len()..]),
        Some(v) if v.starts_with("DPoP ") => PresentedAccessToken::Dpop {
            token: &v["DPoP ".len()..],
            proof,
        },
        _ => return unauthorized("missing bearer token"),
    };

    // The requested tenant comes from the path (`resolve_tenant`). The token's `iss`/`aud` are strictly matched against
    // the tenant's composed issuer, rejecting reuse of tokens issued by other tenants (ADR-0009 §6).
    match state.userinfo.userinfo(tenant.context(), presented).await {
        Ok(claims) => Json(UserInfoResponse {
            sub: claims.sub,
            email: claims.email,
            email_verified: claims.email_verified,
            preferred_username: claims.preferred_username,
            name: claims.name,
        })
        .into_response(),
        Err(UserInfoError::InvalidToken(reason)) => unauthorized(reason),
        Err(UserInfoError::InvalidDpopProof(reason)) => invalid_dpop_proof(reason),
        Err(UserInfoError::InsufficientScope) => (
            StatusCode::FORBIDDEN,
            [(
                header::WWW_AUTHENTICATE,
                "Bearer error=\"insufficient_scope\"",
            )],
            Json(OAuthErrorResponse {
                error: "insufficient_scope".to_string(),
                error_description: Some("openid scope is required".to_string()),
            }),
        )
            .into_response(),
        Err(UserInfoError::Internal(e)) => {
            tracing::error!(error = %e, "userinfo failed with internal error");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn unauthorized(reason: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        // Announce that DPoP is accepted too (RFC 9449 §7.1; two challenges may be listed).
        [(
            header::WWW_AUTHENTICATE,
            "Bearer error=\"invalid_token\", DPoP algs=\"ES256\"",
        )],
        Json(OAuthErrorResponse {
            error: "invalid_token".to_string(),
            error_description: Some(reason.to_string()),
        }),
    )
        .into_response()
}

/// DPoP proof missing or invalid (RFC 9449 §7.1, §12.2).
fn invalid_dpop_proof(reason: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(
            header::WWW_AUTHENTICATE,
            "DPoP error=\"invalid_dpop_proof\", algs=\"ES256\"",
        )],
        Json(OAuthErrorResponse {
            error: "invalid_dpop_proof".to_string(),
            error_description: Some(reason.to_string()),
        }),
    )
        .into_response()
}
