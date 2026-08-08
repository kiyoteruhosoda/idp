//! 利用者セルフサービスのセキュリティ画面（web。`/{tenant_id}/settings/security`。G10）。
//!
//! ログイン中のセッション一覧・失効と、連携済みアプリ（consent）の確認・取り消しを提供する。
//! 判定と永続化は api（`/internal/account/security*`）に委ね、web は CSRF 検証・画面描画・
//! リダイレクトのみを担う（設定画面 `user_settings` と同じ責務分担）。
//!
//! 破壊的操作（セッション失効・連携解除）は POST とし、ログイン後フォーム用の同期トークン
//! （`console_csrf_token`。SSO セッション id 由来）で保護する。

use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::console_csrf_token;
use crate::handlers::{forwarded_context, found, locale, see_other, step_up};
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, ConnectedAppView, SecuritySessionView, UserSecurity};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use idp_contracts::auth::{
    InternalAccountRevokeConsentRequest, InternalAccountRevokeConsentResponse,
    InternalAccountRevokeSessionRequest, InternalAccountRevokeSessionResponse,
    InternalAccountSecurityRequest, InternalAccountSecurityResponse,
};
use serde::Deserialize;

/// PRG 後のバナー表示に使うクエリ。
#[derive(Debug, Deserialize)]
pub struct SecurityQuery {
    #[serde(default)]
    pub saved: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RevokeSessionForm {
    pub session_id: String,
    pub csrf_token: String,
}

#[derive(Debug, Deserialize)]
pub struct RevokeConsentForm {
    pub client_id: String,
    pub csrf_token: String,
}

/// セキュリティ画面（`GET /{tenant_id}/settings/security`）。
pub async fn page(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<SecurityQuery>,
) -> Response {
    let locale = locale(&headers);
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{}/login", tenant.prefix()));
    };
    let csrf = console_csrf_token(&sso, state.config.csrf_secret());

    let request = InternalAccountSecurityRequest {
        tenant_id: Some(tenant.0.clone()),
        sso_session_id: sso,
    };
    let outcome = match state.api.account_security(&correlation.0, &request).await {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "account security fetch call to api failed");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    let (sessions, connected_apps) = match outcome {
        InternalAccountSecurityResponse::Ok {
            sessions,
            connected_apps,
        } => (sessions, connected_apps),
        InternalAccountSecurityResponse::SessionExpired => {
            return found(&format!("{}/login", tenant.prefix()));
        }
        InternalAccountSecurityResponse::Internal => {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // Messages（FluentBundle）は !Send のため、api の await より後・描画の直前に生成する。
    let messages = Messages::new(locale);
    let sessions: Vec<SecuritySessionView> = sessions
        .into_iter()
        .map(|s| SecuritySessionView {
            id: s.id,
            current: s.current,
            multi_factor: s.multi_factor,
            auth_time: s.auth_time,
            user_agent: s.user_agent.unwrap_or_default(),
            ip_address: s.ip_address.unwrap_or_default(),
            absolute_expires_at: s.absolute_expires_at,
        })
        .collect();
    let connected_apps: Vec<ConnectedAppView> = connected_apps
        .into_iter()
        .map(|a| ConnectedAppView {
            client_id: a.client_id,
            app_name: a.app_name,
            scopes: a.scopes.join(" "),
            granted_at: a.granted_at,
        })
        .collect();

    Html(render(&UserSecurity {
        messages: &messages,
        tenant: &tenant.prefix(),
        csrf: &csrf,
        sessions: &sessions,
        connected_apps: &connected_apps,
        saved_key: query.saved.as_deref().and_then(saved_key_for),
        error_key: query.error.as_deref().and_then(error_key_for),
    }))
    .into_response()
}

/// セッションの失効（`POST /{tenant_id}/settings/security/revoke-session`）。
pub async fn revoke_session(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<RevokeSessionForm>,
) -> Response {
    let base = format!("{}/settings/security", tenant.prefix());
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{}/login", tenant.prefix()));
    };
    if console_csrf_token(&sso, state.config.csrf_secret()) != form.csrf_token {
        tracing::warn!(
            correlation_id = %correlation.0,
            "security session revocation rejected: csrf token mismatch"
        );
        return see_other(&format!("{base}?error=csrf"));
    }
    // 他端末の締め出しは step-up の対象（AP5）。セッションを盗んだ側が、本人の端末を先に
    // 切って締め出す（＝気付きと復旧を遅らせる）のを防ぐ。
    if let Err(response) = step_up::require_step_up(
        &state,
        &correlation,
        &tenant,
        &headers,
        step_up::REVOKE_SESSION,
        &base,
    )
    .await
    {
        return response;
    }

    let ctx = forwarded_context(&headers, &correlation);
    let request = InternalAccountRevokeSessionRequest {
        tenant_id: Some(tenant.0.clone()),
        sso_session_id: sso,
        session_id: form.session_id,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    match state
        .api
        .account_revoke_session(&ctx.correlation_id, &request)
        .await
    {
        Ok(InternalAccountRevokeSessionResponse::Ok) => {
            see_other(&format!("{base}?saved=session-revoked"))
        }
        Ok(InternalAccountRevokeSessionResponse::NotFound) => {
            see_other(&format!("{base}?error=session-not-found"))
        }
        Ok(InternalAccountRevokeSessionResponse::CurrentSession) => {
            see_other(&format!("{base}?error=current-session"))
        }
        Ok(InternalAccountRevokeSessionResponse::SessionExpired) => {
            found(&format!("{}/login", tenant.prefix()))
        }
        Ok(InternalAccountRevokeSessionResponse::Internal) => {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "account session revoke call to api failed");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

/// 連携済みアプリの解除（`POST /{tenant_id}/settings/security/revoke-consent`）。
pub async fn revoke_consent(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<RevokeConsentForm>,
) -> Response {
    let base = format!("{}/settings/security", tenant.prefix());
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{}/login", tenant.prefix()));
    };
    if console_csrf_token(&sso, state.config.csrf_secret()) != form.csrf_token {
        tracing::warn!(
            correlation_id = %correlation.0,
            "security consent revocation rejected: csrf token mismatch"
        );
        return see_other(&format!("{base}?error=csrf"));
    }

    let ctx = forwarded_context(&headers, &correlation);
    let request = InternalAccountRevokeConsentRequest {
        tenant_id: Some(tenant.0.clone()),
        sso_session_id: sso,
        client_id: form.client_id,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    match state
        .api
        .account_revoke_consent(&ctx.correlation_id, &request)
        .await
    {
        Ok(InternalAccountRevokeConsentResponse::Ok) => {
            see_other(&format!("{base}?saved=consent-revoked"))
        }
        Ok(InternalAccountRevokeConsentResponse::SessionExpired) => {
            found(&format!("{}/login", tenant.prefix()))
        }
        Ok(InternalAccountRevokeConsentResponse::Internal) => {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "account consent revoke call to api failed");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

/// PRG のクエリ値を翻訳キーへ写す（未知の値は表示しない ＝ 任意文字列を画面へ出させない）。
fn saved_key_for(value: &str) -> Option<&'static str> {
    match value {
        "session-revoked" => Some("user-security-saved-session-revoked"),
        "consent-revoked" => Some("user-security-saved-consent-revoked"),
        _ => None,
    }
}

fn error_key_for(value: &str) -> Option<&'static str> {
    match value {
        "csrf" => Some("user-security-error-csrf"),
        "session-not-found" => Some("user-security-error-session-not-found"),
        "current-session" => Some("user-security-error-current-session"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 未知のクエリ値は翻訳キーに写さない（PRG のクエリはブラウザから任意の値を渡せるため、
    /// そのまま画面に出すと反射型の表示になる）。
    #[test]
    fn only_known_banner_values_map_to_message_keys() {
        assert_eq!(
            saved_key_for("session-revoked"),
            Some("user-security-saved-session-revoked")
        );
        assert_eq!(saved_key_for("<script>"), None);
        assert_eq!(error_key_for("csrf"), Some("user-security-error-csrf"));
        assert_eq!(error_key_for("anything-else"), None);
    }
}
