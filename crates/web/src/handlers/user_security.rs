//! 利用者セルフサービスのセキュリティ画面（web。`/{tenant_id}/settings/security`。G10）。
//!
//! ログイン中のセッション一覧・失効、連携済みアプリ（consent）の確認・取り消し、発行済み
//! トークンの再発行（ADR-0047）を提供する。
//! 判定と永続化は api（`/internal/account/security*`）に委ね、web は CSRF 検証・画面描画・
//! リダイレクトのみを担う（設定画面 `user_settings` と同じ責務分担）。
//!
//! 破壊的操作（セッション失効・連携解除）は POST とし、ログイン後フォーム用の同期トークン
//! （`console_csrf_token`。SSO セッション id 由来）で保護する。

use super::{api_internal_error, internal_call_status};
use crate::client_ip::ClientIp;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::{console_csrf_token, console_csrf_valid};
use crate::device_observation::DEVICE_COOKIE;
use crate::handlers::{forwarded_context, found, locale, see_other, step_up};
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{
    render, ConnectedAppView, SecurityDeviceView, SecuritySessionView, UserSecurity,
};
use crate::tenant::WebTenant;
use assay_contracts::auth::{
    InternalAccountDevicesRequest, InternalAccountDevicesResponse,
    InternalAccountRegisterDeviceRequest, InternalAccountRegisterDeviceResponse,
    InternalAccountReissueTokensRequest, InternalAccountReissueTokensResponse,
    InternalAccountRevokeConsentRequest, InternalAccountRevokeConsentResponse,
    InternalAccountRevokeDeviceRequest, InternalAccountRevokeDeviceResponse,
    InternalAccountRevokeSessionRequest, InternalAccountRevokeSessionResponse,
    InternalAccountSecurityRequest, InternalAccountSecurityResponse,
};
use axum::extract::{Extension, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
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

#[derive(Debug, Deserialize)]
pub struct RegisterDeviceForm {
    pub name: String,
    pub csrf_token: String,
}

#[derive(Debug, Deserialize)]
pub struct RevokeDeviceForm {
    pub device_id: String,
    pub csrf_token: String,
}

/// トークンの再発行は対象を選ばない（当人ぶんを全部落とす）ので CSRF トークンだけを受ける。
#[derive(Debug, Deserialize)]
pub struct ReissueTokensForm {
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
            return internal_call_status(&e).into_response();
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
            return api_internal_error("account_security");
        }
    };

    // 「端末」の欄（task #872）。今のブラウザの端末の印を添えて、登録済みかを api に決めさせる。
    let device_request = InternalAccountDevicesRequest {
        tenant_id: Some(tenant.0.clone()),
        sso_session_id: request.sso_session_id.clone(),
        device_token: cookies::get(&headers, DEVICE_COOKIE),
    };
    let devices = match state
        .api
        .account_devices(&correlation.0, &device_request)
        .await
    {
        Ok(InternalAccountDevicesResponse::Ok {
            devices,
            current_registered,
            current_identified,
            passkey_fresh,
            alerts_enabled,
        }) => DevicesSection {
            devices: devices
                .into_iter()
                .map(|d| SecurityDeviceView {
                    id: d.id,
                    name: d.name,
                    current: d.current,
                    user_agent: d.user_agent.unwrap_or_default(),
                    last_used_at: d.last_used_at,
                    last_country: d.last_country.unwrap_or_default(),
                    expires_at: d.expires_at,
                })
                .collect(),
            current_registered,
            current_identified,
            passkey_fresh,
            alerts_enabled,
        },
        Ok(InternalAccountDevicesResponse::SessionExpired) => {
            return found(&format!("{}/login", tenant.prefix()));
        }
        Ok(InternalAccountDevicesResponse::Internal) => {
            return api_internal_error("account_devices");
        }
        Err(e) => {
            tracing::error!(error = %e, "account devices fetch call to api failed");
            return internal_call_status(&e).into_response();
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
        devices: &devices.devices,
        current_device_registered: devices.current_registered,
        current_device_identified: devices.current_identified,
        passkey_fresh: devices.passkey_fresh,
        devices_alerts_enabled: devices.alerts_enabled,
        saved_key: query.saved.as_deref().and_then(saved_key_for),
        error_key: query.error.as_deref().and_then(error_key_for),
    }))
    .into_response()
}

/// セッションの失効（`POST /{tenant_id}/settings/security/revoke-session`）。
pub async fn revoke_session(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<RevokeSessionForm>,
) -> Response {
    let base = format!("{}/settings/security", tenant.prefix());
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{}/login", tenant.prefix()));
    };
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
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

    let ctx = forwarded_context(&headers, &correlation, &client_ip);
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
            internal_call_status(&e).into_response()
        }
    }
}

/// 連携済みアプリの解除（`POST /{tenant_id}/settings/security/revoke-consent`）。
pub async fn revoke_consent(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<RevokeConsentForm>,
) -> Response {
    let base = format!("{}/settings/security", tenant.prefix());
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{}/login", tenant.prefix()));
    };
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        tracing::warn!(
            correlation_id = %correlation.0,
            "security consent revocation rejected: csrf token mismatch"
        );
        return see_other(&format!("{base}?error=csrf"));
    }

    let ctx = forwarded_context(&headers, &correlation, &client_ip);
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
            internal_call_status(&e).into_response()
        }
    }
}

/// 発行済みトークンの再発行（`POST /{tenant_id}/settings/security/reissue-tokens`。ADR-0047）。
///
/// **step-up は要求しない。** セッションの失効に本人確認を挟むのは、セッションを盗んだ側が
/// 本人の端末を先に切って締め出せるためだが、この操作は端末を切らない（誰も締め出されず、
/// アプリは黙って取り直す）。安全側へ倒すための操作に本人確認の壁を置くと、心当たりがある
/// 利用者ほど押せなくなる。
pub async fn reissue_tokens(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<ReissueTokensForm>,
) -> Response {
    let base = format!("{}/settings/security", tenant.prefix());
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{}/login", tenant.prefix()));
    };
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        tracing::warn!(
            correlation_id = %correlation.0,
            "security token reissue rejected: csrf token mismatch"
        );
        return see_other(&format!("{base}?error=csrf"));
    }

    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let request = InternalAccountReissueTokensRequest {
        tenant_id: Some(tenant.0.clone()),
        sso_session_id: sso,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    match state
        .api
        .account_reissue_tokens(&ctx.correlation_id, &request)
        .await
    {
        // 0 件も成功だが、利用者には区別して伝える（同じ「完了しました」だけを返すと、
        // 効いていないのか元から無いのかが分からない。管理コンソールの MFA 解除と同じ扱い）。
        Ok(InternalAccountReissueTokensResponse::Ok { revoked: 0 }) => {
            see_other(&format!("{base}?saved=tokens-none"))
        }
        Ok(InternalAccountReissueTokensResponse::Ok { .. }) => {
            see_other(&format!("{base}?saved=tokens-reissued"))
        }
        Ok(InternalAccountReissueTokensResponse::SessionExpired) => {
            found(&format!("{}/login", tenant.prefix()))
        }
        Ok(InternalAccountReissueTokensResponse::Internal) => {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "account token reissue call to api failed");
            internal_call_status(&e).into_response()
        }
    }
}

/// 「端末」の欄の中身（描画まで持ち回る）。
struct DevicesSection {
    devices: Vec<SecurityDeviceView>,
    current_registered: bool,
    current_identified: bool,
    passkey_fresh: bool,
    alerts_enabled: bool,
}

/// 今のブラウザを端末として登録する（`POST /{tenant_id}/settings/security/register-device`。task #872）。
///
/// **パスキーで確かめてから 5 分以内**だけ通す。まだなら本人確認の画面（パスキーだけ）へ回し、
/// 戻ってきたら利用者がもう一度押す（他の重要操作と同じく、フォームの中身は持ち越さない）。
pub async fn register_device(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<RegisterDeviceForm>,
) -> Response {
    let base = format!("{}/settings/security", tenant.prefix());
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{}/login", tenant.prefix()));
    };
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        tracing::warn!(
            correlation_id = %correlation.0,
            "device registration rejected: csrf token mismatch"
        );
        return see_other(&format!("{base}?error=csrf"));
    }
    // パスキーでしか通らない本人確認（api が判定する。パスワードの確認では満たされない）。
    if let Err(response) = step_up::require_step_up(
        &state,
        &correlation,
        &tenant,
        &headers,
        step_up::REGISTER_DEVICE,
        &format!("{base}#devices"),
    )
    .await
    {
        return response;
    }

    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let country = if state.config.trust_forwarded_headers() {
        headers
            .get("cf-ipcountry")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    } else {
        None
    };
    let request = InternalAccountRegisterDeviceRequest {
        tenant_id: Some(tenant.0.clone()),
        sso_session_id: sso,
        device_token: cookies::get(&headers, DEVICE_COOKIE),
        name: form.name,
        country,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    match state
        .api
        .account_register_device(&ctx.correlation_id, &request)
        .await
    {
        Ok(InternalAccountRegisterDeviceResponse::Registered) => {
            see_other(&format!("{base}?saved=device-registered#devices"))
        }
        Ok(InternalAccountRegisterDeviceResponse::PasskeyRequired) => {
            see_other(&format!("{base}?error=device-passkey-required#devices"))
        }
        Ok(InternalAccountRegisterDeviceResponse::AlreadyRegistered) => {
            see_other(&format!("{base}?error=device-already-registered#devices"))
        }
        Ok(InternalAccountRegisterDeviceResponse::InvalidName) => {
            see_other(&format!("{base}?error=device-invalid-name#devices"))
        }
        Ok(InternalAccountRegisterDeviceResponse::DeviceUnidentified) => {
            see_other(&format!("{base}?error=device-unidentified#devices"))
        }
        Ok(InternalAccountRegisterDeviceResponse::SessionExpired) => {
            found(&format!("{}/login", tenant.prefix()))
        }
        Ok(InternalAccountRegisterDeviceResponse::Internal) => {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "device registration call to api failed");
            internal_call_status(&e).into_response()
        }
    }
}

/// 端末の登録を取り消す（`POST /{tenant_id}/settings/security/revoke-device`。task #872）。
///
/// その端末で作られたログイン状態も切るので、セッションの失効と同じく本人確認を挟む（盗んだ側が
/// 本人の端末を先に締め出すのを防ぐ）。
pub async fn revoke_device(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<RevokeDeviceForm>,
) -> Response {
    let base = format!("{}/settings/security", tenant.prefix());
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{}/login", tenant.prefix()));
    };
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        tracing::warn!(
            correlation_id = %correlation.0,
            "device revocation rejected: csrf token mismatch"
        );
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
    let request = InternalAccountRevokeDeviceRequest {
        tenant_id: Some(tenant.0.clone()),
        sso_session_id: sso,
        device_id: form.device_id,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    match state
        .api
        .account_revoke_device(&ctx.correlation_id, &request)
        .await
    {
        Ok(InternalAccountRevokeDeviceResponse::Revoked { .. }) => {
            see_other(&format!("{base}?saved=device-revoked#devices"))
        }
        Ok(InternalAccountRevokeDeviceResponse::NotFound) => {
            see_other(&format!("{base}?error=device-not-found#devices"))
        }
        Ok(InternalAccountRevokeDeviceResponse::SessionExpired) => {
            found(&format!("{}/login", tenant.prefix()))
        }
        Ok(InternalAccountRevokeDeviceResponse::Internal) => {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "device revocation call to api failed");
            internal_call_status(&e).into_response()
        }
    }
}

/// PRG のクエリ値を翻訳キーへ写す（未知の値は表示しない ＝ 任意文字列を画面へ出させない）。
fn saved_key_for(value: &str) -> Option<&'static str> {
    match value {
        "session-revoked" => Some("user-security-saved-session-revoked"),
        "consent-revoked" => Some("user-security-saved-consent-revoked"),
        "tokens-reissued" => Some("user-security-saved-tokens-reissued"),
        "tokens-none" => Some("user-security-saved-tokens-none"),
        "device-registered" => Some("user-security-saved-device-registered"),
        "device-revoked" => Some("user-security-saved-device-revoked"),
        _ => None,
    }
}

fn error_key_for(value: &str) -> Option<&'static str> {
    match value {
        "csrf" => Some("user-security-error-csrf"),
        "session-not-found" => Some("user-security-error-session-not-found"),
        "current-session" => Some("user-security-error-current-session"),
        "device-passkey-required" => Some("user-security-error-device-passkey-required"),
        "device-already-registered" => Some("user-security-error-device-already-registered"),
        "device-invalid-name" => Some("user-security-error-device-invalid-name"),
        "device-unidentified" => Some("user-security-devices-unidentified"),
        "device-not-found" => Some("user-security-error-device-not-found"),
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
        assert_eq!(
            saved_key_for("tokens-none"),
            Some("user-security-saved-tokens-none")
        );
        assert_eq!(saved_key_for("<script>"), None);
        assert_eq!(error_key_for("csrf"), Some("user-security-error-csrf"));
        assert_eq!(error_key_for("anything-else"), None);
    }
}
