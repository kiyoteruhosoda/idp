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
    browser_summary, duration_label, render, AppTokensView, BelongingView, ConnectedAppView,
    PolicyView, SecurityApproverKeyView, SecurityDeviceView, SecuritySessionView,
    SecuritySshKeyView, SecurityStatusView, SessionStatusView, SignInAppView, SignInRefreshView,
    SignInView, UserSecurity, WarningView,
};
use crate::tenant::WebTenant;
use assay_contracts::auth::{
    AccountAppTokens, AccountBelonging, AccountOccurrences, AccountSessionStatus,
    AccountSignInEntry, InternalAccountDevicesRequest, InternalAccountDevicesResponse,
    InternalAccountRegisterDeviceRequest, InternalAccountRegisterDeviceResponse,
    InternalAccountRegisterSshKeyRequest, InternalAccountRegisterSshKeyResponse,
    InternalAccountReissueTokensRequest, InternalAccountReissueTokensResponse,
    InternalAccountRevokeConsentRequest, InternalAccountRevokeConsentResponse,
    InternalAccountRevokeDeviceRequest, InternalAccountRevokeDeviceResponse,
    InternalAccountRevokeSessionRequest, InternalAccountRevokeSessionResponse,
    InternalAccountRevokeSshKeyRequest, InternalAccountRevokeSshKeyResponse,
    InternalAccountSecurityRequest, InternalAccountSecurityResponse,
    InternalAccountSecurityStatusRequest, InternalAccountSecurityStatusResponse,
    InternalAccountSignInHistoryRequest, InternalAccountSignInHistoryResponse,
    InternalAccountSshKeysRequest, InternalAccountSshKeysResponse,
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
    /// ログイン履歴のこれより古い行を見る（task #879）。
    #[serde(default)]
    pub history_before: Option<i64>,
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
pub struct RegisterSshKeyForm {
    pub public_key: String,
    pub name: String,
    pub csrf_token: String,
}

#[derive(Debug, Deserialize)]
pub struct RevokeSshKeyForm {
    pub key_id: String,
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
    Extension(client_ip): Extension<ClientIp>,
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

    // 「ログイン履歴」の欄（task #879）。本人の分だけ（api が SSO セッションの持ち主で引く）。
    let history_request = InternalAccountSignInHistoryRequest {
        tenant_id: Some(tenant.0.clone()),
        sso_session_id: request.sso_session_id.clone(),
        before: query.history_before,
        limit: Some(SIGN_IN_HISTORY_PAGE_SIZE),
    };
    let (sign_ins, sign_ins_older) = match state
        .api
        .account_sign_in_history(&correlation.0, &history_request)
        .await
    {
        Ok(InternalAccountSignInHistoryResponse::Ok {
            entries,
            next_before,
        }) => (
            entries.into_iter().map(sign_in_view).collect::<Vec<_>>(),
            next_before,
        ),
        Ok(InternalAccountSignInHistoryResponse::SessionExpired) => {
            return found(&format!("{}/login", tenant.prefix()));
        }
        Ok(InternalAccountSignInHistoryResponse::Internal) => {
            return api_internal_error("account_sign_in_history");
        }
        Err(e) => {
            tracing::error!(error = %e, "account sign-in history call to api failed");
            return internal_call_status(&e).into_response();
        }
    };

    // 「SSH の鍵」の欄（task #885）。組織で使っていなければ欄ごと出さない。
    let ssh_request = InternalAccountSshKeysRequest {
        tenant_id: Some(tenant.0.clone()),
        sso_session_id: request.sso_session_id.clone(),
    };
    let ssh_keys = match state
        .api
        .account_ssh_keys(&correlation.0, &ssh_request)
        .await
    {
        Ok(InternalAccountSshKeysResponse::Ok {
            enabled,
            passkey_fresh,
            keys,
        }) => SshKeysSection {
            enabled,
            passkey_fresh,
            keys: keys
                .into_iter()
                .map(|k| SecuritySshKeyView {
                    id: k.id,
                    name: k.name,
                    key_type: k.key_type,
                    fingerprint: k.fingerprint,
                    created_at: k.created_at,
                })
                .collect(),
        },
        Ok(InternalAccountSshKeysResponse::SessionExpired) => {
            return found(&format!("{}/login", tenant.prefix()));
        }
        Ok(InternalAccountSshKeysResponse::Internal) => {
            return api_internal_error("account_ssh_keys");
        }
        Err(e) => {
            tracing::error!(error = %e, "account ssh keys fetch call to api failed");
            return internal_call_status(&e).into_response();
        }
    };

    // 「認証アプリ」の行（task #892）。認証アプリの口が閉じていれば出さない。読めなくても画面は出す。
    let approver_keys: Vec<SecurityApproverKeyView> = match state
        .api
        .account_approver_keys(
            &correlation.0,
            &assay_contracts::auth::InternalAccountApproverKeysRequest {
                tenant_id: Some(tenant.0.clone()),
                sso_session_id: request.sso_session_id.clone(),
            },
        )
        .await
    {
        Ok(assay_contracts::auth::InternalAccountApproverKeysResponse::Listed { keys, .. }) => keys
            .into_iter()
            .map(|k| SecurityApproverKeyView {
                id: k.id,
                device_name: k.device_name,
                level_key: match k.security_level.as_str() {
                    "strongbox" => "app-approver-level-strongbox",
                    "tee" => "app-approver-level-tee",
                    _ => "app-approver-level-software",
                },
                registered_at: k.registered_at,
                last_used_at: k.last_used_at.unwrap_or_default(),
            })
            .collect(),
        Ok(_) => Vec::new(),
        Err(e) => {
            tracing::warn!(error = %e, "approver keys could not be listed");
            Vec::new()
        }
    };

    // 「状況」（task #896）。読めなくても下の一覧は出す（欄の代わりに案内を出す）。
    let status = match state
        .api
        .account_security_status(
            &correlation.0,
            &InternalAccountSecurityStatusRequest {
                tenant_id: Some(tenant.0.clone()),
                sso_session_id: request.sso_session_id.clone(),
            },
        )
        .await
    {
        Ok(InternalAccountSecurityStatusResponse::Ok {
            sessions,
            belongings,
            apps,
            policy,
            warnings,
        }) => Some((sessions, belongings, apps, policy, warnings)),
        Ok(InternalAccountSecurityStatusResponse::SessionExpired) => {
            return found(&format!("{}/login", tenant.prefix()));
        }
        Ok(InternalAccountSecurityStatusResponse::Internal) => {
            tracing::warn!("security status could not be built");
            None
        }
        Err(e) => {
            tracing::warn!(error = %e, "security status call to api failed");
            None
        }
    };
    let bound_cookie_expires_at =
        crate::session_key::bound_cookie_expiry(&state, &headers, &request.sso_session_id)
            .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
            .map(|t| t.to_rfc3339())
            .unwrap_or_default();
    let request_user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();

    // Messages（FluentBundle）は !Send のため、api の await より後・描画の直前に生成する。
    let messages = Messages::new(locale);
    // ログイン状態ごとの状況は、下の「ログイン状態」の表の行へも添える（同じ id で引く）。
    let mut session_statuses: std::collections::HashMap<String, SessionStatusView> =
        std::collections::HashMap::new();
    let status: Option<SecurityStatusView> =
        status.map(|(sessions, belongings, apps, policy, warnings)| {
            let warnings = *warnings;
            for s in sessions.into_iter().map(session_status_view) {
                session_statuses.insert(s.id.clone(), s);
            }
            SecurityStatusView {
                current: session_statuses.values().find(|s| s.current).cloned(),
                browser: browser_summary(&request_user_agent),
                user_agent: request_user_agent.clone(),
                ip_address: client_ip.0.clone().unwrap_or_default(),
                country: crate::client_country::current().unwrap_or_default(),
                bound_cookie_expires_at: bound_cookie_expires_at.clone(),
                belongings: belongings.into_iter().map(belonging_view).collect(),
                apps: apps.into_iter().map(app_tokens_view).collect(),
                policy: PolicyView {
                    unregistered_device_alerts: policy.unregistered_device_alerts,
                    ssh_keys_enabled: policy.ssh_keys_enabled,
                    bound_ttl: length_label(&messages, policy.bound_ttl_secs),
                    absolute_ttl: length_label(&messages, policy.absolute_ttl_secs),
                    idle_ttl: length_label(&messages, policy.idle_ttl_secs),
                    device_expiry_days: policy.device_expiry_days,
                },
                warnings: [
                    (
                        "user-security-status-warning-reuse",
                        &warnings.refresh_reuse,
                    ),
                    (
                        "user-security-status-warning-session-key",
                        &warnings.session_key_mismatch,
                    ),
                    (
                        "user-security-status-warning-dpop-key",
                        &warnings.dpop_key_mismatch,
                    ),
                    (
                        "user-security-status-warning-unregistered",
                        &warnings.unregistered_sign_ins,
                    ),
                ]
                .into_iter()
                .filter(|(_, o)| o.count > 0)
                .map(
                    |(key, o): (&'static str, &AccountOccurrences)| WarningView {
                        key,
                        count: o.count,
                        last_at: o.last_at.clone().unwrap_or_default(),
                    },
                )
                .collect(),
                failure_days: warnings
                    .failure_days
                    .into_iter()
                    .map(|d| (d.day, d.count))
                    .collect(),
                warning_window_days: warnings.window_days,
            }
        });

    let sessions: Vec<SecuritySessionView> = sessions
        .into_iter()
        .map(|s| SecuritySessionView {
            status: session_statuses.remove(&s.id),
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
        approver_keys: &approver_keys,
        sign_ins: &sign_ins,
        sign_ins_older,
        sign_ins_paged: query.history_before.is_some(),
        ssh_keys_enabled: ssh_keys.enabled,
        ssh_keys: &ssh_keys.keys,
        ssh_keys_passkey_fresh: ssh_keys.passkey_fresh,
        status: status.as_ref(),
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

/// 「SSH の鍵」の欄の中身（描画まで持ち回る）。
struct SshKeysSection {
    enabled: bool,
    passkey_fresh: bool,
    keys: Vec<SecuritySshKeyView>,
}

/// SSH の公開鍵を登録する（`POST /{tenant_id}/settings/security/register-ssh-key`。task #885）。
///
/// **パスキーで確かめてから 5 分以内**だけ通す。まだなら本人確認の画面（パスキーだけ）へ回し、
/// 戻ってきたら利用者がもう一度貼って押す（フォームの中身は持ち越さない）。
pub async fn register_ssh_key(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<RegisterSshKeyForm>,
) -> Response {
    let base = format!("{}/settings/security", tenant.prefix());
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{}/login", tenant.prefix()));
    };
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        tracing::warn!(
            correlation_id = %correlation.0,
            "ssh key registration rejected: csrf token mismatch"
        );
        return see_other(&format!("{base}?error=csrf"));
    }
    // 秘密鍵らしきものは api へも渡さずここで断る（貼られた値をどこにも運ばない。api も同じ判定で断る）。
    if form.public_key.contains("PRIVATE KEY") {
        tracing::warn!(
            correlation_id = %correlation.0,
            "ssh key registration refused: a private key was pasted"
        );
        return see_other(&format!("{base}?error=ssh-key-private#ssh-keys"));
    }
    if let Err(response) = step_up::require_step_up(
        &state,
        &correlation,
        &tenant,
        &headers,
        step_up::MANAGE_SSH_KEYS,
        &format!("{base}#ssh-keys"),
    )
    .await
    {
        return response;
    }

    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let request = InternalAccountRegisterSshKeyRequest {
        tenant_id: Some(tenant.0.clone()),
        sso_session_id: sso,
        public_key: form.public_key,
        name: form.name,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let error = |code: &str| see_other(&format!("{base}?error={code}#ssh-keys"));
    match state
        .api
        .account_register_ssh_key(&ctx.correlation_id, &request)
        .await
    {
        Ok(InternalAccountRegisterSshKeyResponse::Registered { .. }) => {
            see_other(&format!("{base}?saved=ssh-key-registered#ssh-keys"))
        }
        Ok(InternalAccountRegisterSshKeyResponse::Disabled) => error("ssh-key-disabled"),
        Ok(InternalAccountRegisterSshKeyResponse::PasskeyRequired) => {
            error("ssh-key-passkey-required")
        }
        Ok(InternalAccountRegisterSshKeyResponse::InvalidName) => error("ssh-key-invalid-name"),
        Ok(InternalAccountRegisterSshKeyResponse::PrivateKey) => error("ssh-key-private"),
        Ok(InternalAccountRegisterSshKeyResponse::NotSecurityKey) => {
            error("ssh-key-not-security-key")
        }
        Ok(InternalAccountRegisterSshKeyResponse::Malformed) => error("ssh-key-malformed"),
        Ok(InternalAccountRegisterSshKeyResponse::AlreadyRegistered) => {
            error("ssh-key-already-registered")
        }
        Ok(InternalAccountRegisterSshKeyResponse::TooMany) => error("ssh-key-too-many"),
        Ok(InternalAccountRegisterSshKeyResponse::SessionExpired) => {
            found(&format!("{}/login", tenant.prefix()))
        }
        Ok(InternalAccountRegisterSshKeyResponse::Internal) => {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "ssh key registration call to api failed");
            internal_call_status(&e).into_response()
        }
    }
}

/// SSH の公開鍵を取り消す（`POST /{tenant_id}/settings/security/revoke-ssh-key`。task #885）。
///
/// 取り消しもパスキーで 5 分以内だけ（盗んだ側に、本人の鍵を外して締め出させない）。
pub async fn revoke_ssh_key(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<RevokeSshKeyForm>,
) -> Response {
    let base = format!("{}/settings/security", tenant.prefix());
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{}/login", tenant.prefix()));
    };
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        tracing::warn!(
            correlation_id = %correlation.0,
            "ssh key revocation rejected: csrf token mismatch"
        );
        return see_other(&format!("{base}?error=csrf"));
    }
    if let Err(response) = step_up::require_step_up(
        &state,
        &correlation,
        &tenant,
        &headers,
        step_up::MANAGE_SSH_KEYS,
        &format!("{base}#ssh-keys"),
    )
    .await
    {
        return response;
    }

    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let request = InternalAccountRevokeSshKeyRequest {
        tenant_id: Some(tenant.0.clone()),
        sso_session_id: sso,
        key_id: form.key_id,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    match state
        .api
        .account_revoke_ssh_key(&ctx.correlation_id, &request)
        .await
    {
        Ok(InternalAccountRevokeSshKeyResponse::Revoked) => {
            see_other(&format!("{base}?saved=ssh-key-revoked#ssh-keys"))
        }
        Ok(InternalAccountRevokeSshKeyResponse::PasskeyRequired) => {
            see_other(&format!("{base}?error=ssh-key-passkey-required#ssh-keys"))
        }
        Ok(InternalAccountRevokeSshKeyResponse::NotFound) => {
            see_other(&format!("{base}?error=ssh-key-not-found#ssh-keys"))
        }
        Ok(InternalAccountRevokeSshKeyResponse::SessionExpired) => {
            found(&format!("{}/login", tenant.prefix()))
        }
        Ok(InternalAccountRevokeSshKeyResponse::Internal) => {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "ssh key revocation call to api failed");
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
        "approver-key-revoked" => Some("user-security-saved-approver-key-revoked"),
        "ssh-key-registered" => Some("user-security-saved-ssh-key-registered"),
        "ssh-key-revoked" => Some("user-security-saved-ssh-key-revoked"),
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
        "approver-key-not-found" => Some("user-security-error-approver-key-not-found"),
        "ssh-key-disabled" => Some("user-security-error-ssh-key-disabled"),
        "ssh-key-passkey-required" => Some("user-security-error-ssh-key-passkey-required"),
        "ssh-key-invalid-name" => Some("user-security-error-ssh-key-invalid-name"),
        "ssh-key-private" => Some("user-security-error-ssh-key-private"),
        "ssh-key-not-security-key" => Some("user-security-error-ssh-key-not-security-key"),
        "ssh-key-malformed" => Some("user-security-error-ssh-key-malformed"),
        "ssh-key-already-registered" => Some("user-security-error-ssh-key-already-registered"),
        "ssh-key-too-many" => Some("user-security-error-ssh-key-too-many"),
        "ssh-key-not-found" => Some("user-security-error-ssh-key-not-found"),
        _ => None,
    }
}

/// ログイン履歴の 1 ページの件数（task #879）。
const SIGN_IN_HISTORY_PAGE_SIZE: u32 = 10;

/// api の 1 行を画面の 1 行へ（文言はキーにして、訳はテンプレートに任せる）。
fn sign_in_view(e: AccountSignInEntry) -> SignInView {
    let succeeded = e.outcome == "succeeded";
    let user_agent = e.user_agent.unwrap_or_default();
    SignInView {
        outcome_key: outcome_key(&e.outcome),
        succeeded,
        failure_key: e.failure_kind.as_deref().map(failure_key),
        ip_address: e.ip_address.unwrap_or_default(),
        country: e.country.unwrap_or_default(),
        browser_summary: browser_summary(&user_agent),
        user_agent,
        method_keys: e.methods.iter().map(|m| method_key(m)).collect(),
        attempted_app: if succeeded {
            String::new()
        } else {
            e.app_name.or(e.client_id).unwrap_or_default()
        },
        current: e.current,
        device_registered: e.device_registered,
        occurred_at: e.occurred_at,
        apps: e
            .apps
            .into_iter()
            .map(|a| SignInAppView {
                app_name: a.app_name.unwrap_or(a.client_id),
                last_issued_at: a.last_issued_at,
                refresh: a.refresh.map(|r| {
                    let last_user_agent = r.last_user_agent.unwrap_or_default();
                    SignInRefreshView {
                        use_count: r.use_count.to_string(),
                        last_used_at: r.last_used_at.unwrap_or_default(),
                        last_ip_address: r.last_ip_address.unwrap_or_default(),
                        last_browser_summary: browser_summary(&last_user_agent),
                        last_user_agent,
                        reuse_detected_at: r.reuse_detected_at.unwrap_or_default(),
                        state_key: refresh_state_key(&r.state),
                        active: r.state == "active",
                        revoked_at: r.revoked_at.unwrap_or_default(),
                    }
                }),
            })
            .collect(),
    }
}

fn outcome_key(outcome: &str) -> &'static str {
    match outcome {
        "succeeded" => "user-security-signins-outcome-succeeded",
        "locked" => "user-security-signins-outcome-locked",
        "denied" => "user-security-signins-outcome-denied",
        _ => "user-security-signins-outcome-failed",
    }
}

fn failure_key(kind: &str) -> &'static str {
    match kind {
        "wrong_password" => "user-security-signins-failure-wrong-password",
        "wrong_passkey" => "user-security-signins-failure-wrong-passkey",
        "wrong_code" => "user-security-signins-failure-wrong-code",
        "too_many_failures" => "user-security-signins-failure-too-many",
        "account_locked" => "user-security-signins-failure-locked",
        "account_not_active" => "user-security-signins-failure-not-active",
        "rate_limited" => "user-security-signins-failure-rate-limited",
        "policy_denied" => "user-security-signins-failure-policy",
        "external_failed" => "user-security-signins-failure-external",
        _ => "user-security-signins-failure-other",
    }
}

/// 「状況」のログイン状態 1 つを画面の形へ（task #896）。
fn session_status_view(s: AccountSessionStatus) -> SessionStatusView {
    let user_agent = s.user_agent.unwrap_or_default();
    SessionStatusView {
        browser: browser_summary(&user_agent),
        user_agent,
        id: s.id,
        current: s.current,
        auth_time: s.auth_time,
        expires_at: s.expires_at,
        method_keys: s.methods.iter().map(|m| method_key(m)).collect(),
        multi_factor: s.multi_factor,
        ip_address: s.ip_address.unwrap_or_default(),
        country: s.country.unwrap_or_default(),
        device_identified: s.device_identified,
        device_name: s.device_name.unwrap_or_default(),
        device_registered_at: s.device_registered_at.unwrap_or_default(),
        device_last_used_at: s.device_last_used_at.unwrap_or_default(),
        binding_key: match s.binding.as_str() {
            "device_key" => "user-security-status-binding-device-key",
            "app_approval" => "user-security-status-binding-app-approval",
            _ => "user-security-status-binding-unbound",
        },
        long_lifetime: matches!(
            s.lifetime_basis.as_str(),
            "bound_on_registered_device" | "app_approval"
        ),
        basis_key: basis_keys(&s.lifetime_basis).0,
        basis_short_key: basis_keys(&s.lifetime_basis).1,
        key_algorithm: s.key_algorithm.unwrap_or_default(),
        key_thumbprint_head: s
            .key_thumbprint
            .unwrap_or_default()
            .chars()
            .take(12)
            .collect(),
        key_bound_at: s.key_bound_at.unwrap_or_default(),
        key_refreshed_at: s.key_refreshed_at.unwrap_or_default(),
        approver_device_name: s.approver_device_name.unwrap_or_default(),
        approver_level_key: match s.approver_security_level.as_deref() {
            Some("strongbox") => "app-approver-level-strongbox",
            Some("tee") => "app-approver-level-tee",
            Some(_) => "app-approver-level-software",
            None => "",
        },
        passkey_fresh_until: s.passkey_fresh_until.unwrap_or_default(),
    }
}

/// 組織の長さの設定（秒）を「30 日」のように読める形へ。
fn length_label(messages: &Messages, secs: i64) -> String {
    duration_label(messages, u64::try_from(secs).unwrap_or(0)).unwrap_or_else(|| secs.to_string())
}

/// 長さの根拠の文言のキー（長い言い方と、表の 1 行の短い言い方）。
fn basis_keys(basis: &str) -> (&'static str, &'static str) {
    match basis {
        "bound_on_registered_device" => (
            "user-security-status-basis-bound-registered",
            "user-security-status-basis-bound-registered-short",
        ),
        "app_approval" => (
            "user-security-status-basis-app-approval",
            "user-security-status-basis-app-approval-short",
        ),
        "bound_on_unregistered_device" => (
            "user-security-status-basis-bound-unregistered",
            "user-security-status-basis-bound-unregistered-short",
        ),
        "not_extended_by_setting" => (
            "user-security-status-basis-not-extended",
            "user-security-status-basis-not-extended-short",
        ),
        _ => (
            "user-security-status-basis-unbound",
            "user-security-status-basis-unbound-short",
        ),
    }
}

/// 持ち物 1 つを画面の形へ（task #896）。種類ごとに「何に使われるか」「強さ」を決める。
fn belonging_view(b: AccountBelonging) -> BelongingView {
    let (kind_key, use_key, strength_key) = match b.kind.as_str() {
        "passkey" => (
            "user-security-status-kind-passkey",
            "user-security-status-use-passkey",
            "user-security-status-strength-phishing-resistant",
        ),
        "totp" => (
            "user-security-status-kind-totp",
            "user-security-status-use-totp",
            "user-security-status-strength-second-factor",
        ),
        "approver_key" => (
            "user-security-status-kind-approver-key",
            "user-security-status-use-approver-key",
            "user-security-status-strength-phishing-resistant",
        ),
        "device" => (
            "user-security-status-kind-device",
            "user-security-status-use-device",
            "user-security-status-strength-marker",
        ),
        _ => (
            "user-security-status-kind-ssh-key",
            "user-security-status-use-ssh-key",
            "user-security-status-strength-hardware",
        ),
    };
    let (detail, detail_key) = match (b.kind.as_str(), b.detail) {
        ("approver_key", Some(level)) => (
            String::new(),
            match level.as_str() {
                "strongbox" => "app-approver-level-strongbox",
                "tee" => "app-approver-level-tee",
                _ => "app-approver-level-software",
            },
        ),
        ("device", Some(ua)) => (browser_summary(&ua), ""),
        (_, detail) => (detail.unwrap_or_default(), ""),
    };
    BelongingView {
        last_use_invisible: b.kind == "ssh_key",
        kind_key,
        use_key,
        strength_key,
        name: b.name,
        detail,
        detail_key,
        registered_at: b.registered_at,
        last_used_at: b.last_used_at.unwrap_or_default(),
        expires_at: b.expires_at.unwrap_or_default(),
    }
}

/// アプリ 1 つのトークンの種別を画面の形へ（task #896）。
fn app_tokens_view(a: AccountAppTokens) -> AppTokensView {
    let token_key = if a.active_refresh_tokens == 0 {
        "user-security-status-token-none"
    } else if a.dpop_bound_refresh_tokens == a.active_refresh_tokens {
        "user-security-status-token-dpop"
    } else if a.dpop_bound_refresh_tokens == 0 {
        "user-security-status-token-bearer"
    } else {
        "user-security-status-token-mixed"
    };
    let sender = match (a.refresh_last_ip, a.refresh_last_user_agent) {
        (Some(ip), Some(ua)) => {
            let summary = browser_summary(&ua);
            if summary.is_empty() {
                ip
            } else {
                format!("{ip}（{summary}）")
            }
        }
        (Some(ip), None) => ip,
        (None, Some(ua)) => browser_summary(&ua),
        (None, None) => String::new(),
    };
    AppTokensView {
        app_name: a.app_name,
        scopes: a.scopes.join(" "),
        active_refresh_tokens: a.active_refresh_tokens,
        dpop_bound_refresh_tokens: a.dpop_bound_refresh_tokens,
        token_key,
        last_issued_at: a.last_issued_at.unwrap_or_default(),
        refresh_use_count: a.refresh_use_count,
        refresh_last_used_at: a.refresh_last_used_at.unwrap_or_default(),
        refresh_last_sender: sender,
        refresh_reuse_detected_at: a.refresh_reuse_detected_at.unwrap_or_default(),
    }
}

fn method_key(method: &str) -> &'static str {
    match method {
        "password" => "user-security-signins-method-password",
        "totp" => "user-security-signins-method-totp",
        "webauthn" => "user-security-signins-method-passkey",
        "recovery_code" => "user-security-signins-method-recovery-code",
        "email_otp" => "user-security-signins-method-email-otp",
        "sms_otp" => "user-security-signins-method-sms-otp",
        "external_idp" => "user-security-signins-method-external",
        "app_approval" => "user-security-signins-method-app-approval",
        _ => "user-security-signins-method-other",
    }
}

fn refresh_state_key(state: &str) -> &'static str {
    match state {
        "active" => "user-security-signins-refresh-state-active",
        "revoked" => "user-security-signins-refresh-state-revoked",
        _ => "user-security-signins-refresh-state-expired",
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
