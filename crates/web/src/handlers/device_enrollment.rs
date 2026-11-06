//! 登録していない端末で正しく入ろうとしたときの、その場での端末の登録（task #916。ADR-0079）。
//!
//! 登録した端末に限る組織では、どのログインの経路も「SSO を作らずに登録の札を返す」ことがある。
//! そのとき web は札を Cookie（オリジン束縛名・10 分）に置いて `GET /{t}/device-enrollment?next=…` へ
//! 回す。画面はだれのログインかを見せ、パスキーで確かめると、このブラウザを端末として登録して
//! SSO Cookie を置き、`next`（元の画面）へ戻す。OIDC の認可フローの途中なら `next` はログイン画面で、
//! 開き直すと、できた SSO から認可を続ける（`login::continue_with_sso`）。
//!
//! パスキーのセレモニーはログイン画面と同じスクリプト（`passkey-login.js`）を使う。

use super::{api_internal_error, found, internal_call_status, locale};
use crate::client_ip::ClientIp;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::handlers::forwarded_context;
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, DeviceEnrollmentPage, MessagePage};
use crate::tenant::WebTenant;
use assay_contracts::auth::{
    InternalDeviceEnrollmentBeginRequest, InternalDeviceEnrollmentBeginResponse,
    InternalDeviceEnrollmentCompleteRequest, InternalDeviceEnrollmentCompleteResponse,
    InternalDeviceEnrollmentDescribeRequest, InternalDeviceEnrollmentDescribeResponse,
};
use axum::extract::{Extension, Query, State};
use axum::http::header::USER_AGENT;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Json, Response};
use serde::{Deserialize, Serialize};

/// 札の Cookie の寿命（api の札と同じ 10 分）。
pub const DEVICE_ENROLLMENT_TTL_SECS: u64 = 600;

/// 戻り先の長さの上限。
const MAX_NEXT_LEN: usize = 512;

/// 登録の画面の道（`{prefix}/device-enrollment?next=…`）。
pub(crate) fn enrollment_location(tenant: &WebTenant, next: &str) -> String {
    format!(
        "{}/device-enrollment?next={}",
        tenant.prefix(),
        percent_encoding::utf8_percent_encode(next, percent_encoding::NON_ALPHANUMERIC)
    )
}

/// 札を Cookie に置く `Set-Cookie`。
pub(crate) fn ticket_cookie(state: &WebState, ticket: &str) -> crate::cookies::SetCookies {
    state.set_cookies().set_local(
        &state.origin_bound_cookie(cookies::DEVICE_ENROLLMENT_COOKIE),
        ticket,
        DEVICE_ENROLLMENT_TTL_SECS,
    )
}

/// 札を置いて登録の画面へ回す（302）。`next` は登録の後に戻す画面。
pub(crate) fn redirect(state: &WebState, tenant: &WebTenant, ticket: &str, next: &str) -> Response {
    (
        ticket_cookie(state, ticket).into_headers(),
        found(&enrollment_location(tenant, next)),
    )
        .into_response()
}

/// 戻り先として受け付ける形か（このテナントの画面の道だけ。外へは戻さない）。
pub(crate) fn safe_next(tenant: &WebTenant, raw: Option<&str>) -> String {
    let prefix = tenant.prefix();
    let fallback = format!("{prefix}/settings");
    let Some(raw) = raw.map(str::trim) else {
        return fallback;
    };
    let ok = raw.len() <= MAX_NEXT_LEN
        && raw.starts_with(&format!("{prefix}/"))
        && !raw.contains("//")
        && !raw.contains('\\')
        && !raw.chars().any(char::is_control);
    if ok {
        raw.to_string()
    } else {
        fallback
    }
}

/// ブラウザの名乗りから、端末の名前の初めの値を作る（表示の手掛かり。利用者が打ち直せる）。
pub(crate) fn suggested_device_name(user_agent: Option<&str>) -> String {
    let ua = user_agent.unwrap_or_default();
    let os = if ua.contains("Android") {
        "Android"
    } else if ua.contains("iPhone") || ua.contains("iPad") {
        "iOS"
    } else if ua.contains("Windows") {
        "Windows"
    } else if ua.contains("Mac OS X") || ua.contains("Macintosh") {
        "Mac"
    } else if ua.contains("Linux") {
        "Linux"
    } else {
        ""
    };
    let browser = if ua.contains("Edg/") {
        "Edge"
    } else if ua.contains("Firefox/") {
        "Firefox"
    } else if ua.contains("Chrome/") {
        "Chrome"
    } else if ua.contains("Safari/") {
        "Safari"
    } else {
        ""
    };
    let name = format!("{os} {browser}").trim().to_string();
    if name.is_empty() {
        "Browser".to_string()
    } else {
        name
    }
}

#[derive(Debug, Deserialize)]
pub struct EnrollmentQuery {
    #[serde(default)]
    pub next: Option<String>,
}

fn ticket(state: &WebState, headers: &HeaderMap) -> Option<String> {
    cookies::get(
        headers,
        &state.origin_bound_cookie(cookies::DEVICE_ENROLLMENT_COOKIE),
    )
    .filter(|t| !t.is_empty())
}

fn expired_page(messages: &Messages) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Html(render(&MessagePage {
            lang: messages.lang(),
            title: messages.get("device-enrollment-title"),
            message: messages.get("device-enrollment-expired"),
        })),
    )
        .into_response()
}

/// 登録の画面（`GET /{t}/device-enrollment`）。
pub async fn page(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<EnrollmentQuery>,
) -> Response {
    let Some(ticket) = ticket(&state, &headers) else {
        return expired_page(&Messages::new(locale(&headers)));
    };
    let req = InternalDeviceEnrollmentDescribeRequest {
        tenant_id: Some(tenant.0.clone()),
        ticket,
    };
    let result = match state
        .api
        .device_enrollment_describe(&correlation.0, &req)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "device enrollment describe call failed");
            return internal_call_status(&e).into_response();
        }
    };
    let messages = Messages::new(locale(&headers));
    match result {
        InternalDeviceEnrollmentDescribeResponse::Ok { username } => {
            let next = safe_next(&tenant, query.next.as_deref());
            let device_name =
                suggested_device_name(headers.get(USER_AGENT).and_then(|v| v.to_str().ok()));
            Html(render(&DeviceEnrollmentPage {
                messages: &messages,
                tenant_prefix: &tenant.prefix(),
                username: &username,
                device_name: &device_name,
                next: &next,
                app_approval_offered: state.config.app_approver_enabled(),
            }))
            .into_response()
        }
        InternalDeviceEnrollmentDescribeResponse::TicketInvalid => expired_page(&messages),
        InternalDeviceEnrollmentDescribeResponse::Internal => {
            api_internal_error("device_enrollment_describe")
        }
    }
}

/// パスキーの確かめを始める（`POST /{t}/device-enrollment/begin`。JSON）。
pub async fn begin_api(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
) -> Response {
    let Some(ticket) = ticket(&state, &headers) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let req = InternalDeviceEnrollmentBeginRequest {
        tenant_id: Some(tenant.0.clone()),
        ticket,
    };
    match state
        .api
        .device_enrollment_begin(&correlation.0, &req)
        .await
    {
        Ok(InternalDeviceEnrollmentBeginResponse::Ok {
            challenge_id,
            options,
        }) => Json(serde_json::json!({ "challenge_id": challenge_id, "options": options }))
            .into_response(),
        Ok(InternalDeviceEnrollmentBeginResponse::TicketInvalid) => {
            StatusCode::BAD_REQUEST.into_response()
        }
        Ok(InternalDeviceEnrollmentBeginResponse::Internal) => {
            api_internal_error("device_enrollment_begin")
        }
        Err(e) => {
            tracing::error!(error = %e, "device enrollment begin call failed");
            internal_call_status(&e).into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CompleteBody {
    pub challenge_id: String,
    pub credential: serde_json::Value,
    #[serde(default)]
    pub device_name: String,
    #[serde(default)]
    pub next: Option<String>,
}

/// `passkey-login.js` が受ける形（ログインの完了と同じ）。
#[derive(Debug, Serialize)]
struct CompleteJson {
    redirect_to: Option<String>,
    error: Option<&'static str>,
}

/// パスキーで確かめて登録し、ログインする（`POST /{t}/device-enrollment/complete`。JSON）。
pub async fn complete_api(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Json(body): Json<CompleteBody>,
) -> Response {
    let Some(ticket) = ticket(&state, &headers) else {
        return Json(CompleteJson {
            redirect_to: None,
            error: Some("ticket_invalid"),
        })
        .into_response();
    };
    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let req = InternalDeviceEnrollmentCompleteRequest {
        tenant_id: Some(tenant.0.clone()),
        ticket,
        challenge_id: body.challenge_id,
        credential: body.credential,
        device_name: body.device_name,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let outcome = match state
        .api
        .device_enrollment_complete(&ctx.correlation_id, &req)
        .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "device enrollment complete call failed");
            return internal_call_status(&e).into_response();
        }
    };
    let error = |code: &'static str| {
        Json(CompleteJson {
            redirect_to: None,
            error: Some(code),
        })
        .into_response()
    };
    match outcome {
        InternalDeviceEnrollmentCompleteResponse::Enrolled {
            sso_session_id,
            sso_absolute_ttl_secs,
        } => {
            let set_cookies = state
                .set_cookies()
                .set_session(
                    cookies::SSO_SESSION_COOKIE,
                    &sso_session_id,
                    sso_absolute_ttl_secs,
                )
                .expire_local(&state.origin_bound_cookie(cookies::DEVICE_ENROLLMENT_COOKIE));
            (
                set_cookies.into_headers(),
                Json(CompleteJson {
                    redirect_to: Some(safe_next(&tenant, body.next.as_deref())),
                    error: None,
                }),
            )
                .into_response()
        }
        InternalDeviceEnrollmentCompleteResponse::TicketInvalid => error("ticket_invalid"),
        InternalDeviceEnrollmentCompleteResponse::PasskeyRejected => error("invalid_credential"),
        InternalDeviceEnrollmentCompleteResponse::InvalidName => error("invalid_name"),
        InternalDeviceEnrollmentCompleteResponse::AccountUnavailable => {
            error("account_unavailable")
        }
        InternalDeviceEnrollmentCompleteResponse::Internal => {
            api_internal_error("device_enrollment_complete")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant() -> WebTenant {
        WebTenant("01a00dfe-bffb-7f23-88b5-8bbef50d23f0".to_string())
    }

    #[test]
    fn only_paths_of_the_same_tenant_are_accepted_as_next() {
        let t = tenant();
        let prefix = t.prefix();
        assert_eq!(
            safe_next(&t, Some(&format!("{prefix}/login"))),
            format!("{prefix}/login")
        );
        for bad in [
            "https://evil.example/".to_string(),
            "//evil.example/".to_string(),
            format!("{prefix}//evil.example"),
            format!("{prefix}\\evil"),
            "/00000000-0000-7000-8000-000000000001/login".to_string(),
        ] {
            assert_eq!(
                safe_next(&t, Some(&bad)),
                format!("{prefix}/settings"),
                "{bad}"
            );
        }
        assert_eq!(safe_next(&t, None), format!("{prefix}/settings"));
    }

    #[test]
    fn the_suggested_name_reads_the_platform_and_the_browser() {
        assert_eq!(
            suggested_device_name(Some(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0 Safari/537.36"
            )),
            "Windows Chrome"
        );
        assert_eq!(
            suggested_device_name(Some(
                "Mozilla/5.0 (Linux; Android 16) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0 Mobile Safari/537.36"
            )),
            "Android Chrome"
        );
        assert_eq!(suggested_device_name(None), "Browser");
    }
}
