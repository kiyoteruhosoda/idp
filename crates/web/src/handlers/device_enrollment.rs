//! On-the-spot device registration when signing in correctly from an unregistered device (task #916. ADR-0079).
//!
//! In organizations limited to registered devices, any login path may "return an enrollment ticket without SSO".
//! web then puts the ticket in a cookie (origin-bound name, 10 minutes) and redirects to `GET /{t}/device-enrollment?next=…`.
//! The screen shows whose login it is; after confirming with a passkey it registers this browser as a device,
//! sets the SSO cookie and returns to `next` (the original screen). Mid OIDC authorization flow, `next` is the login screen,
//! and reopening it continues authorization from the new SSO (`login::continue_with_sso`).
//!
//! The passkey ceremony uses the same script as the login screen (`passkey-login.js`).

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

/// Lifetime of the ticket cookie (10 minutes, same as the api's ticket).
pub const DEVICE_ENROLLMENT_TTL_SECS: u64 = 600;

/// Maximum length of the return destination.
const MAX_NEXT_LEN: usize = 512;

/// Path of the enrollment screen (`{prefix}/device-enrollment?next=…`).
pub(crate) fn enrollment_location(tenant: &WebTenant, next: &str) -> String {
    format!(
        "{}/device-enrollment?next={}",
        tenant.prefix(),
        percent_encoding::utf8_percent_encode(next, percent_encoding::NON_ALPHANUMERIC)
    )
}

/// `Set-Cookie` placing the ticket in a cookie.
pub(crate) fn ticket_cookie(state: &WebState, ticket: &str) -> crate::cookies::SetCookies {
    state.set_cookies().set_local(
        &state.origin_bound_cookie(cookies::DEVICE_ENROLLMENT_COOKIE),
        ticket,
        DEVICE_ENROLLMENT_TTL_SECS,
    )
}

/// Places the ticket and redirects to the enrollment screen (302). `next` is the screen to return to after enrollment.
pub(crate) fn redirect(state: &WebState, tenant: &WebTenant, ticket: &str, next: &str) -> Response {
    (
        ticket_cookie(state, ticket).into_headers(),
        found(&enrollment_location(tenant, next)),
    )
        .into_response()
}

/// Whether the value is acceptable as a return destination (only this tenant's screen paths; never external).
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

/// Builds the initial device name from the browser's user agent (a display hint; the user can retype it).
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

/// Enrollment screen (`GET /{t}/device-enrollment`).
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

/// Starts the passkey check (`POST /{t}/device-enrollment/begin`. JSON).
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

/// Shape that `passkey-login.js` expects (same as login completion).
#[derive(Debug, Serialize)]
struct CompleteJson {
    redirect_to: Option<String>,
    error: Option<&'static str>,
}

/// Confirms with a passkey, registers and signs in (`POST /{t}/device-enrollment/complete`. JSON).
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
