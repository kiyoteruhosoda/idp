//! ログインした端末を api へ伝える middleware（task #872。ADR-0071）。
//!
//! ログインの経路は 5 つ（OIDC・MFA・パスキー・ポータル・管理コンソール）に外部 IdP とパスワード変更が
//! 加わり、どれも最後に SSO セッションの Cookie を置いて終わる。経路ごとに呼び出しを足すと漏れるので、
//! **応答が SSO セッションの Cookie を新しく置いたこと**だけを見て、1 か所で次を行う:
//!
//! 1. 端末の印（[`DEVICE_COOKIE`]）が無ければ作って置く（400 日。使うたびに置き直さない）
//! 2. api の `/internal/devices/observe` へ「このセッションはこの端末で作られた」と伝える
//!
//! ⚠ **伝えるのに失敗してもログインは止めない**（応答はもう出来上がっている）。失敗はエラーログに残す。
//!
//! 国（`CF-IPCountry`）は `TRUST_FORWARDED_HEADERS` が有効なときだけ読む（`X-Forwarded-For` と同じ扱い）。
//! 家の中からの通信は homeedge がこの項目を空にして渡す（deploy-repo）。

use crate::client_ip::ClientIp;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::state::WebState;
use assay_contracts::auth::{InternalDeviceObserveRequest, InternalDeviceObserveResponse};
use axum::extract::{Request, State};
use axum::http::header::{SET_COOKIE, USER_AGENT};
use axum::http::{HeaderMap, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;

/// 端末の印の Cookie 名。値は 64 文字の 16 進（推測できない乱数）。
pub const DEVICE_COOKIE: &str = "assay_device";
/// 端末の印の寿命（Chrome が受け付ける上限の 400 日）。
pub const DEVICE_COOKIE_MAX_AGE_SECS: u64 = 400 * 24 * 60 * 60;
/// Cloudflare が付ける国の項目。
const COUNTRY_HEADER: &str = "cf-ipcountry";

/// 端末の印として受け付ける形か（64 文字の 16 進）。壊れた値は無いものとして作り直す。
pub fn is_device_token(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// 新しい端末の印。UUID v4 2 つ分（OS の乱数）。
pub fn new_device_token() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

/// 応答が SSO セッションの Cookie を**新しく置いた**なら、その値を返す（消す応答は除く）。
pub fn issued_sso_session(headers: &HeaderMap) -> Option<String> {
    let base = cookies::SSO_SESSION_COOKIE;
    let prefixed = format!("{}{base}", assay_contracts::cookies::HOST_PREFIX);
    headers
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|raw| {
            let mut parts = raw.split(';');
            let (name, value) = parts.next()?.trim().split_once('=')?;
            if name != base && name != prefixed {
                return None;
            }
            let expired = parts.any(|attr| {
                let attr = attr.trim().to_ascii_lowercase();
                attr == "max-age=0" || attr.starts_with("expires=thu, 01 jan 1970")
            });
            (!value.is_empty() && !expired).then(|| value.to_string())
        })
}

/// 信じてよい国の項目（形の確かめは api が行う）。
fn country(headers: &HeaderMap, trust_forwarded: bool) -> Option<String> {
    if !trust_forwarded {
        return None;
    }
    headers
        .get(COUNTRY_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// middleware 本体（router の外側寄り、`correlation::propagate` の内側に置く）。
pub async fn observe_sign_ins(
    State(state): State<WebState>,
    request: Request,
    next: Next,
) -> Response {
    let existing = cookies::get(request.headers(), DEVICE_COOKIE).filter(|v| is_device_token(v));
    let country = country(request.headers(), state.config.trust_forwarded_headers());
    let user_agent = request
        .headers()
        .get(USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let ip_address = request
        .extensions()
        .get::<ClientIp>()
        .and_then(|ip| ip.0.clone());
    let correlation_id = request
        .extensions()
        .get::<CorrelationId>()
        .map(|c| c.0.clone())
        .unwrap_or_default();

    let mut response = next.run(request).await;
    let Some(sso_session_id) = issued_sso_session(response.headers()) else {
        return response;
    };

    let token = match existing {
        Some(token) => token,
        None => {
            let token = new_device_token();
            let cookie = state.config.cookie_policy().set_local(
                DEVICE_COOKIE,
                &token,
                DEVICE_COOKIE_MAX_AGE_SECS,
            );
            match HeaderValue::from_str(&cookie) {
                Ok(value) => {
                    response.headers_mut().append(SET_COOKIE, value);
                }
                Err(e) => tracing::error!(error = %e, "device cookie is not a valid header value"),
            }
            token
        }
    };

    let request = InternalDeviceObserveRequest {
        sso_session_id,
        device_token: Some(token),
        country,
        ip_address,
        user_agent,
    };
    match state.api.device_observe(&correlation_id, &request).await {
        Ok(InternalDeviceObserveResponse::Internal) => {
            tracing::error!("device observation failed in api; the sign-in itself succeeded");
        }
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "device observation call to api failed; the sign-in itself succeeded");
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(values: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in values {
            h.append(SET_COOKIE, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn a_newly_issued_session_cookie_is_found_with_or_without_the_host_prefix() {
        assert_eq!(
            issued_sso_session(&headers(&[
                "lang=ja; Path=/",
                "__Host-sso_session_id=abc; Path=/; HttpOnly; Secure; Max-Age=86400"
            ]))
            .as_deref(),
            Some("abc")
        );
        assert_eq!(
            issued_sso_session(&headers(&["sso_session_id=xyz; Path=/; Max-Age=600"])).as_deref(),
            Some("xyz")
        );
    }

    #[test]
    fn clearing_the_session_cookie_is_not_a_sign_in() {
        assert_eq!(
            issued_sso_session(&headers(&["sso_session_id=; Path=/; Max-Age=0"])),
            None
        );
        assert_eq!(
            issued_sso_session(&headers(&["__Host-sso_session_id=gone; Path=/; Max-Age=0"])),
            None
        );
        assert_eq!(
            issued_sso_session(&headers(&["auth_session_id=abc; Path=/"])),
            None
        );
    }

    #[test]
    fn device_tokens_are_64_hex_characters() {
        let token = new_device_token();
        assert!(is_device_token(&token));
        assert_ne!(token, new_device_token());
        assert!(!is_device_token("short"));
        assert!(!is_device_token(&"z".repeat(64)));
    }

    #[test]
    fn the_country_is_read_only_when_forwarded_headers_are_trusted() {
        let mut h = HeaderMap::new();
        h.insert(COUNTRY_HEADER, HeaderValue::from_static("JP"));
        assert_eq!(country(&h, true).as_deref(), Some("JP"));
        assert_eq!(country(&h, false), None);
        h.insert(COUNTRY_HEADER, HeaderValue::from_static(""));
        assert_eq!(country(&h, true), None);
    }
}
