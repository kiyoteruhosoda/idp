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
pub(crate) fn trusted_country(headers: &HeaderMap, trust_forwarded: bool) -> Option<String> {
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

tokio::task_local! {
    /// 今の要求のブラウザの端末の印（task #916）。api クライアントが内部の呼び出しへ添える。
    static CLIENT_DEVICE: Option<String>;
}

/// 今の要求の端末の印（middleware の外・要求の外では `None`）。
pub fn current_device_token() -> Option<String> {
    CLIENT_DEVICE.try_with(Clone::clone).ok().flatten()
}

/// 応答が登録の札（task #916）を新しく置いたか（消す応答は除く）。
fn issued_enrollment_ticket(headers: &HeaderMap) -> bool {
    let base = crate::cookies::DEVICE_ENROLLMENT_COOKIE;
    headers
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|raw| {
            let mut parts = raw.split(';');
            let Some((name, value)) = parts.next().and_then(|p| p.trim().split_once('=')) else {
                return false;
            };
            let name = name
                .strip_prefix(assay_contracts::cookies::HOST_PREFIX)
                .unwrap_or(name);
            name == base
                && !value.is_empty()
                && !parts.any(|attr| attr.trim().eq_ignore_ascii_case("max-age=0"))
        })
}

/// middleware 本体（router の外側寄り、`correlation::propagate` の内側に置く）。
///
/// 端末の印は**要求の前に**決める（task #916）。無ければここで作り、要求の間だけ
/// [`current_device_token`] に置く。api はログインのその場で「登録した端末か」を決めるので、初めての
/// ブラウザでも印が届いている必要がある。作った印を Cookie に置くのは、応答がログイン状態か登録の札を
/// 置いたときだけ（ただ見に来ただけのブラウザには置かない）。
pub async fn observe_sign_ins(
    State(state): State<WebState>,
    request: Request,
    next: Next,
) -> Response {
    let existing = cookies::get(request.headers(), DEVICE_COOKIE).filter(|v| is_device_token(v));
    let (token, generated) = match existing {
        Some(token) => (token, false),
        None => (new_device_token(), true),
    };
    let country = trusted_country(request.headers(), state.config.trust_forwarded_headers());
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

    // 端末の鍵への結び付けの口（task #887）は、長い Cookie を置き直すだけでログインではない。
    let key_binding_path = request.uri().path().starts_with("/dbsc/");
    // 要求に付いてきた SSO セッション。SSO の復元は同じ値の Cookie を置き直す（ADR-0018 決定 4）ので、
    // 結び付けを求めるのは**値が変わった**とき（新しいログイン状態）だけにする。同じログイン状態で
    // Chrome に登録をやり直させると、新しい鍵が「別の鍵」になり、ログイン状態を終わらせてしまう。
    let incoming_sso = cookies::get(request.headers(), cookies::SSO_SESSION_COOKIE);
    let mut response = CLIENT_DEVICE
        .scope(Some(token.clone()), next.run(request))
        .await;
    if key_binding_path {
        return response;
    }
    let issued_sso = issued_sso_session(response.headers());
    if generated && (issued_sso.is_some() || issued_enrollment_ticket(response.headers())) {
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
    }
    let Some(sso_session_id) = issued_sso else {
        return response;
    };
    // 新しいログイン状態を端末の鍵へ結び付けるよう Chrome に求める（DBSC。task #887・ADR-0074）。
    let new_session = incoming_sso.as_deref() != Some(sso_session_id.as_str());
    if let Some(value) = new_session
        .then(|| crate::session_key::registration_header(&state, &sso_session_id))
        .flatten()
    {
        response.headers_mut().insert(
            axum::http::HeaderName::from_static(assay_contracts::session_key::REGISTRATION_HEADER),
            value,
        );
    }

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
        assert_eq!(trusted_country(&h, true).as_deref(), Some("JP"));
        assert_eq!(trusted_country(&h, false), None);
        h.insert(COUNTRY_HEADER, HeaderValue::from_static(""));
        assert_eq!(trusted_country(&h, true), None);
    }
}
