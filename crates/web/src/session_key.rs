//! SSO セッションを端末の鍵へ結び付ける（Chrome の DBSC。task #887。ADR-0074）の web 側。
//!
//! | 役 | 何をするか |
//! |---|---|
//! | [`registration_header`] | ログインの応答（SSO セッションの Cookie を置いた応答）に `Secure-Session-Registration` を付ける |
//! | [`register`]（`POST /dbsc/register`） | Chrome の署名を api へ渡し、結び付いたら短い Cookie を出す |
//! | [`refresh`]（`POST /dbsc/refresh`） | 短い Cookie が切れたときの更新。署名が無ければ 403 で challenge を渡す |
//! | [`enforce`]（middleware） | 合う短い Cookie の無い要求で、結び付いたログイン状態なら長い Cookie を外す |
//!
//! 決まり（ヘッダーの名前・JSON の形）は W3C WebAppSec の草案（2026-09-08 版）と Chrome の資料に合わせた。

use crate::client_ip::ClientIp;
use crate::cookies::{self, SSO_SESSION_COOKIE};
use crate::correlation::CorrelationId;
use crate::state::WebState;
use assay_contracts::auth::{
    InternalSessionKeyBindingRequest, InternalSessionKeyBindingResponse,
    InternalSessionKeyRefreshRequest, InternalSessionKeyRegisterRequest,
    InternalSessionKeyResponse,
};
use assay_contracts::session_key as contract;
use axum::extract::{Request, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, COOKIE, SET_COOKIE, USER_AGENT};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 「結び付いているか」の答えを覚えておく長さ。
const BINDING_CACHE_TTL: Duration = Duration::from_secs(60);
/// 覚えておく件数の上限（越えたら古いものを捨てる）。
const BINDING_CACHE_MAX: usize = 10_000;

/// 「この SSO セッションは結び付いているか」の答えを短く覚える（入口で毎回 api を呼ばないため）。
///
/// 鍵は SSO セッションの Cookie の SHA-256（平文を持たない）。結び付けは「無い → ある」にしか変わらないので、
/// 「無い」を 60 秒覚えると、結び付いた直後の 60 秒は長い Cookie だけでも通る（その間に Chrome は短い Cookie を
/// 受け取っている）。
#[derive(Clone, Default)]
pub struct SessionKeyCache {
    entries: Arc<Mutex<HashMap<String, (bool, Instant)>>>,
}

impl SessionKeyCache {
    fn get(&self, key: &str) -> Option<bool> {
        let entries = self.entries.lock().ok()?;
        entries
            .get(key)
            .filter(|(_, at)| at.elapsed() < BINDING_CACHE_TTL)
            .map(|(bound, _)| *bound)
    }

    fn put(&self, key: String, bound: bool) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        if entries.len() >= BINDING_CACHE_MAX {
            entries.retain(|_, (_, at)| at.elapsed() < BINDING_CACHE_TTL);
            if entries.len() >= BINDING_CACHE_MAX {
                entries.clear();
            }
        }
        entries.insert(key, (bound, Instant::now()));
    }

    /// 結び付いたと分かったときに覚え直す（登録の直後）。
    pub fn mark_bound(&self, sso_session_id: &str) {
        self.put(cache_key(sso_session_id), true);
    }
}

fn cache_key(sso_session_id: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(sso_session_id.as_bytes()))
}

fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

/// ログインの応答に付ける `Secure-Session-Registration`（新しく置いた SSO セッションの Cookie の値で作る）。
pub fn registration_header(state: &WebState, sso_session_id: &str) -> Option<HeaderValue> {
    let challenge = contract::challenge(state.config.csrf_secret(), sso_session_id, now_secs());
    HeaderValue::from_str(&contract::registration_header(&challenge)).ok()
}

/// 短い Cookie のブラウザ上の名前（HTTPS では `__Host-` 前置）。
fn bound_cookie_name(state: &WebState) -> String {
    state
        .config
        .cookie_policy()
        .origin_bound_name(contract::BOUND_COOKIE)
}

/// このブラウザの短い Cookie の期限（UNIX 秒）。無い・合わない・切れているなら `None`（task #896）。
pub fn bound_cookie_expiry(
    state: &WebState,
    headers: &axum::http::HeaderMap,
    sso_session_id: &str,
) -> Option<i64> {
    let value = crate::cookies::get(headers, &bound_cookie_name(state))?;
    contract::bound_cookie_expires_at(
        state.config.csrf_secret(),
        sso_session_id,
        &value,
        now_secs(),
    )
}

/// 短い Cookie を置く `Set-Cookie`。
fn set_bound_cookie(state: &WebState, sso_session_id: &str) -> String {
    let expires_at = now_secs() + contract::BOUND_COOKIE_MAX_AGE_SECS;
    let value = contract::bound_cookie(state.config.csrf_secret(), sso_session_id, expires_at);
    state.config.cookie_policy().set_local(
        &bound_cookie_name(state),
        &value,
        contract::BOUND_COOKIE_MAX_AGE_SECS as u64,
    )
}

/// 短い Cookie の属性（登録の応答の `credentials` に書く。Chrome はこれで Cookie を見分ける。Max-Age は見ない）。
fn bound_cookie_attributes(state: &WebState) -> String {
    let mut attributes = "Path=/; HttpOnly; SameSite=Lax".to_string();
    if state.config.cookie_policy().secure() {
        attributes.push_str("; Secure");
    }
    attributes
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

struct Caller {
    correlation_id: String,
    ip_address: Option<String>,
    user_agent: Option<String>,
}

fn caller(request: &Request) -> Caller {
    Caller {
        correlation_id: request
            .extensions()
            .get::<CorrelationId>()
            .map(|c| c.0.clone())
            .unwrap_or_default(),
        ip_address: request
            .extensions()
            .get::<ClientIp>()
            .and_then(|ip| ip.0.clone()),
        user_agent: header_str(request.headers(), USER_AGENT.as_str()).map(str::to_string),
    }
}

/// JSON の応答（キャッシュさせない）。
fn json_response(status: StatusCode, body: serde_json::Value) -> Response {
    let mut response = (status, body.to_string()).into_response();
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// 「このログイン状態の結び付けは終わり」（Chrome は結び付けを捨てる）。
fn terminated() -> Response {
    json_response(StatusCode::OK, serde_json::json!({ "continue": false }))
}

fn append_cookie(response: &mut Response, cookie: &str) {
    match HeaderValue::from_str(cookie) {
        Ok(value) => {
            response.headers_mut().append(SET_COOKIE, value);
        }
        Err(e) => tracing::error!(error = %e, "session key cookie is not a valid header value"),
    }
}

/// 結び付けが続いている応答に、短い Cookie と、置き直した長い Cookie（残りの長さ）を付ける。
fn add_bound_cookies(
    state: &WebState,
    response: &mut Response,
    sso_session_id: &str,
    remaining_secs: u64,
) {
    append_cookie(response, &set_bound_cookie(state, sso_session_id));
    for cookie in
        state
            .config
            .cookie_policy()
            .set_session(SSO_SESSION_COOKIE, sso_session_id, remaining_secs)
    {
        append_cookie(response, &cookie);
    }
}

/// ログイン状態を終わらせたときに、ブラウザの Cookie も消す。
fn expire_cookies(state: &WebState, response: &mut Response) {
    let policy = state.config.cookie_policy();
    append_cookie(response, &policy.expire_local(&bound_cookie_name(state)));
    for cookie in policy.expire_session(SSO_SESSION_COOKIE) {
        append_cookie(response, &cookie);
    }
}

/// 登録と更新の応答の本文（結び付けの設定。草案 §9.6）。
///
/// 範囲は assay のオリジンだけ（`include_site: false`）。各アプリから始まった要求（見えない枠の `prompt=none`）でも
/// Chrome が短い Cookie を取り直すよう、`allowed_refresh_initiators` に設定のホストの型を入れる（task #934）。
fn session_instructions(state: &WebState, session_identifier: &str) -> serde_json::Value {
    serde_json::json!({
        "session_identifier": session_identifier,
        "refresh_url": contract::REFRESH_PATH,
        "scope": {
            "include_site": false,
            "scope_specification": [],
        },
        "credentials": [{
            "type": "cookie",
            "name": bound_cookie_name(state),
            "attributes": bound_cookie_attributes(state),
        }],
        "allowed_refresh_initiators": state.config.dbsc_allowed_refresh_initiators(),
    })
}

/// 登録（`POST /dbsc/register`）。
pub async fn register(State(state): State<WebState>, request: Request) -> Response {
    let who = caller(&request);
    let headers = request.headers();
    let (Some(sso_session_id), Some(proof)) = (
        cookies::get(headers, SSO_SESSION_COOKIE),
        header_str(headers, contract::RESPONSE_HEADER).map(str::to_string),
    ) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let req = InternalSessionKeyRegisterRequest {
        sso_session_id: sso_session_id.clone(),
        proof,
        ip_address: who.ip_address,
        user_agent: who.user_agent,
    };
    match state
        .api
        .session_key_register(&who.correlation_id, &req)
        .await
    {
        Ok(InternalSessionKeyResponse::Bound {
            session_identifier,
            remaining_secs,
        }) => {
            state.session_keys.mark_bound(&sso_session_id);
            let mut response = json_response(
                StatusCode::OK,
                session_instructions(&state, &session_identifier),
            );
            add_bound_cookies(&state, &mut response, &sso_session_id, remaining_secs);
            response
        }
        Ok(InternalSessionKeyResponse::KeyMismatch) => {
            let mut response = StatusCode::BAD_REQUEST.into_response();
            expire_cookies(&state, &mut response);
            response
        }
        Ok(InternalSessionKeyResponse::Internal) | Err(_) => {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Ok(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}

/// 更新（`POST /dbsc/refresh`）。
pub async fn refresh(State(state): State<WebState>, request: Request) -> Response {
    let who = caller(&request);
    let headers = request.headers();
    let Some(sso_session_id) = cookies::get(headers, SSO_SESSION_COOKIE) else {
        return terminated();
    };
    let Some(session_identifier) = header_str(headers, contract::SESSION_ID_HEADER)
        .filter(|v| contract::is_session_identifier(v))
        .map(str::to_string)
    else {
        return terminated();
    };
    let Some(proof) = header_str(headers, contract::RESPONSE_HEADER).map(str::to_string) else {
        // 署名が無い 1 回目: challenge を渡す（その前に、結び付けが生きているかを確かめる）。
        return challenge_or_end(&state, &who, &sso_session_id, &session_identifier).await;
    };
    let req = InternalSessionKeyRefreshRequest {
        sso_session_id: sso_session_id.clone(),
        session_identifier: session_identifier.clone(),
        proof,
        ip_address: who.ip_address.clone(),
        user_agent: who.user_agent.clone(),
    };
    match state
        .api
        .session_key_refresh(&who.correlation_id, &req)
        .await
    {
        Ok(InternalSessionKeyResponse::Bound { remaining_secs, .. }) => {
            // 登録と同じ設定を返す。草案（§8.8・§8.9）では本文のある更新の応答で結び付けの設定が置き換わるので、
            // 設定を足す前に結び付いたログイン状態にも、次の更新で `allowed_refresh_initiators` が届く。
            let mut response = json_response(
                StatusCode::OK,
                session_instructions(&state, &session_identifier),
            );
            add_bound_cookies(&state, &mut response, &sso_session_id, remaining_secs);
            response
        }
        // 古い challenge など: 新しい challenge でもう一度。
        Ok(InternalSessionKeyResponse::Rejected) => {
            challenge_response(&state, &sso_session_id, &session_identifier)
        }
        Ok(InternalSessionKeyResponse::KeyMismatch) => {
            let mut response = terminated();
            expire_cookies(&state, &mut response);
            response
        }
        Ok(InternalSessionKeyResponse::SessionGone) => terminated(),
        // 一時的な失敗。Chrome は結び付けを保ったまま、あとでやり直す。
        Ok(InternalSessionKeyResponse::Internal) | Err(_) => {
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

async fn challenge_or_end(
    state: &WebState,
    who: &Caller,
    sso_session_id: &str,
    session_identifier: &str,
) -> Response {
    let req = InternalSessionKeyBindingRequest {
        sso_session_id: sso_session_id.to_string(),
    };
    match state
        .api
        .session_key_binding(&who.correlation_id, &req)
        .await
    {
        Ok(InternalSessionKeyBindingResponse::Bound {
            session_identifier: bound,
        }) if bound == session_identifier => {
            challenge_response(state, sso_session_id, session_identifier)
        }
        Ok(InternalSessionKeyBindingResponse::Internal) | Err(_) => {
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
        Ok(_) => terminated(),
    }
}

fn challenge_response(
    state: &WebState,
    sso_session_id: &str,
    session_identifier: &str,
) -> Response {
    let challenge = contract::challenge(state.config.csrf_secret(), sso_session_id, now_secs());
    let mut response = StatusCode::FORBIDDEN.into_response();
    match HeaderValue::from_str(&contract::challenge_header(&challenge, session_identifier)) {
        Ok(value) => {
            response
                .headers_mut()
                .insert(HeaderName::from_static(contract::CHALLENGE_HEADER), value);
        }
        Err(e) => tracing::error!(error = %e, "session challenge is not a valid header value"),
    }
    response
}

/// 入口の確かめ（middleware）。`bind_session_cookie_names` より内側、ハンドラより外側に置く。
///
/// 長い Cookie があって、合う短い Cookie が無い要求について、そのログイン状態が結び付いていれば長い Cookie を
/// 要求から外す（どの画面にも「ログインしていない」に見える）。`/dbsc/*`（登録・更新そのもの）と
/// `/assets/*` は見ない。api に聞けなかったときも外す（結び付いているかもしれないものを通さない）。
pub async fn enforce(State(state): State<WebState>, mut request: Request, next: Next) -> Response {
    let path = request.uri().path();
    if path.starts_with("/dbsc/") || path.starts_with("/assets/") {
        return next.run(request).await;
    }
    let Some(sso_session_id) = cookies::get(request.headers(), SSO_SESSION_COOKIE) else {
        return next.run(request).await;
    };
    if let Some(bound) = cookies::get(request.headers(), &bound_cookie_name(&state)) {
        if contract::bound_cookie_is_valid(
            state.config.csrf_secret(),
            &sso_session_id,
            &bound,
            now_secs(),
        ) {
            return next.run(request).await;
        }
    }
    let key = cache_key(&sso_session_id);
    let bound = match state.session_keys.get(&key) {
        Some(bound) => bound,
        None => {
            let correlation_id = caller(&request).correlation_id;
            let req = InternalSessionKeyBindingRequest {
                sso_session_id: sso_session_id.clone(),
            };
            match state.api.session_key_binding(&correlation_id, &req).await {
                Ok(InternalSessionKeyBindingResponse::Bound { .. }) => {
                    state.session_keys.put(key, true);
                    true
                }
                Ok(InternalSessionKeyBindingResponse::Unbound) => {
                    state.session_keys.put(key, false);
                    false
                }
                Ok(InternalSessionKeyBindingResponse::Internal) | Err(_) => {
                    tracing::error!(
                        "session key binding could not be checked; treating the session as absent"
                    );
                    true
                }
            }
        }
    };
    if bound {
        strip_session_cookie(request.headers_mut());
    }
    next.run(request).await
}

/// `Cookie` ヘッダーから SSO セッションの Cookie を外す（読み替え後の名前で。前置付きは読み替え済み）。
fn strip_session_cookie(headers: &mut HeaderMap) {
    let kept: Vec<String> = headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|raw| raw.split(';'))
        .map(str::trim)
        .filter(|pair| !pair.is_empty())
        .filter(|pair| pair.split_once('=').map_or(*pair, |(k, _)| k) != SSO_SESSION_COOKIE)
        .map(str::to_string)
        .collect();
    headers.remove(COOKIE);
    if kept.is_empty() {
        return;
    }
    if let Ok(value) = HeaderValue::from_str(&kept.join("; ")) {
        headers.insert(COOKIE, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stripping_removes_only_the_session_cookie() {
        let mut headers = HeaderMap::new();
        headers.append(
            COOKIE,
            HeaderValue::from_static("lang=ja; sso_session_id=abc; assay_device=d"),
        );
        headers.append(COOKIE, HeaderValue::from_static("theme=dark"));
        strip_session_cookie(&mut headers);
        let rebuilt = headers.get(COOKIE).unwrap().to_str().unwrap();
        assert_eq!(rebuilt, "lang=ja; assay_device=d; theme=dark");
        assert_eq!(cookies::get(&headers, SSO_SESSION_COOKIE), None);
    }

    #[test]
    fn stripping_the_only_cookie_leaves_no_cookie_header() {
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, HeaderValue::from_static("sso_session_id=abc"));
        strip_session_cookie(&mut headers);
        assert!(headers.get(COOKIE).is_none());
    }

    #[test]
    fn the_cache_remembers_answers_for_a_while() {
        let cache = SessionKeyCache::default();
        assert_eq!(cache.get(&cache_key("s")), None);
        cache.put(cache_key("s"), false);
        assert_eq!(cache.get(&cache_key("s")), Some(false));
        cache.mark_bound("s");
        assert_eq!(cache.get(&cache_key("s")), Some(true));
    }
}
