//! web の統合テスト共通土台（G11）。
//!
//! web は DB を持たず、データ操作はすべて api への HTTP 呼び出しである（ADR-0007）。したがって
//! **api を HTTP でスタブすれば、ルータ経由の振る舞いを DB 無しで検証できる**。ここで見たいのは
//! ハンドラ内の純関数ではなく、その外側 —— Cookie の発行と読み出し、CSRF の同期トークン、
//! リダイレクトの行き先とステータス、そして api が落ちているときの処理である。いずれも
//! `#[test]` の単体検証では通らない経路で、これまで `scripts/e2e.sh` のシェルスクリプトだけが
//! 通していた。
//!
//! # 設定の渡し方（環境変数を掴む理由）
//!
//! `Config::from_env()` は環境変数から読む。スタブサーバの URL は起動するまで決まらない
//! （ポートが動的）ため、`API_BASE_URL` を立ててから設定を組む必要がある。環境変数はプロセス
//! 全体で共有なので、**「立てる → 設定を組む」までを 1 つのロックで囲う**。組み上がった
//! `Config` は自分の写しを持つので、その後で別のテストが同じ変数を書き換えても影響しない。
//!
//! # 秘密鍵を実行環境から受け取らない
//!
//! `CSRF_SECRET` は**テスト側で固定する**（[`TEST_CSRF_SECRET`]）。CI は job の環境変数として
//! 独自の `CSRF_SECRET` を渡すため、そのまま `Config::from_env()` に拾わせるとルータは CI の鍵で
//! トークンを検証し、テストが手元の鍵で作ったトークンと必ず食い違う —— ローカルでは通り CI だけが
//! 落ちる、いちばん読み解きにくい形の失敗になる。同じ理由で `INTERNAL_SERVICE_TOKEN` も固定する。

#![allow(dead_code)]

use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE};
use axum::http::{Method, Request, Response, StatusCode};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use idp_web::config::Config;
use idp_web::router;
use idp_web::state::WebState;
use std::sync::{Arc, Mutex, OnceLock};
use tower::ServiceExt;
use wiremock::MockServer;

/// api のスタブと、それを向いた web ルータ。
pub struct WebEnv {
    pub app: axum::Router,
    pub api: MockServer,
    pub tenant: String,
}

impl WebEnv {
    /// `/{tenant_id}` プレフィクス。
    pub fn prefix(&self) -> String {
        format!("/{}", self.tenant)
    }
}

/// テストが使う CSRF 鍵（ちょうど 32 バイト）。フォームへ出るトークンをテスト側で導出するために、
/// ルータと同じ値を使う必要がある。実行環境の値は使わない（モジュールコメント参照）。
pub const TEST_CSRF_SECRET: &[u8; 32] = b"idp-web-integration-test-csrf-32";

/// テストが使うサービス間トークン（長さの下限は `idp_contracts::deployment` の契約が決める）。
pub const TEST_INTERNAL_SERVICE_TOKEN: &str = "idp-web-integration-test-service-token";

/// 環境変数を書き換えて設定を組むまでの排他区間（モジュールコメント参照）。
fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// api のスタブを起動し、そこを向いた web ルータを組む。
pub async fn setup() -> WebEnv {
    let api = MockServer::start().await;
    let uri = api.uri();
    let app = build_app(&uri);
    WebEnv {
        app,
        api,
        tenant: uuid::Uuid::now_v7().to_string(),
    }
}

/// **誰も listen していない**宛先を向いた web ルータ（api 障害の検証用）。
///
/// スタブサーバを drop して落とす方法は使わない。停止が完了する前に届いた要求へ 404 が返り、
/// 「api 不通」ではなく「テナントが無い」として扱われて偽陰性になる。閉じたポートなら接続が
/// 即座に拒否され、常に同じ経路（api 呼び出しの失敗）を通る。
pub fn unreachable_api_app() -> axum::Router {
    build_app("http://127.0.0.1:1")
}

fn build_app(api_base_url: &str) -> axum::Router {
    let config = {
        let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("API_BASE_URL", api_base_url);
        // 秘密は実行環境から受け取らない（CI の値を拾うとテストの鍵と食い違う）。
        std::env::set_var("CSRF_SECRET", STANDARD.encode(TEST_CSRF_SECRET));
        std::env::set_var("INTERNAL_SERVICE_TOKEN", TEST_INTERNAL_SERVICE_TOKEN);
        // 開発用の既定シークレットで起動できるよう、公開オリジンはループバックのままにする
        //（本番相当のオリジンでは fail-fast する。SEC11）。
        std::env::remove_var("PUBLIC_WEB_BASE_URL");
        std::env::remove_var("COOKIE_DOMAIN");
        Config::from_env().expect("load web config")
    };
    router::build(WebState::build(Arc::new(config)))
}

/// テナント経路の組み立て（`unreachable_api_app` は `WebEnv` を持たないため単体で使う）。
pub fn tenant_prefix() -> String {
    format!("/{}", uuid::Uuid::now_v7())
}

pub async fn send(app: &axum::Router, request: Request<Body>) -> Response<Body> {
    app.clone().oneshot(request).await.expect("send request")
}

pub fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

pub fn get_with_cookies(uri: &str, cookies: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header(COOKIE, cookies)
        .body(Body::empty())
        .unwrap()
}

/// `application/x-www-form-urlencoded` の POST（画面のフォーム送信と同じ形）。
pub fn post_form(uri: &str, cookies: Option<&str>, fields: &[(&str, &str)]) -> Request<Body> {
    let body = fields
        .iter()
        .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(cookies) = cookies {
        builder = builder.header(COOKIE, cookies);
    }
    builder.body(Body::from(body)).unwrap()
}

fn urlencode(value: &str) -> String {
    percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC).to_string()
}

pub async fn body_text(response: Response<Body>) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    String::from_utf8_lossy(&bytes).into_owned()
}

pub fn location(response: &Response<Body>) -> String {
    response
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

/// 応答の `Set-Cookie` から指定名の値を取り出す（削除指示＝空値も value として返す）。
pub fn set_cookie(response: &Response<Body>, name: &str) -> Option<String> {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|raw| {
            let (pair, _) = raw.split_once(';').unwrap_or((raw, ""));
            let (key, value) = pair.split_once('=')?;
            (key.trim() == name).then(|| value.trim().to_string())
        })
}

/// 応答の `Set-Cookie` 1 本の生の文字列（属性まで検証したいとき）。
pub fn set_cookie_raw(response: &Response<Body>, name: &str) -> Option<String> {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|raw| raw.starts_with(&format!("{name}=")))
        .map(str::to_string)
}

pub fn assert_status(response: &Response<Body>, expected: StatusCode, context: &str) {
    assert_eq!(response.status(), expected, "{context}");
}
