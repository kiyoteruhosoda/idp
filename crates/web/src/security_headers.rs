//! セキュリティヘッダミドルウェア（SEC3。api の `security_headers` と同方針）。
//!
//! web は HTML（ログイン画面・管理コンソール）を配信するため、全レスポンスに以下を付与する:
//! - `X-Content-Type-Options: nosniff`
//! - `Referrer-Policy: strict-origin-when-cross-origin`
//! - `X-Frame-Options: DENY`（クリックジャッキング対策）
//! - `Content-Security-Policy`（`frame-ancestors 'none'`・外部オリジン読み込み禁止）
//!
//! さらに `hsts_max_age > 0` のときは `Strict-Transport-Security` を付与する。
//!
//! `script-src` から `'unsafe-inline'` を外してある（SEC12）。インラインを許したままでは、
//! 反射型 XSS が 1 か所でもあれば CSP が防御にならない。画面固有スクリプトはすべて自オリジンの
//! アセット（`handlers::page_scripts`）へ切り出し、テンプレートが渡していた値は `data-*` 属性で
//! 受け渡している。
//!
//! `style-src` の `'unsafe-inline'` は残している。現行テンプレートが `style="display:none"` の
//! ような属性を多数使っており、これらは**スクリプト実行につながらない**（`style-src` は
//! `javascript:` を持ち込めない）ため、優先度が違う。外すならクラス化とセットで行う。

use axum::extract::Request;
use axum::http::header::{HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;

/// 自オリジン限定の CSP。スクリプトはインラインを許さない（SEC12）。
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; \
     script-src 'self'; \
     style-src 'self' 'unsafe-inline'; \
     img-src 'self' data:; \
     object-src 'none'; \
     base-uri 'self'; \
     form-action 'self'; \
     frame-ancestors 'none'";

/// フォーム送信の遷移先が外部オリジンになるページ向けの CSP（既定に `form-action` の許可を 1 つ足す）。
///
/// **Chrome は `form-action` をフォーム送信後のリダイレクト先にも適用する**（CSP3 の仕様とは
/// 異なるが、長年そうなっている）。ログイン画面と同意画面は、送信のあと RP の `redirect_uri` へ
/// 302 して終わるため、既定の `form-action 'self'` のままだと **サーバは同意を記録しコードも
/// 発行したのに、ブラウザが RP へ戻れない**。原因が画面にもログにも出ない止まり方になる。
///
/// 許可するのは**その認可要求の `redirect_uri` のオリジン 1 つだけ**である（登録済みの値と完全
/// 一致したものが渡ってくる）。SAML の ACS へ POST するページも同じ事情で同じ形を採っている
/// （`handlers::saml_sso`）。`origin` が空なら既定の CSP をそのまま返す。
pub fn csp_allowing_form_action(origin: &str) -> String {
    if origin.is_empty() {
        return CONTENT_SECURITY_POLICY.to_string();
    }
    CONTENT_SECURITY_POLICY.replace(
        "form-action 'self'",
        &format!("form-action 'self' {origin}"),
    )
}

/// URL からスキーム + ホスト（+ ポート）を取り出す。CSP の source は path を持てないため。
/// 解釈できない URL は空文字（＝許可を足さない。fail-closed）。
pub fn origin_of(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|parsed| {
            let host = parsed.host_str()?.to_string();
            Some(match parsed.port() {
                Some(port) => format!("{}://{host}:{port}", parsed.scheme()),
                None => format!("{}://{host}", parsed.scheme()),
            })
        })
        .unwrap_or_default()
}

/// フォーム送信の遷移先が外部オリジンになる HTML 応答を、その許可を足した CSP で返す。
///
/// middleware はハンドラが設定済みの CSP を尊重するので、ここで差し替えたものがそのまま出る。
/// `redirect_uri` が解釈できないときは既定の CSP のまま返す（許可を足さない。fail-closed）。
pub fn html_with_form_action_csp(redirect_uri: &str, body: String) -> Response {
    use axum::response::{Html, IntoResponse};
    let csp = csp_allowing_form_action(&origin_of(redirect_uri));
    match HeaderValue::from_str(&csp) {
        Ok(value) => (
            [(axum::http::header::CONTENT_SECURITY_POLICY, value)],
            Html(body),
        )
            .into_response(),
        // 組み立てに失敗したら既定の CSP のまま返す。壊れたヘッダを送るより安全側。
        Err(_) => Html(body).into_response(),
    }
}

/// セキュリティヘッダを付与するミドルウェアファクトリ。`hsts_max_age` が `0` のときは HSTS を付与しない。
pub async fn add_security_headers(request: Request, next: Next, hsts_max_age: u64) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    // ハンドラが応答に CSP を設定済みの場合は尊重する（RP-initiated logout の front-channel ページが
    // 通知先オリジンだけ `frame-src` を許可した CSP を使う。`handlers::rp_logout`）。
    let csp = HeaderName::from_static("content-security-policy");
    if !headers.contains_key(&csp) {
        headers.insert(csp, HeaderValue::from_static(CONTENT_SECURITY_POLICY));
    }

    if hsts_max_age > 0 {
        if let Ok(value) = HeaderValue::from_str(&format!("max-age={hsts_max_age}")) {
            headers.insert(HeaderName::from_static("strict-transport-security"), value);
        }
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Chrome は `form-action` をフォーム送信後のリダイレクト先にも適用する。** ログイン画面と
    /// 同意画面の送信は RP の `redirect_uri` への 302 で終わるので、そのオリジンを許可しないと
    /// 「同意も code 発行も成功したのにブラウザが RP へ戻らない」という、画面にもログにも
    /// 出ない止まり方をする（2026-08-27 に blobshare の本番ログインで踏んだ）。
    #[test]
    fn the_relying_party_origin_is_allowed_for_form_action() {
        let csp = csp_allowing_form_action("https://share.example.com");
        assert!(
            csp.contains("form-action 'self' https://share.example.com;"),
            "{csp}"
        );
        // 他のディレクティブは既定のまま（緩めない）。
        assert!(csp.contains("script-src 'self';"), "{csp}");
        assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
    }

    /// オリジンが取れないときは既定のまま返す（許可を足さない。fail-closed）。
    #[test]
    fn an_unusable_redirect_uri_leaves_the_policy_untouched() {
        assert_eq!(csp_allowing_form_action(""), CONTENT_SECURITY_POLICY);
        assert_eq!(origin_of("not a url"), "");
        assert_eq!(origin_of(""), "");
    }

    /// CSP の source は path を持てないので、スキーム + ホスト（+ ポート）まで切り詰める。
    #[test]
    fn only_the_origin_of_the_redirect_uri_is_used() {
        assert_eq!(
            origin_of("https://share.example.com/api/auth/oidc/callback"),
            "https://share.example.com"
        );
        assert_eq!(
            origin_of("http://localhost:8080/cb?x=1#f"),
            "http://localhost:8080"
        );
    }
    use axum::body::Body;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    async fn respond(app: Router, uri: &str) -> Response {
        app.oneshot(
            axum::http::Request::builder()
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
    }

    fn app(hsts_max_age: u64) -> Router {
        Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(move |req, next| {
                add_security_headers(req, next, hsts_max_age)
            }))
    }

    #[tokio::test]
    async fn adds_security_headers_to_every_response() {
        let res = respond(app(0), "/").await;
        let headers = res.headers();
        assert_eq!(headers["x-content-type-options"], "nosniff");
        assert_eq!(headers["x-frame-options"], "DENY");
        assert_eq!(
            headers["referrer-policy"],
            "strict-origin-when-cross-origin"
        );
        let csp = headers["content-security-policy"].to_str().unwrap();
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(csp.contains("default-src 'self'"));
        // インラインスクリプトを許さない（SEC12）。許すと XSS 1 か所で CSP が無力になる。
        assert!(
            !csp.contains("script-src 'self' 'unsafe-inline'"),
            "script-src must not allow inline: {csp}"
        );
        // HSTS は hsts_max_age = 0 では付与しない。
        assert!(!headers.contains_key("strict-transport-security"));
    }

    #[tokio::test]
    async fn adds_hsts_when_max_age_is_positive() {
        let res = respond(app(31_536_000), "/").await;
        assert_eq!(
            res.headers()["strict-transport-security"],
            "max-age=31536000"
        );
    }
}
