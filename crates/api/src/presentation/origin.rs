//! Cookie 認証の変更系リクエストに対する Origin / Referer 検証（SEC4）。
//!
//! 既定の `domain-split` トポロジでは SSO Cookie が host-only で web ホストにしか付かないため、
//! ブラウザから api の管理 API へ Cookie が届くことはない。しかし `PUBLISH_TOPOLOGY=single-origin`
//! では nginx が `/{tenant}/admin/*` を `Accept` ヘッダで振り分けるため、`Accept: application/json`
//! を付けた same-site のスクリプトから Cookie 付きで api の管理 API へ到達できる。
//!
//! **JSON の content-type は防御にならない。** 変更系の一部は body を取らず（`restart_service`・
//! `rotate_client_secret`・`reset_user_password` / `reset_user_mfa`）、POST + `Accept` だけの
//! **simple request**（プリフライト無し）で発火する。`SameSite=Lax` の Cookie は same-site なので送られる。
//!
//! そこで Cookie 認証を行う extractor は、変更系メソッドで **`Origin`（無ければ `Referer`）が
//! 許可オリジンと一致すること**を要求する。
//!
//! 許可オリジンは配置から決まる 2 つだけ:
//!
//! * `PUBLIC_WEB_BASE_URL` のオリジン（single-origin では api と同じホストになる）
//! * `ISSUER` のオリジン（api 自身。`/api/docs` の Swagger UI からの試行を想定）
//!
//! **ヘッダを一切持たないリクエストは通す。** ブラウザは変更系メソッドで必ず `Origin` を送るため
//! CSRF の脅威モデルからは外れ、運用手順（`docs/OPERATIONS.md` の `curl` 例）を壊さないため。

use crate::config::Config;
use axum::http::header::{ORIGIN, REFERER};
use axum::http::request::Parts;
use axum::http::{HeaderMap, Method};

/// Cookie 認証の変更系リクエストとして許容できるオリジンから来ているか。
pub fn is_allowed(parts: &Parts, config: &Config) -> bool {
    is_allowed_from(&parts.method, &parts.headers, &allowed_origins(config))
}

fn is_allowed_from(method: &Method, headers: &HeaderMap, allowed: &[String]) -> bool {
    // 安全メソッド（状態を変えない）は対象外。ブラウザの画面遷移には Origin が付かない。
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return true;
    }
    let Some(origin) = request_origin(headers) else {
        // ブラウザ以外（サーバ間・CLI）。CSRF の前提（ブラウザが Cookie を自動付与する）が無い。
        return true;
    };
    allowed.contains(&origin)
}

/// リクエストが主張するオリジン。`Origin` を優先し、無ければ `Referer` から導出する。
/// `Origin: null`（サンドボックス iframe・`data:` 由来）は「不透明なオリジン」なので一致させない。
fn request_origin(headers: &HeaderMap) -> Option<String> {
    if let Some(origin) = headers.get(ORIGIN).and_then(|v| v.to_str().ok()) {
        return Some(normalize(origin).unwrap_or_else(|| origin.to_string()));
    }
    let referer = headers.get(REFERER).and_then(|v| v.to_str().ok())?;
    normalize(referer)
}

/// 許可オリジン（ascii シリアライズ済み。`scheme://host[:port]`）。
fn allowed_origins(config: &Config) -> Vec<String> {
    [config.public_web_base_url(), config.issuer()]
        .into_iter()
        .filter_map(normalize)
        .collect()
}

fn normalize(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    let origin = parsed.origin();
    origin.is_tuple().then(|| origin.ascii_serialization())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    fn parts(method: Method, headers: &[(&str, &str)]) -> Parts {
        let mut builder = Request::builder().method(method).uri("/t/admin/clients");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(()).unwrap().into_parts().0
    }

    fn allowed() -> Vec<String> {
        vec!["https://id.example.com".to_string()]
    }

    fn check(method: Method, headers: &[(&str, &str)]) -> bool {
        let p = parts(method, headers);
        is_allowed_from(&p.method, &p.headers, &allowed())
    }

    #[test]
    fn safe_methods_are_never_blocked() {
        // 状態を変えないので CSRF の対象外。画面遷移には Origin が付かない。
        assert!(check(
            Method::GET,
            &[("origin", "https://evil.example.com")]
        ));
        assert!(check(
            Method::HEAD,
            &[("origin", "https://evil.example.com")]
        ));
    }

    #[test]
    fn same_site_subdomain_cannot_post_to_the_admin_api() {
        // SEC4 の攻撃形: 同一 eTLD+1 の別サブドメインから body 無しの simple request。
        assert!(!check(
            Method::POST,
            &[
                ("origin", "https://evil.id.example.com"),
                ("accept", "application/json")
            ]
        ));
        assert!(!check(
            Method::POST,
            &[("origin", "https://id.example.com.evil.test")]
        ));
        assert!(!check(
            Method::DELETE,
            &[("origin", "https://evil.example.com")]
        ));
    }

    #[test]
    fn the_configured_origin_is_accepted() {
        assert!(check(Method::POST, &[("origin", "https://id.example.com")]));
        assert!(check(
            Method::POST,
            &[("referer", "https://id.example.com/t/admin/clients")]
        ));
    }

    #[test]
    fn requests_without_browser_headers_still_work() {
        // 運用手順の curl（Cookie を明示的に付ける）を壊さない。
        assert!(check(Method::POST, &[]));
    }

    #[test]
    fn opaque_origin_is_rejected() {
        assert!(!check(Method::POST, &[("origin", "null")]));
    }

    #[test]
    fn normalizes_to_scheme_host_port() {
        assert_eq!(
            normalize("https://id.example.com/tenant/login?x=1").as_deref(),
            Some("https://id.example.com")
        );
        assert_eq!(
            normalize("http://id.example.com:8080/").as_deref(),
            Some("http://id.example.com:8080")
        );
        // 不透明なオリジン（tuple でない）は一致対象にしない。
        assert_eq!(normalize("null"), None);
        assert_eq!(normalize("data:text/html,x"), None);
    }

    #[test]
    fn referer_is_used_when_origin_is_absent() {
        let p = parts(
            Method::POST,
            &[("referer", "https://id.example.com/tenant/admin/clients")],
        );
        assert_eq!(
            request_origin(&p.headers).as_deref(),
            Some("https://id.example.com")
        );
    }

    #[test]
    fn opaque_origin_never_matches_an_allowed_origin() {
        let p = parts(Method::POST, &[("origin", "null")]);
        // 正規化できないので生値のまま返り、許可オリジン（URL 由来）とは一致しない。
        assert_eq!(request_origin(&p.headers).as_deref(), Some("null"));
    }

    #[test]
    fn missing_headers_mean_a_non_browser_client() {
        let p = parts(Method::POST, &[]);
        assert_eq!(request_origin(&p.headers), None);
    }
}
