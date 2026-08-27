//! 認可応答を RP へ返す（`response_mode`。G12）。
//!
//! api は認可応答を「送信先（`redirect_to`）＋任意のフォームフィールド（`form_post`）」の形で返す。
//! web はそれを HTTP へ写すだけ:
//!
//! - `form_post` が `None`（＝ `query`）: `redirect_to` へ 302。従来どおり。
//! - `form_post` が `Some`: `redirect_to` を action にした**自動送信フォーム**を描いて POST。
//!
//! 認可応答を返す経路はログイン・MFA・パスキー・同意・強制パスワード変更・外部 IdP・resume と
//! 7 つある。**判断をこの 1 か所に集める**のは、どれか 1 つで `form_post` を見落とすと、そこだけ
//! 認可コードが URL に載って返る——しかも成功して見える——ためである。

use crate::i18n::Messages;
use crate::templates::{render, AuthorizationPost};
use axum::http::header;
use axum::response::{Html, IntoResponse, Response};
use idp_contracts::auth::FormPostFields;

/// 認可応答を返す。`form_post` の有無で 302 と自動送信フォームを出し分ける。
pub fn respond(
    messages: &Messages,
    redirect_to: &str,
    form_post: Option<FormPostFields>,
) -> Response {
    match form_post {
        Some(fields) => form_post_page(messages, redirect_to, &fields),
        None => found(redirect_to),
    }
}

/// 自動送信フォームのページ。
///
/// **キャッシュを禁止する。** 本文に認可コードが載るため、共有プロキシやブラウザの戻る操作で
/// 再表示されると、コードが本来より長く手の届く場所に残る。
///
/// **`form-action` に RP のオリジンを許可する。** このページのフォームは `redirect_uri` へ直接
/// POST する。既定の CSP（`form-action 'self'`）のままでは、Chrome の挙動とは関係なく **仕様
/// どおり全ブラウザで送信が遮断され**、認可コードは発行済みなのに RP へ届かない
/// （SAML の POST binding が同じ形を採っている。`handlers::saml_sso`）。
fn form_post_page(messages: &Messages, action: &str, fields: &[(String, String)]) -> Response {
    let html = render(&AuthorizationPost {
        messages,
        action,
        fields,
    });
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
            // 認可コードを載せたページから RP へ遷移するので、`Referer` も出さない。
            (header::REFERRER_POLICY, "no-referrer"),
        ],
        [(
            header::CONTENT_SECURITY_POLICY,
            crate::security_headers::form_action_csp_for(action),
        )],
        Html(html),
    )
        .into_response()
}

/// 302 リダイレクト（`query` モード）。
fn found(location: &str) -> Response {
    crate::handlers::found(location)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::Locale;
    use axum::http::StatusCode;

    #[tokio::test]
    async fn query_mode_redirects() {
        let messages = Messages::new(Locale::Ja);
        let response = respond(&messages, "https://rp.example.com/cb?code=x&state=y", None);
        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(
            response
                .headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("https://rp.example.com/cb?code=x&state=y")
        );
    }

    /// form_post ではフォームを描く。**302 は返さない**（Location に載せたら意味が無い）。
    #[tokio::test]
    async fn form_post_mode_renders_a_self_submitting_form() {
        let messages = Messages::new(Locale::Ja);
        let response = respond(
            &messages,
            "https://rp.example.com/cb",
            Some(vec![
                ("code".to_string(), "the-code".to_string()),
                ("state".to_string(), "the-state".to_string()),
            ]),
        );
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::LOCATION).is_none());
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store"),
            "認可コードを載せたページはキャッシュさせない"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        let html = String::from_utf8_lossy(&body);
        assert!(
            html.contains(r#"action="https://rp.example.com/cb""#),
            "{html}"
        );
        assert!(html.contains(r#"name="code""#), "{html}");
        assert!(html.contains("the-code"), "{html}");
        assert!(html.contains(r#"name="state""#), "{html}");
        assert!(html.contains("data-auto-submit"), "{html}");
    }

    /// 自動送信フォームは `redirect_uri` へ直接 POST する。既定の `form-action 'self'` のままだと
    /// **全ブラウザが仕様どおり遮断する**（コードは発行済みなのに RP へ届かない）。
    #[tokio::test]
    async fn form_post_mode_allows_the_relying_party_origin_as_a_form_action() {
        let messages = Messages::new(Locale::Ja);
        let response = respond(
            &messages,
            "https://rp.example.com/cb",
            Some(vec![("code".to_string(), "the-code".to_string())]),
        );
        let csp = response
            .headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(
            csp.contains("form-action 'self' https://rp.example.com;"),
            "{csp}"
        );
    }

    /// フィールドの値は RP 由来（`state`）を含むため、テンプレートのエスケープに委ねる。
    #[tokio::test]
    async fn field_values_are_escaped() {
        let messages = Messages::new(Locale::Ja);
        let response = respond(
            &messages,
            "https://rp.example.com/cb",
            Some(vec![(
                "state".to_string(),
                r#""><script>alert(1)</script>"#.to_string(),
            )]),
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        let html = String::from_utf8_lossy(&body);
        assert!(!html.contains("<script>alert(1)</script>"), "{html}");
    }
}
