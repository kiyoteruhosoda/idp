//! Returns the authorization response to the RP (`response_mode`, G12).
//!
//! api returns the authorization response as "destination (`redirect_to`) + optional form fields (`form_post`)".
//! web only maps that onto HTTP:
//!
//! - `form_post` is `None` (= `query`): 302 to `redirect_to`. Same as before.
//! - `form_post` is `Some`: render an **auto-submitting form** with `redirect_to` as its action and POST.
//!
//! There are 7 paths that return an authorization response: sign-in, MFA, passkey, consent, forced password change,
//! external IdP and resume. **The decision is gathered in this one place** because if any one of them overlooked
//! `form_post`, only that path would return the authorization code in the URL — and it would even look successful.

use crate::i18n::Messages;
use crate::templates::{render, AuthorizationPost};
use assay_contracts::auth::FormPostFields;
use axum::http::header;
use axum::response::{Html, IntoResponse, Response};

/// Returns the authorization response. Chooses between a 302 and an auto-submitting form based on `form_post`.
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

/// The auto-submitting form page.
///
/// **Caching is forbidden.** The body carries the authorization code, so if a shared proxy or the browser's back
/// button redisplays it, the code stays within reach longer than it should.
///
/// **`form-action` allows the RP's origin.** This page's form POSTs directly to `redirect_uri`.
/// With the default CSP (`form-action 'self'`), regardless of Chrome's behaviour, **every browser blocks the
/// submission per spec**, and the authorization code, though issued, never reaches the RP
/// (the SAML POST binding takes the same shape; see `handlers::saml_sso`).
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
            // The page carrying the authorization code navigates to the RP, so no `Referer` is sent either.
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

/// 302 redirect (`query` mode).
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

    /// form_post renders a form. **No 302 is returned** (putting it in Location would defeat the purpose).
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
            "the page carrying the authorization code must not be cached"
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

    /// The auto-submitting form POSTs directly to `redirect_uri`. With the default `form-action 'self'`,
    /// **every browser blocks it per spec** (the code is issued but never reaches the RP).
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

    /// Field values include RP-supplied data (`state`), so escaping is left to the template.
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
