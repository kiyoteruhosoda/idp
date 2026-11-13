//! Rendering of HTTP error pages (all status codes) and middleware that fills in error response bodies.
//!
//! **Turning error responses into HTML is centralized in this middleware.** Responses that handlers return without
//! a body like `StatusCode::X.into_response()`, axum extractor rejections
//! (`Form` deserialization failures etc.), 404 for unmatched routes and 405 for method mismatches are all
//! replaced here with the shared error page. Rewriting handlers one by one is not used because new
//! error paths would be missed.
//!
//! Replacement happens only when "the body is empty" or "the body is `text/plain` (axum's default rejection message)".
//! If a handler already rendered context-specific HTML (e.g. the admin console's insufficient permission banner, a
//! notice with a back link), it is respected and passed through. `text/plain` is included in the replacement
//! also so that internal details like "Failed to deserialize form body: ..." are not exposed to the browser.
//!
//! Wording uses `error-<code>-title` / `error-<code>-message`, and codes without dedicated wording
//! fall back to the class defaults (`error-4xx-*` / `error-5xx-*`). This way even non-standard codes
//! never show a raw translation key on screen.

use crate::i18n::{Locale, Messages};
use crate::templates::{render, ErrorPage};
use axum::body::Body;
use axum::extract::Request;
use axum::http::header::{HeaderValue, CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::Uri;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Response};

/// Status codes with dedicated wording (`error-<code>-title` / `-message`).
/// Covers the IANA-registered 4xx / 5xx (418 I'm a teapot is excluded as a joke code).
/// Codes not listed here fall back to the class defaults (`error-4xx-*` / `error-5xx-*`).
const DEDICATED_STATUS_CODES: &[u16] = &[
    400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 421,
    422, 423, 424, 425, 426, 428, 429, 431, 451, 500, 501, 502, 503, 504, 505, 506, 507, 508, 510,
    511,
];

/// Upper limit for buffering an error response body to decide on replacement. Error responses are small, so this is ample.
/// Bodies over the limit are considered intentionally rendered by the handler and returned as is.
const MAX_BUFFERED_ERROR_BODY: usize = 64 * 1024;

/// Returns the translation keys (title / message) for a status code.
fn message_keys(status: StatusCode) -> (String, String) {
    let code = status.as_u16();
    if DEDICATED_STATUS_CODES.contains(&code) {
        return (
            format!("error-{code}-title"),
            format!("error-{code}-message"),
        );
    }
    let class = if status.is_server_error() {
        "5xx"
    } else {
        "4xx"
    };
    (
        format!("error-{class}-title"),
        format!("error-{class}-message"),
    )
}

/// Where the user can go back to from the error screen.
///
/// **Error screens get an exit.** Without one, a user who failed after following a link
/// has nothing but the browser's back button (the name in the top left is not a link either).
struct BackLink {
    href: String,
    label_key: &'static str,
}

/// Decides the return destination from the requested path.
///
/// Shown only when a tenant prefix (UUID) can be extracted. Under the admin console it goes to the console home,
/// otherwise to account settings. **Not shown if it is the current location** — returning to the same place
/// would just produce the same error, looking like an exit but actually a dead end.
fn back_link(path: &str) -> Option<BackLink> {
    let mut segments = path.split('/').skip(1);
    let tenant = segments.next()?;
    if uuid::Uuid::parse_str(tenant).is_err() {
        return None;
    }
    let (suffix, label_key) = match segments.next() {
        Some("admin") => ("/admin", "error-back-to-console"),
        _ => ("/settings", "error-back-to-settings"),
    };
    let href = format!("/{tenant}{suffix}");
    (href.trim_end_matches('/') != path.trim_end_matches('/'))
        .then_some(BackLink { href, label_key })
}

/// Renders the error page HTML.
fn render_page(status: StatusCode, locale: Locale, back: Option<BackLink>) -> String {
    let messages = Messages::new(locale);
    let (title_key, message_key) = message_keys(status);
    let (back_href, back_label) = match back {
        Some(link) => (link.href, messages.get(link.label_key)),
        None => (String::new(), String::new()),
    };
    render(&ErrorPage {
        lang: messages.lang(),
        code: status.as_u16().to_string(),
        title: messages.get(&title_key),
        message: messages.get(&message_key),
        back_href,
        back_label,
    })
}

/// Builds a response for returning an error page directly from a handler (display language from request headers).
///
/// The caller passes the return destination. It is not derived mechanically from the path — for a 404 like
/// "the tenant does not exist", a derived destination cannot be opened for the same reason.
pub(crate) fn page(status: StatusCode, headers: &HeaderMap, back: Option<&str>) -> Response {
    let back = back.map(|href| BackLink {
        href: href.to_string(),
        label_key: "error-back-to-settings",
    });
    let html = render_page(status, crate::handlers::locale(headers), back);
    (status, Html(html)).into_response()
}

/// 404 page returned for requests matching no route (`Router::fallback`).
pub(crate) async fn fallback(uri: Uri, headers: HeaderMap) -> Response {
    let html = render_page(
        StatusCode::NOT_FOUND,
        crate::handlers::locale(&headers),
        back_link(uri.path()),
    );
    (StatusCode::NOT_FOUND, Html(html)).into_response()
}

/// Replaces the body of an error response (4xx / 5xx) with the shared error page when it is empty or plain text.
pub async fn render_error_pages(request: Request, next: Next) -> Response {
    // Browser JS paths sending JSON (passkey registration/authentication APIs) get no HTML and are passed through.
    // Their JS checks `response.ok` and shows the error, so filling in the body is unnecessary.
    let is_json_request = request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/json"));
    // HEAD cannot have a body.
    let is_head = request.method() == Method::HEAD;
    // `next.run` consumes the request, so extract the display language and return-destination inputs first.
    let locale = crate::handlers::locale(request.headers());
    let back = back_link(request.uri().path());

    let response = next.run(request).await;

    let status = response.status();
    if is_json_request || is_head || !(status.is_client_error() || status.is_server_error()) {
        return response;
    }
    replace_placeholder_body(response, status, locale, back).await
}

/// Replaces with the error page only when the body is "empty" or `text/plain`. Otherwise (HTML/JSON rendered by
/// the handler) the body is restored and returned as is. Response headers (Set-Cookie etc.) are kept.
async fn replace_placeholder_body(
    response: Response,
    status: StatusCode,
    locale: Locale,
    back: Option<BackLink>,
) -> Response {
    let is_plain_text = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("text/plain"));

    let (mut parts, body) = response.into_parts();
    // On exceeding the limit or a read failure the body cannot be restored, so render the error page (fail-soft).
    let keep_body = match axum::body::to_bytes(body, MAX_BUFFERED_ERROR_BODY).await {
        Ok(bytes) if !bytes.is_empty() && !is_plain_text => Some(bytes),
        Ok(_) => None,
        Err(error) => {
            tracing::warn!(%error, %status, "failed to buffer error response body");
            None
        }
    };
    if let Some(bytes) = keep_body {
        return Response::from_parts(parts, Body::from(bytes));
    }

    parts.headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    // The body length changes, so discard the original Content-Length and let it be recomputed.
    parts.headers.remove(CONTENT_LENGTH);
    Response::from_parts(parts, Body::from(render_page(status, locale, back)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::{get, post};
    use axum::Router;
    use tower::ServiceExt;

    fn app() -> Router {
        Router::new()
            .route("/ok", get(|| async { "fine" }))
            // An error without a body (like an existing handler's `StatusCode::X.into_response()`).
            .route("/bare", get(|| async { StatusCode::BAD_GATEWAY }))
            // An error for which the handler rendered context-specific HTML.
            .route(
                "/rendered",
                get(|| async {
                    (
                        StatusCode::FORBIDDEN,
                        Html("<!DOCTYPE html><p>context specific</p>".to_string()),
                    )
                }),
            )
            // A non-standard status code (falls back to the class default).
            .route(
                "/nonstandard",
                get(|| async { StatusCode::from_u16(499).expect("status") }),
            )
            // Path where an extractor rejection (`Form` extraction on a body-less POST) returns text/plain.
            .route(
                "/form",
                post(
                    |_: axum::extract::Form<std::collections::HashMap<String, String>>| async {
                        StatusCode::OK
                    },
                ),
            )
            .fallback(fallback)
            .layer(axum::middleware::from_fn(render_error_pages))
    }

    async fn request(method: &str, uri: &str, content_type: Option<&str>) -> (StatusCode, String) {
        let mut builder = axum::http::Request::builder().method(method).uri(uri);
        if let Some(content_type) = content_type {
            builder = builder.header(CONTENT_TYPE, content_type);
        }
        let response = app()
            .oneshot(builder.body(Body::empty()).expect("request"))
            .await
            .expect("response");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    #[test]
    fn dedicated_codes_use_their_own_keys_and_others_fall_back_by_class() {
        assert_eq!(
            message_keys(StatusCode::FORBIDDEN),
            (
                "error-403-title".to_string(),
                "error-403-message".to_string()
            )
        );
        assert_eq!(
            message_keys(StatusCode::INTERNAL_SERVER_ERROR),
            (
                "error-500-title".to_string(),
                "error-500-message".to_string()
            )
        );
        // 4xx / 5xx without dedicated wording go to the class default.
        assert_eq!(
            message_keys(StatusCode::from_u16(499).expect("status")),
            (
                "error-4xx-title".to_string(),
                "error-4xx-message".to_string()
            )
        );
        assert_eq!(
            message_keys(StatusCode::from_u16(599).expect("status")),
            (
                "error-5xx-title".to_string(),
                "error-5xx-message".to_string()
            )
        );
    }

    /// Every code declared with dedicated wording and the class defaults are actually translated in both ja / en
    /// (`Messages::get` returns undefined keys as the key name, so getting the key name back means a missing translation).
    #[test]
    fn every_declared_status_code_has_translations_in_both_locales() {
        for locale in [Locale::Ja, Locale::En] {
            let messages = Messages::new(locale);
            let codes = DEDICATED_STATUS_CODES
                .iter()
                .map(|code| code.to_string())
                .chain(["4xx".to_string(), "5xx".to_string()]);
            for code in codes {
                for key in [
                    format!("error-{code}-title"),
                    format!("error-{code}-message"),
                ] {
                    assert_ne!(
                        messages.get(&key),
                        key,
                        "missing translation for {key} ({})",
                        locale.as_tag()
                    );
                }
            }
        }
    }

    /// Body-less error responses are replaced with the shared error page.
    #[tokio::test]
    async fn fills_empty_error_bodies_with_the_common_page() {
        let (status, body) = request("GET", "/bare", None).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(body.contains("502"), "must show the status code: {body}");
        assert!(body.contains("<!DOCTYPE html>"));
    }

    /// Context-specific HTML rendered by the handler is not overwritten.
    #[tokio::test]
    async fn keeps_handler_rendered_error_pages() {
        let (status, body) = request("GET", "/rendered", None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(body.contains("context specific"));
    }

    /// Plain-text extractor rejections (internal details) are replaced with the error page and not exposed.
    #[tokio::test]
    async fn replaces_extractor_rejection_text_with_the_common_page() {
        let (status, body) = request("POST", "/form", None).await;
        assert!(status.is_client_error(), "unexpected status {status}");
        assert!(
            !body.contains("Failed to deserialize"),
            "internal rejection message must not leak: {body}"
        );
        assert!(body.contains("<!DOCTYPE html>"));
    }

    /// Unmatched routes (404) and method mismatches (405) also become error pages.
    #[tokio::test]
    async fn covers_unmatched_routes_and_method_mismatch() {
        let (status, body) = request("GET", "/no/such/path", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains("404"));

        let (status, body) = request("POST", "/ok", None).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert!(body.contains("405"), "must show the status code: {body}");
    }

    /// Even non-standard codes show the class default wording instead of translation keys.
    #[tokio::test]
    async fn nonstandard_status_codes_use_class_defaults() {
        let (status, body) = request("GET", "/nonstandard", None).await;
        assert_eq!(status.as_u16(), 499);
        assert!(body.contains("499"));
        assert!(
            !body.contains("error-4xx-title"),
            "translation key must not leak into the page: {body}"
        );
    }

    /// JSON requests (passkey JS paths) get no HTML.
    #[tokio::test]
    async fn leaves_json_requests_untouched() {
        let (status, body) = request("GET", "/bare", Some("application/json")).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(
            body.is_empty(),
            "JSON callers must not receive HTML: {body}"
        );
    }

    /// HEAD gets no body.
    #[tokio::test]
    async fn does_not_add_a_body_to_head_responses() {
        let (_, body) = request("HEAD", "/bare", None).await;
        assert!(body.is_empty(), "HEAD must not carry a body: {body}");
    }

    /// Successful responses (2xx) are passed through.
    #[tokio::test]
    async fn leaves_successful_responses_untouched() {
        let (status, body) = request("GET", "/ok", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "fine");
    }

    /// When the tenant is known, a return destination is shown. When not, none is shown (nowhere to go).
    #[test]
    fn the_way_out_is_offered_only_when_the_tenant_is_known() {
        let t = "01a00dfe-bffb-7f23-88b5-8bbef50d23f0";
        let link = back_link(&format!("/{t}/account/mfa/totp/setup")).expect("link");
        assert_eq!(link.href, format!("/{t}/settings"));
        assert_eq!(link.label_key, "error-back-to-settings");

        let link = back_link(&format!("/{t}/admin/clients/new")).expect("link");
        assert_eq!(link.href, format!("/{t}/admin"));
        assert_eq!(link.label_key, "error-back-to-console");

        // Paths without a tenant prefix (assets, root) have no return destination.
        assert!(back_link("/assets/app.css").is_none());
        assert!(back_link("/").is_none());
        assert!(back_link("/healthz").is_none());
    }

    /// **Never return to the current location.** If the settings screen itself fails and the same URL is shown,
    /// pressing it just yields the same error, looking like an exit but a dead end.
    #[test]
    fn it_does_not_offer_a_link_back_to_the_failing_page_itself() {
        let t = "01a00dfe-bffb-7f23-88b5-8bbef50d23f0";
        assert!(back_link(&format!("/{t}/settings")).is_none());
        assert!(back_link(&format!("/{t}/settings/")).is_none());
        assert!(back_link(&format!("/{t}/admin")).is_none());
    }

    /// A page that replaced a body-less 500 carries the return link.
    #[tokio::test]
    async fn a_replaced_error_page_carries_the_way_out() {
        let t = "01a00dfe-bffb-7f23-88b5-8bbef50d23f0";
        let app = Router::new().route(
            &format!("/{t}/account/mfa/totp/setup"),
            get(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
        );
        let app = app.layer(axum::middleware::from_fn(render_error_pages));
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/{t}/account/mfa/totp/setup"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = String::from_utf8_lossy(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .into_owned();
        assert!(
            body.contains(&format!(r#"href="/{t}/settings""#)),
            "no return link: {body}"
        );
    }
}
