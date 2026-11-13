//! Manifest for adding the admin console to the home screen (`GET /{tenant_id}/admin/manifest.webmanifest`).
//!
//! # One per tenant
//!
//! The admin console URL starts with the tenant ID, so `start_url` and `scope` differ per tenant too.
//! A single one for the whole origin could not decide which tenant's screen to open. `id` is also
//! split per tenant so that admin consoles of multiple tenants can sit side by side as separate apps.
//!
//! # Kept outside authentication
//!
//! ⚠ **Do not check for an admin here.** Browsers fetch the manifest without cookies
//! (`<link rel="manifest">` defaults to no `crossorigin` = no credentials sent). A 302 to the login
//! screen would make the browser read HTML as the manifest and say "cannot be installed". The content is the
//! same boilerplate for every tenant and does not include the tenant name (names are only available inside auth).
//!
//! # No service worker
//!
//! Chrome's install criteria are met by the manifest and icons alone. A service worker is fragile
//! in apps whose screens sit behind authentication (if fetching the script gets redirected to login,
//! the registration is lost entirely), and this screen has nothing to show offline.

use super::locale;
use crate::i18n::Messages;
use crate::tenant::WebTenant;
use axum::extract::Extension;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::HeaderMap;
use axum::response::IntoResponse;

/// Background and theme color. Same as the icon's background (the touchstone in `assets/assay.svg`).
const BACKGROUND: &str = "#0F1417";

/// The manifest body.
pub async fn manifest(
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let messages = Messages::new(locale(&headers));
    let admin = format!("{}/admin", tenant.prefix());
    let body = serde_json::json!({
        // `id` is the key that identifies an installed app. Make each tenant a separate app.
        "id": format!("{admin}/"),
        "name": format!("assay {}", messages.get("admin-console-title")),
        "short_name": "assay",
        "lang": messages.lang(),
        "start_url": admin,
        // ⚠ No trailing `/`. With it, `start_url` (`/admin`) itself would fall outside the scope.
        "scope": admin,
        "display": "standalone",
        "background_color": BACKGROUND,
        "theme_color": BACKGROUND,
        "icons": [
            icon("assay-192.png", "192x192", "any"),
            icon("assay-512.png", "512x512", "any"),
            icon("assay-maskable-512.png", "512x512", "maskable"),
        ],
    });
    (
        [
            (CONTENT_TYPE, "application/manifest+json; charset=utf-8"),
            // The content varies by language, so do not keep it long.
            (CACHE_CONTROL, "public, max-age=86400"),
        ],
        body.to_string(),
    )
}

/// One icon. Like other screen assets it gets `?v=` so replacements propagate on deploy.
fn icon(file: &str, sizes: &str, purpose: &str) -> serde_json::Value {
    serde_json::json!({
        "src": format!("/assets/icons/{file}?v={}", crate::templates::asset_version()),
        "sizes": sizes,
        "type": "image/png",
        "purpose": purpose,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::HeaderValue;

    async fn manifest_json(accept_language: &str) -> serde_json::Value {
        let mut headers = HeaderMap::new();
        headers.insert(
            "accept-language",
            HeaderValue::from_str(accept_language).unwrap(),
        );
        let tenant = WebTenant("01a00dfe-0000-7000-8000-000000000000".into());
        let response = manifest(Extension(tenant), headers).await.into_response();
        assert_eq!(
            response.headers()[CONTENT_TYPE],
            "application/manifest+json; charset=utf-8"
        );
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Start URL, scope and identity key all point to that tenant's admin console.
    #[tokio::test]
    async fn the_manifest_is_scoped_to_the_tenant_console() {
        let json = manifest_json("ja").await;
        let admin = "/01a00dfe-0000-7000-8000-000000000000/admin";
        assert_eq!(json["start_url"], admin);
        assert_eq!(json["scope"], admin);
        assert_eq!(json["id"], format!("{admin}/"));
        assert!(json["start_url"]
            .as_str()
            .unwrap()
            .starts_with(json["scope"].as_str().unwrap()));
        assert_eq!(json["display"], "standalone");
    }

    /// Meets Chrome's install criteria (192px and 512px PNGs).
    #[tokio::test]
    async fn the_manifest_carries_the_icons_chrome_requires() {
        let json = manifest_json("en").await;
        let sizes: Vec<&str> = json["icons"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|i| i["type"] == "image/png")
            .map(|i| i["sizes"].as_str().unwrap())
            .collect();
        assert!(sizes.contains(&"192x192"), "{json}");
        assert!(sizes.contains(&"512x512"), "{json}");
        assert!(json["name"].as_str().unwrap().starts_with("assay "));
    }
}
