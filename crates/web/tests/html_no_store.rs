//! HTML returned by web must not be stored (task #589; low-5 of the vulnerability review 2026-10-20).
//!
//! Some screens carry client secrets, recovery codes, setup links, TOTP secrets or SAML responses.
//! To keep them from being read via "back" or the disk cache on shared devices, HTML gets `no-store`.
//! Static assets (CSS, JS) are excluded (no reason to refetch them every time).

mod support;

use axum::http::header::CACHE_CONTROL;
use support::{get, send, setup};

#[tokio::test]
async fn html_pages_are_not_stored_but_assets_are_left_alone() {
    let env = setup().await;

    // The 404 screen for no matching route is also rendered HTML.
    for uri in ["/".to_string(), format!("{}/no-such-page", env.prefix())] {
        let res = send(&env.app, get(&uri)).await;
        let cache = res
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(cache.contains("no-store"), "{uri}: {cache}");
        assert_eq!(res.headers()["pragma"], "no-cache", "{uri}");
    }

    let res = send(&env.app, get("/assets/app.css")).await;
    let cache = res
        .headers()
        .get(CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(!cache.contains("no-store"), "{cache}");
}
