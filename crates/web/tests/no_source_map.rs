//! Production web does not serve the source map (`app.js.map`) (task #593). There is no reason to hand out
//! the screen's original source wholesale. The bundle (`app.js`) is served as before.

mod support;

use axum::http::StatusCode;
use support::{get, send, setup};

#[tokio::test]
async fn the_source_map_is_not_served_but_the_bundle_is() {
    let env = setup().await;
    let res = send(&env.app, get("/assets/react/app.js.map")).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let res = send(&env.app, get("/assets/react/app.js")).await;
    assert_eq!(res.status(), StatusCode::OK);
}
