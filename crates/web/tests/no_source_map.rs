//! 本番の web はソースマップ（`app.js.map`）を配らない（task #593）。画面の元のソースを丸ごと
//! 渡す理由が無い。バンドル（`app.js`）は今までどおり配る。

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
