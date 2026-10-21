//! web が返す HTML は保存させない（task #589。脆弱性確認 2026-10-20 の低-5）。
//!
//! クライアントシークレット・回復コード・設定リンク・TOTP の秘密・SAML の応答を載せる画面がある。
//! 共有の端末で「戻る」やディスクのキャッシュから読ませないよう、HTML には `no-store` を付ける。
//! 静的な資産（CSS・JS）は対象外（毎回取り直させる理由が無い）。

mod support;

use axum::http::header::CACHE_CONTROL;
use support::{get, send, setup};

#[tokio::test]
async fn html_pages_are_not_stored_but_assets_are_left_alone() {
    let env = setup().await;

    // どのルートにも当たらない 404 の画面も、描画した HTML である。
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
