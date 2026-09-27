//! 管理コンソールをホーム画面へ入れるためのマニフェスト（`GET /{tenant_id}/admin/manifest.webmanifest`）。
//!
//! # テナントごとに 1 つ
//!
//! 管理コンソールの URL はテナント ID から始まるので、`start_url` と `scope` もテナントごとに
//! 変わる。オリジン全体で 1 枚にすると、どのテナントの画面を開くかが決められない。`id` も
//! テナントごとに分け、複数テナントの管理コンソールを別のアプリとして並べられるようにする。
//!
//! # 認証の外に置く
//!
//! ⚠ **ここで管理者を確かめない。** ブラウザはマニフェストを Cookie 無しで取りに来る
//! （`<link rel="manifest">` の既定は `crossorigin` 無し ＝ 資格情報を送らない）。ログイン画面へ
//! 302 すると、HTML をマニフェストとして読んで「インストールできません」になる。中身はどの
//! テナントでも同じ定型文で、テナントの名前も載せない（名前は認証の内側でしか引けない）。
//!
//! # service worker は置かない
//!
//! Chrome のインストール条件はマニフェストとアイコンだけで満たせる。service worker は
//! 認証の後ろの画面を持つアプリでは壊れやすい（スクリプトの取得がログインへ飛ばされると
//! 登録ごと失われる）うえ、この画面にオフラインで見せられるものは無い。

use super::locale;
use crate::i18n::Messages;
use crate::tenant::WebTenant;
use axum::extract::Extension;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::HeaderMap;
use axum::response::IntoResponse;

/// 背景とテーマの色。アイコンの地（`assets/assay.svg` の試金石）と同じ。
const BACKGROUND: &str = "#0F1417";

/// マニフェスト本体。
pub async fn manifest(
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let messages = Messages::new(locale(&headers));
    let admin = format!("{}/admin", tenant.prefix());
    let body = serde_json::json!({
        // `id` はインストール済みのアプリを見分ける鍵。テナントごとに別のアプリにする。
        "id": format!("{admin}/"),
        "name": format!("assay {}", messages.get("admin-console-title")),
        "short_name": "assay",
        "lang": messages.lang(),
        "start_url": admin,
        // ⚠ 末尾の `/` を付けない。付けると `start_url`（`/admin`）自身が範囲の外になる。
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
            // 言語で中身が変わるので長く持たせない。
            (CACHE_CONTROL, "public, max-age=86400"),
        ],
        body.to_string(),
    )
}

/// アイコン 1 つ。画面の他の資産と同じく `?v=` を付け、差し替えがデプロイで行き渡るようにする。
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

    /// 開く先・範囲・見分けの鍵がすべてそのテナントの管理コンソールを指す。
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

    /// Chrome のインストール条件（192px と 512px の PNG）を満たす。
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
