//! API エラーメッセージの多言語化（MT19。CLAUDE.md「国際化」）の統合テスト（DB あり）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test api_i18n
//!
//! 検証するのは「エラーコードは言語不変で `message` だけが訳される」という契約そのもの:
//!
//! 1. `Accept-Language` に従って `message` が切り替わる。
//! 2. **`error`（エラーコード）は言語によらず同一**。クライアントはコードで分岐するため、
//!    ここが揺れると多言語化が API の互換性を壊す。
//! 3. ヘッダ未指定・非対応言語は既定 `ja`（`Accept-Language` **のみ**を見る。Cookie も
//!    ユーザー設定も参照しない）。
//! 4. Application 層が返すメッセージ（バリデーション・競合・権限）も訳される。
//!    ここが訳されないと「英語の内部文言がそのまま利用者へ出る」状態が残る。
//! 5. 埋め込み引数（不正な scope 名など）が展開される。

mod support;

use axum::body::Body;
use axum::http::header::ACCEPT_LANGUAGE;
use axum::http::{Method, Request, StatusCode};
use serde_json::{json, Value};
use support::{body_json, create_sso_session, send};

/// SSO Cookie と `Accept-Language` を付けた JSON リクエストを組み立てる。
fn request(
    method: Method,
    cookie: &str,
    uri: &str,
    accept_language: Option<&str>,
    body: Option<Value>,
) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri).header(
        axum::http::header::COOKIE,
        format!("sso_session_id={cookie}"),
    );
    if let Some(lang) = accept_language {
        builder = builder.header(ACCEPT_LANGUAGE, lang);
    }
    if body.is_some() {
        builder = builder.header(axum::http::header::CONTENT_TYPE, "application/json");
    }
    builder
        .body(body.map_or(Body::empty(), |b| Body::from(b.to_string())))
        .unwrap()
}

#[tokio::test]
async fn error_messages_follow_accept_language_while_codes_stay_invariant() {
    let Some(env) = support::setup("api i18n").await else {
        return;
    };
    let admin_cookie = create_sso_session(&env.pool, &env.root_admin_id).await;
    let unknown_user = uuid::Uuid::now_v7();
    let uri = format!("/{}/admin/users/{unknown_user}", env.root_tenant_id);

    // ── 1〜3. 同じ失敗をロケール違いで叩き、コードは同一・メッセージだけが変わることを見る。
    let mut messages = Vec::new();
    for accept_language in [Some("en"), Some("ja"), Some("fr-FR"), None] {
        let res = send(
            &env.app,
            request(Method::GET, &admin_cookie, &uri, accept_language, None),
        )
        .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "{accept_language:?}");
        let body = body_json(res).await;
        assert_eq!(
            body["error"], "not_found",
            "エラーコードは言語不変: {accept_language:?}"
        );
        messages.push(body["message"].as_str().unwrap_or_default().to_string());
    }
    let (english, japanese) = (messages[0].clone(), messages[1].clone());
    assert_ne!(english, japanese, "言語で message が切り替わる");
    assert!(!english.is_empty() && !japanese.is_empty());
    // 非対応言語（fr）とヘッダ未指定は既定 `ja` へ倒す。
    assert_eq!(messages[2], japanese, "非対応言語は既定 ja");
    assert_eq!(messages[3], japanese, "未指定は既定 ja");
    // 翻訳キーがそのまま出ていない（訳の抜けはキー名が応答に出る形で表面化する）。
    for message in &messages {
        assert!(
            !message.starts_with("api-"),
            "untranslated key leaked: {message}"
        );
    }

    // ── 4. Application 層のバリデーション（クライアント登録）も訳される。
    let clients_uri = format!("/{}/admin/clients", env.root_tenant_id);
    // scope に未知の値を含めるので Application 層の検証で 400 になる。
    let create = |lang: &str| {
        request(
            Method::POST,
            &admin_cookie,
            &clients_uri,
            Some(lang),
            Some(json!({
                "client_id": format!("i18n-{}", uuid::Uuid::now_v7().simple()),
                "client_type": "public",
                "app_name": "i18n test",
                "redirect_uris": ["https://rp.example.com/cb"],
                "scopes": ["openid", "banana"],
            })),
        )
    };
    let res = send(&env.app, create("en")).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let en_body = body_json(res).await;
    let res = send(&env.app, create("ja")).await;
    let ja_body = body_json(res).await;

    assert_eq!(en_body["error"], "invalid_request");
    assert_eq!(ja_body["error"], en_body["error"], "コードは言語不変");
    let (en_message, ja_message) = (
        en_body["message"].as_str().unwrap_or_default(),
        ja_body["message"].as_str().unwrap_or_default(),
    );
    assert_ne!(en_message, ja_message, "Application 層の文言も訳される");
    assert!(!en_message.starts_with("api-"), "{en_message}");
    // ── 5. 埋め込み引数（問題のある scope 名）は両言語で展開される。どの値が悪いのか
    //       分からないメッセージにしないため。
    assert!(en_message.contains("banana"), "{en_message}");
    assert!(ja_message.contains("banana"), "{ja_message}");
}
