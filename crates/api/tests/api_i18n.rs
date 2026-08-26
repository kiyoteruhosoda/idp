//! API エラーメッセージの多言語化（MT19）の統合テスト（DB あり）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test api_i18n
//!
//! 検証するのは:
//!
//! 1. `Accept-Language` **だけ**でレスポンス言語が決まること（Cookie・クエリは見ない）。
//! 2. 既定が `ja` で、非対応言語も `ja` にフォールバックすること。
//! 3. **エラーコード（`error`）は言語不変**で、`message` だけが変わること。
//! 4. Domain / Application 層のバリデーションエラー（`MessageKey`）が訳出され、差し込み値
//!    （不正な scope 名など）が本文に入ること。
//! 5. extractor の拒否（401 / 403）も同じ言語で返ること。

mod support;

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, COOKIE};
use axum::http::{Method, Request, StatusCode};
use serde_json::{json, Value};
use support::{admin_token, body_json, send};

/// `Accept-Language` を付けた管理 API リクエストを組み立てる（`None` はヘッダ無し）。
fn request(
    method: Method,
    token: &str,
    uri: &str,
    accept_language: Option<&str>,
    body: Option<Value>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(AUTHORIZATION, format!("Bearer {token}"));
    if let Some(lang) = accept_language {
        builder = builder.header("accept-language", lang);
    }
    if body.is_some() {
        builder = builder.header(CONTENT_TYPE, "application/json");
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
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    // 不明な利用者への操作 → 404（メッセージは `api-user-not-found`）。
    let uri = format!(
        "/{}/admin/users/{}",
        env.root_tenant_id,
        uuid::Uuid::now_v7()
    );

    let cases = [
        // (Accept-Language, 期待される言語が日本語か)
        (None, true),                    // 未指定は既定 ja
        (Some("ja"), true),              // 明示 ja
        (Some("ja-JP,en;q=0.8"), true),  // 地域コードは無視
        (Some("fr-FR"), true),           // 非対応は ja へフォールバック
        (Some("en"), false),             // 明示 en
        (Some("en-US,ja;q=0.5"), false), // 先着優先
    ];
    for (header, expect_ja) in cases {
        let res = send(
            &env.app,
            request(Method::GET, &admin_tok, &uri, header, None),
        )
        .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "header={header:?}");
        let body = body_json(res).await;
        // コードは言語不変。
        assert_eq!(body["error"], "not_found", "header={header:?}");
        let message = body["message"].as_str().expect("message");
        if expect_ja {
            assert_eq!(message, "ユーザーが見つかりません。", "header={header:?}");
        } else {
            assert_eq!(message, "User not found.", "header={header:?}");
        }
    }

    // Cookie で言語を渡しても API は見ない（表示言語の決定は web の責務。CLAUDE.md「国際化」）。
    // 資格情報は Bearer なので、ここでの Cookie は `lang` を運ぶためだけに付ける。
    let res = send(
        &env.app,
        Request::builder()
            .method(Method::GET)
            .uri(&uri)
            .header(AUTHORIZATION, format!("Bearer {admin_tok}"))
            .header(COOKIE, "lang=en")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let body = body_json(res).await;
    assert_eq!(
        body["message"], "ユーザーが見つかりません。",
        "the lang cookie must not change the API's language: {body}"
    );
}

/// Domain / Application 層のバリデーションエラー（`MessageKey`）が訳出され、差し込み値が入る。
#[tokio::test]
async fn validation_errors_from_the_domain_are_translated_with_their_value() {
    let Some(env) = support::setup("api i18n validation").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let uri = format!("/{}/admin/clients", env.root_tenant_id);
    let body = json!({
        "app_name": "X",
        "client_type": "public",
        "redirect_uris": ["https://app.example.com/cb"],
        "scopes": ["openid", "no-such-scope"],
    });

    let res = send(
        &env.app,
        request(
            Method::POST,
            &admin_tok,
            &uri,
            Some("en"),
            Some(body.clone()),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let response = body_json(res).await;
    assert_eq!(response["error"], "invalid_request");
    let message = response["message"].as_str().expect("message");
    // 訳文が出ており、翻訳キーがそのまま漏れていない。
    assert!(!message.starts_with("api-"), "untranslated key: {message}");
    // 差し込み値（不正な scope 名）が本文に入る。
    assert!(message.contains("no-such-scope"), "{message}");
    assert!(message.contains("not supported"), "{message}");

    // 同じ入力を ja で送ると日本語になる（コードは同じ）。
    let res = send(
        &env.app,
        request(Method::POST, &admin_tok, &uri, Some("ja"), Some(body)),
    )
    .await;
    let response = body_json(res).await;
    assert_eq!(response["error"], "invalid_request");
    let message = response["message"].as_str().expect("message");
    assert!(message.contains("no-such-scope"), "{message}");
    assert!(message.contains("対応していません"), "{message}");
}

/// extractor の拒否（未認証 401・権限不足 403）も同じ言語で返る。
#[tokio::test]
async fn extractor_rejections_are_translated_too() {
    let Some(env) = support::setup("api i18n rejections").await else {
        return;
    };
    let uri = format!("/{}/admin/whoami", env.root_tenant_id);

    // 未認証（Cookie 無し）。
    for (header, expected) in [
        (Some("en"), "Sign-in is required."),
        (Some("ja"), "サインインが必要です。"),
        (None, "サインインが必要です。"),
    ] {
        let mut builder = Request::builder().method(Method::GET).uri(&uri);
        if let Some(lang) = header {
            builder = builder.header("accept-language", lang);
        }
        let res = send(&env.app, builder.body(Body::empty()).unwrap()).await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let body = body_json(res).await;
        assert_eq!(body["error"], "unauthorized", "code is language-invariant");
        assert_eq!(body["message"], expected, "header={header:?}");
    }

    // 権限不足（ログイン済みだが idp.tenant.admin なし）。
    let plain = support::create_plain_user(&env.pool, &env.root_tenant_id).await;
    let plain_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &plain).await;
    for (header, expected) in [
        ("en", "You do not have permission to perform this action."),
        ("ja", "この操作を行う権限がありません。"),
    ] {
        let res = send(
            &env.app,
            request(Method::GET, &plain_tok, &uri, Some(header), None),
        )
        .await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        let body = body_json(res).await;
        assert_eq!(body["error"], "forbidden");
        assert_eq!(body["message"], expected, "header={header}");
    }
}
