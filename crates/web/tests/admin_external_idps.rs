//! 外部 IdP 設定画面のルータ経由の統合テスト（AP16。土台は G11。SAML 対応は AP12）。
//!
//! この画面の要は**クライアントシークレットの扱い**である。api はシークレットを返さないため
//! 編集フォームに現在値を出せず、空欄の意味を決めなければならない。ここでは api をスタブして、
//! 実際に送られる HTTP ボディで「空欄＝変更しない」が守られていることを確かめる。
//! ここが崩れると、表示名を直しただけで外部 IdP との連携が壊れる。
//!
//! もう一つの要は**プロトコルの出し分け**である。OIDC と SAML は必要な項目がまったく違い、
//! 混ざった設定は api が受け付けても誤りがログイン時まで表に出ない。

mod support;

use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, COOKIE};
use axum::http::{Method, Request, StatusCode};
use idp_contracts::cookies::SSO_SESSION_COOKIE;
use idp_web::csrf::console_csrf_token;
use serde_json::{json, Value};
use support::{body_text, get_with_cookies, post_form, send, setup, WebEnv};
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, ResponseTemplate};

const SSO: &str = "admin-session";
const PROVIDER_ID: &str = "019f8ea8-f5dd-7fc7-ac15-a7d4337e4611";
const SAML_PROVIDER_ID: &str = "019f8ea8-f5dd-7fc7-ac15-a7d4337e4612";

fn cookies() -> String {
    format!("{SSO_SESSION_COOKIE}={SSO}")
}

fn csrf() -> String {
    console_csrf_token(SSO, support::TEST_CSRF_SECRET)
}

async fn stub_admin(env: &WebEnv) {
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/whoami$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "user_id": "00000000-0000-7000-8000-000000000001",
            "name": "Admin",
            "preferred_username": "admin"
        })))
        .mount(&env.api)
        .await;
}

fn sample_provider() -> Value {
    json!({
        "id": PROVIDER_ID,
        "provider_code": "corp",
        "display_name": "Corp IdP",
        "issuer": "https://idp.example.com",
        "protocol": "oidc",
        "authorization_endpoint": "https://idp.example.com/authorize",
        "token_endpoint": "https://idp.example.com/token",
        "jwks_uri": "https://idp.example.com/jwks",
        "client_id": "abc",
        "has_client_secret": true,
        "scopes": ["openid", "email"],
        "enabled": true,
        "allow_auto_link": false,
        "redirect_uri": "https://web.example.com/external/corp/callback",
        "created_at": "2026-08-10T00:00:00Z",
        "updated_at": "2026-08-10T00:00:00Z"
    })
}

/// SAML のプロバイダ。api は**使わない側のプロトコルの項目を `null`** で返す（ADR-0027）。
fn sample_saml_provider() -> Value {
    json!({
        "id": SAML_PROVIDER_ID,
        "provider_code": "corp-saml",
        "display_name": "Corp SAML",
        "issuer": "urn:idp:corp",
        "protocol": "saml",
        "authorization_endpoint": Value::Null,
        "token_endpoint": Value::Null,
        "jwks_uri": Value::Null,
        "client_id": Value::Null,
        "has_client_secret": false,
        "scopes": [],
        "saml_sso_url": "https://idp.example.com/sso",
        "saml_certificates": ["MIIBCURRENT==", "MIIBNEXT=="],
        "saml_name_id_format": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        "saml_sp_entity_id": "https://web.example.com/t/saml/sp",
        "saml_acs_url": "https://web.example.com/t/external/corp-saml/saml/acs",
        "enabled": true,
        "allow_auto_link": false,
        "redirect_uri": "https://web.example.com/t/external/corp-saml/callback",
        "created_at": "2026-08-10T00:00:00Z",
        "updated_at": "2026-08-10T00:00:00Z"
    })
}

/// multipart/form-data の POST（メタデータ取り込みフォームと同じ形）。
fn post_multipart(uri: &str, cookies: &str, fields: &[(&str, &str)]) -> Request<Body> {
    const BOUNDARY: &str = "----idp-test-boundary";
    let mut body = String::new();
    for (name, value) in fields {
        body.push_str(&format!("--{BOUNDARY}\r\n"));
        // ファイル欄はファイル名付きで送る（貼り付け欄との優先順を確かめるため）。
        if *name == "metadata_file" {
            body.push_str(&format!(
                "Content-Disposition: form-data; name=\"{name}\"; filename=\"metadata.xml\"\r\n\r\n"
            ));
        } else {
            body.push_str(&format!(
                "Content-Disposition: form-data; name=\"{name}\"\r\n\r\n"
            ));
        }
        body.push_str(value);
        body.push_str("\r\n");
    }
    body.push_str(&format!("--{BOUNDARY}--\r\n"));
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(
            CONTENT_TYPE,
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )
        .header(COOKIE, cookies)
        .body(Body::from(body))
        .unwrap()
}

async fn stub_list(env: &WebEnv, providers: Value) {
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/external-idps$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(providers))
        .mount(&env.api)
        .await;
}

async fn stub_patch(env: &WebEnv) {
    Mock::given(method("PATCH"))
        .and(path_regex(r"^/[^/]+/admin/external-idps/[^/]+$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_provider()))
        .mount(&env.api)
        .await;
}

/// 登録で api へ届いた本文（取り込みエンドポイントは除く）。
async fn posted_body(env: &WebEnv) -> Option<Value> {
    env.api
        .received_requests()
        .await
        .expect("recorded requests")
        .iter()
        .find(|r| {
            r.method == wiremock::http::Method::POST
                && r.url.path().ends_with("/admin/external-idps")
        })
        .map(|r| serde_json::from_slice(&r.body).expect("json body"))
}

/// 更新で api へ届いた本文。
async fn patched_body(env: &WebEnv) -> Option<Value> {
    env.api
        .received_requests()
        .await
        .expect("recorded requests")
        .iter()
        .find(|r| {
            r.method == wiremock::http::Method::PATCH
                && r.url.path().contains("/admin/external-idps/")
        })
        .map(|r| serde_json::from_slice(&r.body).expect("json body"))
}

/// 登録済みの外部 IdP が一覧に出て、**外部 IdP へ登録すべきリダイレクト URI** も見える。
/// これが出ていないと、設定作業のたびに URL を組み立て方から調べ直すことになる。
#[tokio::test]
async fn the_list_shows_the_redirect_uri_to_register_with_the_provider() {
    let env = setup().await;
    stub_admin(&env).await;
    stub_list(&env, json!([sample_provider()])).await;

    let response = send(
        &env.app,
        get_with_cookies(&format!("{}/admin/external-idps", env.prefix()), &cookies()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    assert!(html.contains("corp"), "{html}");
    assert!(
        html.contains("https://web.example.com/external/corp/callback"),
        "redirect uri is missing: {html}"
    );
}

/// **空欄のシークレットは送らない。** api の部分更新は未指定の項目に触れないため、これで
/// 「変更しない」になる。載せてしまうと、表示名を直しただけで連携が壊れる。
#[tokio::test]
async fn an_empty_secret_field_leaves_the_stored_secret_alone() {
    let env = setup().await;
    stub_admin(&env).await;
    stub_list(&env, json!([sample_provider()])).await;
    stub_patch(&env).await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/admin/external-idps/{PROVIDER_ID}/update", env.prefix()),
            Some(&cookies()),
            &[
                ("display_name", "Corp IdP (renamed)"),
                ("issuer", "https://idp.example.com"),
                (
                    "authorization_endpoint",
                    "https://idp.example.com/authorize",
                ),
                ("token_endpoint", "https://idp.example.com/token"),
                ("jwks_uri", "https://idp.example.com/jwks"),
                ("client_id", "abc"),
                ("client_secret", ""),
                ("scope_email", "1"),
                ("enabled", "1"),
                ("csrf_token", &csrf()),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);

    let body = patched_body(&env)
        .await
        .expect("the update reached the api");
    assert!(
        body.get("client_secret").is_none(),
        "an empty field must not be forwarded: {body}"
    );
    assert_eq!(body["display_name"], json!("Corp IdP (renamed)"));
    assert_eq!(body["scopes"], json!(["openid", "email"]));
    // チェックの外れたチェックボックスは送られてこないが、`false` として明示的に送る。
    // 未指定にすると api が「変更しない」と解釈し、チェックを外しても無効化できない。
    assert_eq!(body["allow_auto_link"], json!(false));
}

/// 入力されたシークレットは載せる（置き換え）。
#[tokio::test]
async fn a_filled_secret_field_replaces_the_stored_secret() {
    let env = setup().await;
    stub_admin(&env).await;
    stub_list(&env, json!([sample_provider()])).await;
    stub_patch(&env).await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/admin/external-idps/{PROVIDER_ID}/update", env.prefix()),
            Some(&cookies()),
            &[
                ("display_name", "Corp IdP"),
                ("issuer", "https://idp.example.com"),
                (
                    "authorization_endpoint",
                    "https://idp.example.com/authorize",
                ),
                ("token_endpoint", "https://idp.example.com/token"),
                ("jwks_uri", "https://idp.example.com/jwks"),
                ("client_id", "abc"),
                ("client_secret", "new-secret"),
                ("enabled", "1"),
                ("csrf_token", &csrf()),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);

    let body = patched_body(&env)
        .await
        .expect("the update reached the api");
    assert_eq!(body["client_secret"], json!("new-secret"));
}

/// CSRF トークンが合わなければ api を呼ばない。
#[tokio::test]
async fn a_bad_csrf_token_never_reaches_the_api() {
    let env = setup().await;
    stub_admin(&env).await;
    stub_list(&env, json!([sample_provider()])).await;
    stub_patch(&env).await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/admin/external-idps/{PROVIDER_ID}/update", env.prefix()),
            Some(&cookies()),
            &[
                ("display_name", "Hijacked"),
                ("issuer", "https://evil.example.com"),
                ("authorization_endpoint", "https://evil.example.com/a"),
                ("token_endpoint", "https://evil.example.com/t"),
                ("jwks_uri", "https://evil.example.com/j"),
                ("client_id", "abc"),
                ("client_secret", ""),
                ("csrf_token", "wrong"),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(
        patched_body(&env).await.is_none(),
        "the request must not be forwarded when CSRF verification fails"
    );
}

// ── SAML 対応（AP12）─────────────────────────────────────────────────────────

/// 一覧に SAML のプロバイダが混ざっても画面が開く。api は使わない側のプロトコルの項目を
/// `null` で返すため、これを取りこぼすと **SAML を 1 件登録した時点で画面ごと開かなくなる**。
/// ACS URL と SP entityID も出す（外部 IdP 側へ登録する値で、組み立て規則を推測させない）。
#[tokio::test]
async fn the_list_renders_saml_providers_with_the_values_to_register_upstream() {
    let env = setup().await;
    stub_admin(&env).await;
    stub_list(&env, json!([sample_provider(), sample_saml_provider()])).await;

    let response = send(
        &env.app,
        get_with_cookies(&format!("{}/admin/external-idps", env.prefix()), &cookies()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    assert!(html.contains("corp-saml"), "{html}");
    assert!(
        html.contains("https://web.example.com/t/external/corp-saml/saml/acs"),
        "the ACS URL to register with the provider is missing: {html}"
    );
    assert!(
        html.contains("https://web.example.com/t/saml/sp"),
        "the SP entityID to register with the provider is missing: {html}"
    );
    // OIDC のリダイレクト URI も並んで出る（プロトコルごとに列を分けない）。
    assert!(
        html.contains("https://web.example.com/external/corp/callback"),
        "{html}"
    );
}

/// SAML を選んだ登録では**SAML の欄だけ**が api へ届く。OIDC の欄も一緒に送ると、api が
/// 片方だけ埋まった半端な設定を作れてしまい、誤りがログイン時まで表に出ない。
#[tokio::test]
async fn registering_a_saml_provider_sends_only_the_saml_fields() {
    let env = setup().await;
    stub_admin(&env).await;
    stub_list(&env, json!([])).await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/[^/]+/admin/external-idps$"))
        .respond_with(ResponseTemplate::new(201).set_body_json(sample_saml_provider()))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/admin/external-idps", env.prefix()),
            Some(&cookies()),
            &[
                ("provider_code", "corp-saml"),
                ("display_name", "Corp SAML"),
                ("protocol", "saml"),
                ("issuer", "urn:idp:corp"),
                // 画面に残っていた OIDC の欄も送られてくるが、api へは渡さない。
                (
                    "authorization_endpoint",
                    "https://idp.example.com/authorize",
                ),
                ("client_id", "abc"),
                ("scope_email", "1"),
                ("saml_sso_url", "https://idp.example.com/sso"),
                // ブラウザは textarea の改行を CRLF にして送る。ここも同じ形で送る。
                (
                    "saml_certificates",
                    "MIIB\r\nCURRENT==\r\n\r\nMIIB\r\nNEXT==",
                ),
                (
                    "saml_name_id_format",
                    "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
                ),
                ("enabled", "1"),
                ("csrf_token", &csrf()),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);

    let body = posted_body(&env).await.expect("the create reached the api");
    assert_eq!(body["protocol"], json!("saml"));
    assert_eq!(body["saml_sso_url"], json!("https://idp.example.com/sso"));
    // 証明書は空行区切りで複数枚。行区切りにすると折り返された 1 枚が複数枚に割れる。
    assert_eq!(
        body["saml_certificates"],
        json!(["MIIBCURRENT==", "MIIBNEXT=="])
    );
    assert!(
        body.get("authorization_endpoint").is_none(),
        "OIDC fields must not leak into a SAML registration: {body}"
    );
    assert!(body.get("scopes").is_none(), "{body}");
}

/// 更新は **`protocol` を必ず送る**。api はプロトコル固有の設定を「`protocol` が指定されたときだけ」
/// まとめて差し替えるため、省くとエンドポイントの変更が黙って無視される（保存したつもりで
/// 何も変わらない）。
#[tokio::test]
async fn an_update_carries_the_protocol_so_endpoint_edits_are_not_silently_dropped() {
    let env = setup().await;
    stub_admin(&env).await;
    stub_list(&env, json!([sample_provider()])).await;
    stub_patch(&env).await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/admin/external-idps/{PROVIDER_ID}/update", env.prefix()),
            Some(&cookies()),
            &[
                ("display_name", "Corp IdP"),
                ("protocol", "oidc"),
                ("issuer", "https://idp.example.com"),
                (
                    "authorization_endpoint",
                    "https://idp.example.com/authorize2",
                ),
                ("token_endpoint", "https://idp.example.com/token"),
                ("jwks_uri", "https://idp.example.com/jwks"),
                ("client_id", "abc"),
                ("client_secret", ""),
                ("enabled", "1"),
                ("csrf_token", &csrf()),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);

    let body = patched_body(&env)
        .await
        .expect("the update reached the api");
    assert_eq!(body["protocol"], json!("oidc"));
    assert_eq!(
        body["authorization_endpoint"],
        json!("https://idp.example.com/authorize2")
    );
}

/// 貼り付けた IdP メタデータが登録フォームの初期値になる。**登録はしない**（管理者が値を
/// 確認してから登録する）。証明書は base64 が数行続くため、手で写すと誤りに気づけない。
#[tokio::test]
async fn imported_metadata_prefills_the_form_without_registering_anything() {
    let env = setup().await;
    stub_admin(&env).await;
    stub_list(&env, json!([])).await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/[^/]+/admin/external-idps/import-metadata$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "display_name": "Corp SAML",
            "entity_id": "urn:idp:corp",
            "sso_url": "https://idp.example.com/sso",
            "certificates": ["MIIBCURRENT==", "MIIBNEXT=="],
            "name_id_format": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
        })))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        post_multipart(
            &format!("{}/admin/external-idps/import", env.prefix()),
            &cookies(),
            &[
                ("csrf_token", &csrf()),
                ("metadata_xml", "<EntityDescriptor/>"),
            ],
        ),
    )
    .await;
    // 取り込みは登録ではないので PRG を挟まず、その場でフォームを描き直す。
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    assert!(html.contains("urn:idp:corp"), "{html}");
    assert!(html.contains("https://idp.example.com/sso"), "{html}");
    assert!(html.contains("MIIBCURRENT=="), "{html}");
    // 証明書更新期間の 2 枚目も落とさない。
    assert!(html.contains("MIIBNEXT=="), "{html}");
    // 何も登録していない。
    assert!(
        posted_body(&env).await.is_none(),
        "importing metadata must not register a provider"
    );
}

/// 取り込みの CSRF トークンが合わなければ api を呼ばない（メタデータ取り込みは管理者の
/// 画面操作であり、他サイトから踏ませてよい操作ではない）。
#[tokio::test]
async fn a_bad_csrf_token_never_reaches_the_import_endpoint() {
    let env = setup().await;
    stub_admin(&env).await;
    stub_list(&env, json!([])).await;

    let response = send(
        &env.app,
        post_multipart(
            &format!("{}/admin/external-idps/import", env.prefix()),
            &cookies(),
            &[
                ("csrf_token", "wrong"),
                ("metadata_xml", "<EntityDescriptor/>"),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(
        !env.api
            .received_requests()
            .await
            .expect("recorded requests")
            .iter()
            .any(|r| r.url.path().ends_with("/import-metadata")),
        "the import must not be forwarded when CSRF verification fails"
    );
}

/// **一覧に登録フォームは無い。** 登録は「プロトコルを選ぶ」から始まる —— OIDC と SAML の欄を
/// 1 枚に並べると、埋めるべき欄と埋めなくてよい欄が同居して読み取れない。
#[tokio::test]
async fn the_list_offers_registration_without_showing_a_form() {
    let env = setup().await;
    stub_admin(&env).await;
    stub_list(&env, json!([sample_provider()])).await;

    let html = body_text(
        send(
            &env.app,
            get_with_cookies(&format!("{}/admin/external-idps", env.prefix()), &cookies()),
        )
        .await,
    )
    .await;
    assert!(
        html.contains(&format!(
            r#"href="{}/admin/external-idps/new""#,
            env.prefix()
        )),
        "the list must lead to the protocol choice: {html}"
    );
    assert!(
        !html.contains(r#"name="provider_code""#),
        "the list must not carry a registration form: {html}"
    );
    // 編集も専用ページへ向かう（一覧に開くフォームが無いため）。
    assert!(
        html.contains(&format!(
            r#"href="{}/admin/external-idps/{PROVIDER_ID}/edit""#,
            env.prefix()
        )),
        "{html}"
    );
}

/// 選択画面は 2 つのプロトコルへ分岐するだけ。
#[tokio::test]
async fn the_entry_point_offers_exactly_the_two_protocols() {
    let env = setup().await;
    stub_admin(&env).await;

    let html = body_text(
        send(
            &env.app,
            get_with_cookies(
                &format!("{}/admin/external-idps/new", env.prefix()),
                &cookies(),
            ),
        )
        .await,
    )
    .await;
    for protocol in ["oidc", "saml"] {
        assert!(
            html.contains(&format!(
                r#"href="{}/admin/external-idps/new/{protocol}""#,
                env.prefix()
            )),
            "the {protocol} entry point is missing: {html}"
        );
    }
}

/// **OIDC のフォームに SAML の欄は出ない**（逆も同じ）。プロトコルは経路が決めており、
/// 出し分けの JS は要らない —— JS が動かない環境でも、見えている欄がそのまま送る欄になる。
///
/// メタデータの取り込みは SAML にだけ出す。OIDC の discovery は未対応で、取り込む先が無い。
#[tokio::test]
async fn each_protocol_form_shows_only_its_own_fields() {
    let env = setup().await;
    stub_admin(&env).await;

    let oidc = body_text(
        send(
            &env.app,
            get_with_cookies(
                &format!("{}/admin/external-idps/new/oidc", env.prefix()),
                &cookies(),
            ),
        )
        .await,
    )
    .await;
    assert!(oidc.contains(r#"name="jwks_uri""#), "{oidc}");
    assert!(oidc.contains(r#"name="protocol" value="oidc""#), "{oidc}");
    assert!(
        !oidc.contains(r#"name="saml_sso_url""#),
        "SAML fields must not appear on the OIDC form: {oidc}"
    );
    assert!(
        !oidc.contains(r#"name="metadata_xml""#),
        "OIDC has no metadata to import: {oidc}"
    );

    let saml = body_text(
        send(
            &env.app,
            get_with_cookies(
                &format!("{}/admin/external-idps/new/saml", env.prefix()),
                &cookies(),
            ),
        )
        .await,
    )
    .await;
    assert!(saml.contains(r#"name="saml_sso_url""#), "{saml}");
    assert!(saml.contains(r#"name="protocol" value="saml""#), "{saml}");
    assert!(saml.contains(r#"name="metadata_xml""#), "{saml}");
    assert!(
        !saml.contains(r#"name="jwks_uri""#),
        "OIDC fields must not appear on the SAML form: {saml}"
    );
    // scope は OIDC にしか無い（SAML アサーションに scope は無い）。
    assert!(!saml.contains(r#"name="scope_email""#), "{saml}");
}

/// 綴りの違うプロトコルは 404。既定へ丸めると、URL を直打ちした人が意図と違うプロトコルの
/// フォームを埋めることになる。
#[tokio::test]
async fn an_unknown_protocol_is_not_rounded_to_a_default() {
    let env = setup().await;
    stub_admin(&env).await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/admin/external-idps/new/ws-fed", env.prefix()),
            &cookies(),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// 編集はプロトコルが固定で、メタデータの取り込みは出さない（編集中に別の IdP のメタデータで
/// 上書きすると、何を保存しようとしていたのか分からなくなる）。
#[tokio::test]
async fn editing_pins_the_protocol_and_does_not_offer_metadata_import() {
    let env = setup().await;
    stub_admin(&env).await;
    stub_list(&env, json!([sample_saml_provider()])).await;

    let html = body_text(
        send(
            &env.app,
            get_with_cookies(
                &format!(
                    "{}/admin/external-idps/{SAML_PROVIDER_ID}/edit",
                    env.prefix()
                ),
                &cookies(),
            ),
        )
        .await,
    )
    .await;
    // プロトコルは変更できない（api も拒否する）。値は hidden で送る。
    assert!(html.contains(r#"name="protocol" value="saml""#), "{html}");
    assert!(
        !html.contains(r#"name="jwks_uri""#),
        "editing a SAML provider must not offer the OIDC fields: {html}"
    );
    assert!(
        !html.contains(r#"name="metadata_xml""#),
        "editing must not offer to overwrite the form from another provider's metadata: {html}"
    );
    // 保存済みの証明書は空行区切りで戻り、追記・差し替えができる。
    assert!(html.contains("MIIBCURRENT==\n\nMIIBNEXT=="), "{html}");
}

/// 一覧に無い id（削除済み・別テナント）の編集は一覧へ戻す。空のフォームを出すと、編集の
/// つもりで新規登録することになる。
#[tokio::test]
async fn editing_an_unknown_provider_returns_to_the_list() {
    let env = setup().await;
    stub_admin(&env).await;
    stub_list(&env, json!([])).await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/admin/external-idps/{PROVIDER_ID}/edit", env.prefix()),
            &cookies(),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok()),
        Some(format!("{}/admin/external-idps?error=notfound", env.prefix()).as_str())
    );
}

/// **要求する scope は選択で入れる。** 保存済みの値はチェック状態に戻り、相手方が独自に定義した
/// scope は自由入力側へ回る —— 選択肢を固定値に閉じると、`groups` のような相手固有の scope が
/// 編集のたびに落ちる。
#[tokio::test]
async fn saved_scopes_come_back_as_checkboxes_and_provider_specific_ones_stay_editable() {
    let env = setup().await;
    stub_admin(&env).await;
    let mut provider = sample_provider();
    provider["scopes"] = json!(["openid", "email", "groups"]);
    stub_list(&env, json!([provider])).await;

    let html = body_text(
        send(
            &env.app,
            get_with_cookies(
                &format!("{}/admin/external-idps/{PROVIDER_ID}/edit", env.prefix()),
                &cookies(),
            ),
        )
        .await,
    )
    .await;
    assert!(
        html.contains(r#"name="scope_email" checked"#),
        "a saved scope must come back checked: {html}"
    );
    assert!(
        !html.contains(r#"name="scope_profile" checked"#),
        "a scope that was not saved must not look selected: {html}"
    );
    // 相手固有の scope は自由入力へ。`openid` は必ず付くので、ここには出さない。
    assert!(
        html.contains(r#"id="scopes_extra" name="scopes_extra" value="groups""#),
        "{html}"
    );
}

/// 知らないプロトコルで登録が失敗したら、**一覧へ落とす**。`protocol` はフォームから来る値で、
/// ハンドラは未知の綴りを丸めずに api へ通す（判断を 1 か所に寄せるため）。それをそのまま
/// リダイレクト先の経路へ差し込むと、行き先の無い URL や `?` で壊れたクエリを Location に
/// 載せることになる。
#[tokio::test]
async fn a_failed_registration_with_an_unknown_protocol_falls_back_to_the_list() {
    let env = setup().await;
    stub_admin(&env).await;
    stub_list(&env, json!([])).await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/[^/]+/admin/external-idps$"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"error": "invalid"})))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/admin/external-idps", env.prefix()),
            Some(&cookies()),
            &[
                ("provider_code", "corp"),
                ("display_name", "Corp"),
                ("protocol", "ws-fed?x=1"),
                ("issuer", "https://idp.example.com"),
                ("csrf_token", &csrf()),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok()),
        Some(format!("{}/admin/external-idps?error=validation", env.prefix()).as_str())
    );
}

/// 登録に失敗したら、同じプロトコルのフォームへ戻す（プロトコルを選び直させない）。
#[tokio::test]
async fn a_failed_registration_returns_to_the_form_for_the_same_protocol() {
    let env = setup().await;
    stub_admin(&env).await;
    stub_list(&env, json!([])).await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/[^/]+/admin/external-idps$"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"error": "invalid"})))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/admin/external-idps", env.prefix()),
            Some(&cookies()),
            &[
                ("provider_code", "corp-saml"),
                ("display_name", "Corp SAML"),
                ("protocol", "saml"),
                ("issuer", "urn:idp:corp"),
                ("saml_sso_url", "not-a-url"),
                ("csrf_token", &csrf()),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok()),
        Some(
            format!(
                "{}/admin/external-idps/new/saml?error=validation",
                env.prefix()
            )
            .as_str()
        )
    );
}
