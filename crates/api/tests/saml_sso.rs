//! SAML SP-initiated SSO の統合テスト（DB あり）。
//!
//! `/{tenant_id}/saml/sso`（Redirect / POST binding）→ web ハンドオフ →
//! `/internal/saml/resume`（SSO 判定・署名付き SAML Response 発行）の一連を検証する。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test saml_sso

mod support;

use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, SET_COOKIE};
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use serde_json::{json, Value};
use sqlx::MySqlPool;
use std::io::Write as _;
use support::{
    body_json, create_sso_session, location, post_internal, query_param, send, unique,
    SERVICE_TOKEN,
};

const ACS_URL: &str = "https://sp.example.test/acs";

/// 有効な SAML SP をテナントへ直接登録して entity_id を返す。
///
/// 空の `saml_service_providers` へ複数テストが同時に INSERT すると、UNIQUE 索引のギャップロックで
/// InnoDB のデッドロック（1213）が起き得るため、デッドロックのみ再試行する（テストデータ生成の都合で、
/// アプリの挙動検証ではない）。
async fn insert_service_provider(
    pool: &MySqlPool,
    tenant_id: &str,
    name_id_format: &str,
) -> String {
    let entity_id = format!("https://sp.example.test/metadata/{}", unique());
    for attempt in 0.. {
        let result = sqlx::query(
            "INSERT INTO saml_service_providers \
             (id, tenant_id, display_name, entity_id, acs_url, name_id_format, x509_certificate, \
              enabled, created_at, updated_at) \
             VALUES (?, ?, 'Integration SAML SP', ?, ?, ?, NULL, 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))",
        )
        .bind(uuid::Uuid::now_v7().to_string())
        .bind(tenant_id)
        .bind(&entity_id)
        .bind(ACS_URL)
        .bind(name_id_format)
        .execute(pool)
        .await;
        match result {
            Ok(_) => break,
            Err(e) if attempt < 5 && e.to_string().contains("1213") => continue,
            Err(e) => panic!("insert saml service provider: {e}"),
        }
    }
    entity_id
}

fn authn_request_xml(sp_entity_id: &str, request_id: &str, acs_url: Option<&str>) -> String {
    let acs_attr = acs_url
        .map(|acs| format!(" AssertionConsumerServiceURL=\"{acs}\""))
        .unwrap_or_default();
    format!(
        r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{request_id}" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"{acs_attr}>
  <saml:Issuer>{sp_entity_id}</saml:Issuer>
</samlp:AuthnRequest>"#
    )
}

/// HTTP-Redirect binding のクエリ値（base64(raw DEFLATE(xml)) を URL エンコード）を組み立てる。
fn redirect_binding_query(xml: &str, relay_state: Option<&str>) -> String {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(xml.as_bytes()).expect("deflate");
    let encoded = STANDARD.encode(encoder.finish().expect("finish deflate"));
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("SAMLRequest", &encoded);
    if let Some(rs) = relay_state {
        serializer.append_pair("RelayState", rs);
    }
    serializer.finish()
}

/// `/internal/saml/resume` を呼ぶ（web の代わり）。
async fn resume_saml(
    app: &axum::Router,
    tenant: &str,
    handle: Option<&str>,
    saml_request_id: Option<&str>,
    sso_session_id: Option<&str>,
) -> Value {
    let response = send(
        app,
        post_internal(
            "/internal/saml/resume",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": tenant,
                "handle": handle,
                "saml_request_id": saml_request_id,
                "sso_session_id": sso_session_id,
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "saml resume");
    body_json(response).await
}

#[tokio::test]
async fn full_sso_flow_issues_a_signed_response_after_login() {
    let Some(env) = support::setup("saml sso flow").await else {
        return;
    };
    let entity_id = insert_service_provider(
        &env.pool,
        &env.root_tenant_id,
        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    )
    .await;

    // 1. Redirect binding で AuthnRequest を受けると web の /saml/continue へハンドオフする。
    let xml = authn_request_xml(&entity_id, "_it-request-1", Some(ACS_URL));
    let uri = format!(
        "/{}/saml/sso?{}",
        env.root_tenant_id,
        redirect_binding_query(&xml, Some("it-relay-state"))
    );
    let response = send(
        &env.app,
        Request::builder().uri(&uri).body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND, "handoff to web");
    // api はブラウザ Cookie を発行しない（ADR-0018 決定 2 と同方式）。
    assert!(
        response
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .next()
            .is_none(),
        "the api must not set browser cookies on /saml/sso"
    );
    let redirect = location(&response);
    assert!(
        redirect.starts_with(&format!(
            "{}/{}/saml/continue?",
            env.public_web_base_url, env.root_tenant_id
        )),
        "handoff URL: {redirect}"
    );
    let handle = query_param(&redirect, "handle").expect("handle in Location");

    // 2. SSO 未確立の resume はログイン誘導（進行状態 id を返す）。
    let body = resume_saml(&env.app, &env.root_tenant_id, Some(&handle), None, None).await;
    assert_eq!(body["result"], "login_required", "{body}");
    let saml_request_id = body["saml_request_id"].as_str().expect("saml_request_id");

    // ハンドルは単回使用（再利用は expired）。
    let body = resume_saml(&env.app, &env.root_tenant_id, Some(&handle), None, None).await;
    assert_eq!(
        body["result"], "expired",
        "handle must be single-use: {body}"
    );

    // 3. ログイン（SSO 確立）後、進行状態 id で再開すると署名付き SAML Response が発行される。
    let sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let body = resume_saml(
        &env.app,
        &env.root_tenant_id,
        None,
        Some(saml_request_id),
        Some(&sso),
    )
    .await;
    assert_eq!(body["result"], "completed", "{body}");
    assert_eq!(body["acs_url"], ACS_URL);
    assert_eq!(body["relay_state"], "it-relay-state");

    let decoded = STANDARD
        .decode(body["saml_response"].as_str().expect("saml_response"))
        .expect("base64 SAMLResponse");
    let response_xml = String::from_utf8(decoded).expect("utf-8 SAMLResponse");
    let tenant_issuer = format!("{}/{}", env.issuer, env.root_tenant_id);
    assert!(response_xml.contains("urn:oasis:names:tc:SAML:2.0:status:Success"));
    assert!(response_xml.contains("InResponseTo=\"_it-request-1\""));
    assert!(
        response_xml.contains(&format!("<saml:Issuer>{tenant_issuer}</saml:Issuer>")),
        "issuer must be the tenant issuer: {response_xml}"
    );
    assert!(
        response_xml.contains(&format!("<saml:Audience>{entity_id}</saml:Audience>")),
        "audience must be the SP entity id"
    );
    // NameID は SP 登録の emailAddress Format に従い、seed 管理者のメールになる。
    assert!(
        response_xml.contains(">admin@example.com</saml:NameID>"),
        "NameID must carry the email: {response_xml}"
    );
    assert!(
        response_xml.contains("<ds:Signature"),
        "assertion must be signed"
    );
    assert!(response_xml.contains("<ds:SignatureValue>"));

    // 4. 進行状態は応答発行時に削除される（同じ id での再開は expired）。
    let body = resume_saml(
        &env.app,
        &env.root_tenant_id,
        None,
        Some(saml_request_id),
        Some(&sso),
    )
    .await;
    assert_eq!(body["result"], "expired", "request must be deleted: {body}");
}

#[tokio::test]
async fn post_binding_hands_off_like_the_redirect_binding() {
    let Some(env) = support::setup("saml sso post binding").await else {
        return;
    };
    let entity_id = insert_service_provider(
        &env.pool,
        &env.root_tenant_id,
        "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
    )
    .await;

    let xml = authn_request_xml(&entity_id, "_it-request-post", None);
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("SAMLRequest", &STANDARD.encode(&xml));
    let form = serializer.finish();
    let response = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{}/saml/sso", env.root_tenant_id))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND, "handoff to web");
    let handle = query_param(&location(&response), "handle").expect("handle");

    // persistent Format の NameID は外部公開サブジェクト識別子（sub）で、email ではない。
    let sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let body = resume_saml(
        &env.app,
        &env.root_tenant_id,
        Some(&handle),
        None,
        Some(&sso),
    )
    .await;
    assert_eq!(body["result"], "completed", "{body}");
    let decoded = STANDARD
        .decode(body["saml_response"].as_str().unwrap())
        .expect("base64");
    let response_xml = String::from_utf8(decoded).unwrap();
    assert!(
        !response_xml.contains(">admin@example.com</saml:NameID>"),
        "persistent NameID must not expose the email as the identifier"
    );
    // AuthnRequest が ACS を指定しない場合も、登録済み ACS へ送る。
    assert_eq!(body["acs_url"], ACS_URL);
}

#[tokio::test]
async fn unknown_sp_and_acs_mismatch_are_rejected_without_redirect() {
    let Some(env) = support::setup("saml sso rejects").await else {
        return;
    };

    // 未登録 SP → 400（リダイレクトしない）。
    let xml = authn_request_xml("https://unregistered.example.test/metadata", "_x", None);
    let uri = format!(
        "/{}/saml/sso?{}",
        env.root_tenant_id,
        redirect_binding_query(&xml, None)
    );
    let response = send(
        &env.app,
        Request::builder().uri(&uri).body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "unknown SP");

    // ACS 不一致 → 400（登録外の送信先へアサーションを送らない）。
    let entity_id = insert_service_provider(
        &env.pool,
        &env.root_tenant_id,
        "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
    )
    .await;
    let xml = authn_request_xml(&entity_id, "_x", Some("https://evil.example.test/acs"));
    let uri = format!(
        "/{}/saml/sso?{}",
        env.root_tenant_id,
        redirect_binding_query(&xml, None)
    );
    let response = send(
        &env.app,
        Request::builder().uri(&uri).body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "ACS mismatch");

    // SAMLRequest 無し → 400。
    let response = send(
        &env.app,
        Request::builder()
            .uri(format!("/{}/saml/sso", env.root_tenant_id))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "missing SAMLRequest"
    );
}

#[tokio::test]
async fn disabled_sp_is_rejected() {
    let Some(env) = support::setup("saml sso disabled sp").await else {
        return;
    };
    let entity_id = insert_service_provider(
        &env.pool,
        &env.root_tenant_id,
        "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
    )
    .await;
    sqlx::query("UPDATE saml_service_providers SET enabled = 0 WHERE entity_id = ?")
        .bind(&entity_id)
        .execute(&env.pool)
        .await
        .expect("disable SP");

    let xml = authn_request_xml(&entity_id, "_x", None);
    let uri = format!(
        "/{}/saml/sso?{}",
        env.root_tenant_id,
        redirect_binding_query(&xml, None)
    );
    let response = send(
        &env.app,
        Request::builder().uri(&uri).body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "disabled SP");
}

#[tokio::test]
async fn resume_requires_the_service_token() {
    let Some(env) = support::setup("saml resume authz").await else {
        return;
    };
    let response = send(
        &env.app,
        post_internal(
            "/internal/saml/resume",
            None,
            json!({ "tenant_id": env.root_tenant_id, "handle": "x" }),
        ),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "missing service token"
    );
}
