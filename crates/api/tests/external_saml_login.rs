//! 外部 SAML IdP を認証元として使う経路の統合テスト（DB あり。AP12。ADR-0027）。
//!
//! 単体テスト（`domain::saml_external_idp`）は署名検証と応答の解釈を固めているが、そこには
//! **登録した設定が実際に使われるか**が含まれない。ここは管理 API で SAML プロバイダを登録し、
//! `/internal/external/start` が返した `AuthnRequest` の ID へ答える応答を作って
//! `/internal/external/saml/acs` へ投げ、ログインが成立するまでを通す。
//!
//! この経路が壊れる形は「どこかで値の受け渡しがずれる」——SP entityID の組み立て、
//! `InResponseTo` の保存、証明書の保存形式——で、いずれも単体テストの外にある。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test external_saml_login

mod support;

use axum::http::StatusCode;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{Duration, Utc};
use idp_api::domain::saml_external_idp::NAME_ID_FORMAT_UNSPECIFIED;
use idp_api::domain::saml_response::{
    build_signed_response_xml, generate_saml_id, SamlResponseInput, SamlSigner,
};
use serde_json::{json, Value};
use sqlx::MySqlPool;
use std::io::Read as _;
use support::{
    admin_token, body_json, create_plain_user, post, post_internal, send, unique, SERVICE_TOKEN,
};

/// テスト専用の自己署名証明書と鍵（`domain::saml_external_idp` の単体テストと同じ実物）。
/// **本番のどこからも参照されない。** 署名は IdP 側の生成器に作らせ、SP 側の検証器で確かめる。
const TEST_KEY_PEM: &str = concat!(
    "-----BEGIN RSA PRIVATE KEY-----\n",
    "MIIEpAIBAAKCAQEAtNcidptZa/sP2KxNTbEXiEYxtt4F90gKhG3xx/uAcHlHUdmW\n",
    "AqDzM+oOBgOOGusX5FFBFXZZfZ0QkuK62zEryXs3UujdzdY7zOmbqX+i3nC0CoIe\n",
    "DpkE8ZnFhxQEg1dpTfgYkiJ40bLYv7/eDz6EqU6vQfCytsh78KlkzOsWsrKoqpjw\n",
    "YIA0brZ6kZ+WC6R+tgZL7vJW0goEOtQ33oOclvqPUgLrw7gio5Ojz9qMfVBhNmAt\n",
    "8bC1UoZaw8ZuRWm3HQKakXn9j6wLaXE+VwrzZ1qVwTKzipIiCTzxg8ko7WsgMu0z\n",
    "M2aNjBDztvqw6vvfNJu2O9Dw48vt7fognnr16QIDAQABAoIBAAJwGgdWTczOXCbU\n",
    "H9Cp0ALmy1nHQXZVcsrZPpavFcquX99DGyoa6FxtTdYX6y0CuVY7IDD9YPR4Dxaj\n",
    "1tgIoCn9rr+/4umY90Jqbc5JqbTs+QhhO61/s5jcNVT+WJc6sPE7pH0n2NAe5Jwl\n",
    "JoW3Fou/w04UxBwBtOYIKpM2oh4zk5QWXJs/crAvCFlixednlz8mM88jF+PK04gt\n",
    "K0zEbK5LIZEMpBFOz+XRUQ62gigTpZBj3YXCbOBM00AEiL5b/rIzBS3ULgMNCDG4\n",
    "fdeHGv2bxhhZdN/acNh63Yr05iZM1umbye0yvu80p0CydTfxBPGOl7e6OQ1SuuT+\n",
    "CZA/gQECgYEA247YUvx8kIW8BzGARMxJLwX94ZUfxa4u5wRTQ3wtaFHcd074R2zS\n",
    "kyoG5DwAE01IgJ/WwcG0HQ3SNsDkEM0yTtv90HC2gbK3YorT4FcNOZzNvCYGRN6R\n",
    "RBVYtHetg2YrKXRAMn8Qy9Gi9uvVf3DryLdvH1nRkFkiAZDpDmcvksECgYEA0tsn\n",
    "bBmtBYUX2fkUE+mXGihxB5ciYxoWIWnglMhpMsIOoeI9K6uvdhVgc6caZw2bUpi6\n",
    "/w7THsuG7JGBzOlxMpe89xWBB+TEMwKitaVQAuSNOcUHR1HxTrDliSj0pL8H+qvt\n",
    "m7pes2Y624PN2yiSgvsQHReeqYwH4uHLg22atSkCgYEA1Logardr0XNh7O5PQ1lT\n",
    "hxYdGFYuRJAxrW+JZReJv0uheo+vCzUrCZ9ssfJYeFsm5kj4AR827feYN6jI0Gag\n",
    "WbvYvf6XNi78c6PjCbgOfkWpKKUG6e9jfD3ahnB2U5vIMhAKq2Jl2bUyWl/Bqgq0\n",
    "yPLB3fRekadqxW2sAWKEu4ECgYEAzLRYxHj04fwBWOuY03Ae8xU6Dp1qk/26aHwK\n",
    "vUcH4nBFlmI28tO+B4zfU8hyOIQcPAbs3Dv/ONFszvTAqDgmXnCz0sk8uHYfCErR\n",
    "vjmcwQI0HVasJ1BlTfktDokFYX/YdkM97cb0s4RXNc/zJYZxHtoxHZ1VutKowVpm\n",
    "otTgsmkCgYBliNbW1c/M7blO4m1XeiGeiY1Pvx0S5UF4QBAK4J0GeyhrTs75hfJQ\n",
    "a6LZN9vdOyJgscruyMsLs+f4JyHdRy6+HRLeBAnKJXvJNe+hmWGG1usff1tQPDd6\n",
    "nkc33BX3Yu3ZV6agi/W7wdQOMQHaWNNlR4h76bNOXSF44fFlkh+6/Q==\n",
    "-----END RSA PRIVATE KEY-----\n"
);

const TEST_CERTIFICATE: &str = concat!(
    "MIIDEzCCAfugAwIBAgIUS/GBZGhWNXp2jDPH758Z9FfRuTcwDQYJKoZIhvcNAQELBQAwGDEWMBQGA1UEAww",
    "Nc2FtbC10ZXN0LWlkcDAgFw0yNjA4MTAxNzE0MzFaGA8yMTI2MDcxNzE3MTQzMVowGDEWMBQGA1UEAwwNc2",
    "FtbC10ZXN0LWlkcDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALTXInabWWv7D9isTU2xF4hGM",
    "bbeBfdICoRt8cf7gHB5R1HZlgKg8zPqDgYDjhrrF+RRQRV2WX2dEJLiutsxK8l7N1Lo3c3WO8zpm6l/ot5w",
    "tAqCHg6ZBPGZxYcUBINXaU34GJIieNGy2L+/3g8+hKlOr0HwsrbIe/CpZMzrFrKyqKqY8GCANG62epGflgu",
    "kfrYGS+7yVtIKBDrUN96DnJb6j1IC68O4IqOTo8/ajH1QYTZgLfGwtVKGWsPGbkVptx0CmpF5/Y+sC2lxPl",
    "cK82dalcEys4qSIgk88YPJKO1rIDLtMzNmjYwQ87b6sOr73zSbtjvQ8OPL7e36IJ569ekCAwEAAaNTMFEwH",
    "QYDVR0OBBYEFAT0eeOfZCtp1gyarcLEOGAQMoXQMB8GA1UdIwQYMBaAFAT0eeOfZCtp1gyarcLEOGAQMoXQ",
    "MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAHZUr3nBbiOIyA0PShhu3+/PMTr33zEJOw8",
    "eJUb/7DkNdR4lLeBEFpMsNHRErQ/0cZ4DnTBrySDII7egjPF1fzyetqhDXk9vxP3Vr/zWLAT4O2cRuRXYbr",
    "zfeIETSHM321pfpDG4up95+prur3wQMHkEO2k/8/QDoo0/+VYl/9g27E+WRjnEVtWc+JV6VS3QKgCdFXyn/",
    "qvnp13+jU4lsXwADkSparze4ujzLH6H0lkN7sw1pn269DlmPMhR7tENNynNPK0s/pIk/qVPUD9XBcfnfLD5",
    "2lL4Z2nOgIDfG0JCaGV9BNrCl1wn62lzi3FmxRX8gztUNCqYo0WMlG1tDo8="
);

const IDP_SSO_URL: &str = "https://idp.corp.example.com/sso";

/// 開始応答から取り出した、応答を組み立てるために要る値。
struct StartedLogin {
    /// `AuthnRequest` の `ID`（応答の `InResponseTo` に載せる）。
    request_id: String,
    /// `RelayState`（進行状態を引く鍵）。
    relay_state: String,
}

/// SAML の外部 IdP を管理 API で登録し、`(id, provider_code, issuer)` を返す。
async fn register_saml_provider(
    env: &support::TestEnv,
    admin_tok: &str,
) -> (String, String, String) {
    let provider_code = format!("saml-{}", unique());
    let issuer = format!("https://idp.corp.example.com/{provider_code}");
    let res = send(
        &env.app,
        post(
            admin_tok,
            &format!("/{}/admin/external-idps", env.root_tenant_id),
            json!({
                "provider_code": provider_code,
                "display_name": "Corp SAML",
                "protocol": "saml",
                "issuer": issuer,
                "saml_sso_url": IDP_SSO_URL,
                "saml_certificates": [TEST_CERTIFICATE],
                "saml_name_id_format": NAME_ID_FORMAT_UNSPECIFIED,
                "enabled": true
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "register saml provider");
    let created = body_json(res).await;
    assert_eq!(created["protocol"], "saml");
    (
        created["id"].as_str().expect("id").to_string(),
        provider_code,
        issuer,
    )
}

/// 外部の同一性（`issuer` + `NameID`）を利用者へ結び付ける。SAML のアサーションは
/// `email_verified` を主張できないため自動連携が働かない（ADR-0023）。連携済みの状態を作る。
async fn link_identity(
    pool: &MySqlPool,
    user_id: &str,
    provider_id: &str,
    issuer: &str,
    subject: &str,
) {
    sqlx::query(
        "INSERT INTO user_external_identities \
         (id, user_id, provider_id, external_issuer, external_subject) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(user_id)
    .bind(provider_id)
    .bind(issuer)
    .bind(subject)
    .execute(pool)
    .await
    .expect("link external identity");
}

/// `/internal/external/start` を呼び、リダイレクト先から `AuthnRequest` の ID と `RelayState` を取り出す。
async fn start_login(env: &support::TestEnv, provider_code: &str) -> StartedLogin {
    let res = send(
        &env.app,
        post_internal(
            "/internal/external/start",
            Some(SERVICE_TOKEN),
            json!({ "tenant_id": env.root_tenant_id, "provider_code": provider_code }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "start");
    let body = body_json(res).await;
    assert_eq!(body["result"], "redirect", "{body}");
    let location = body["location"].as_str().expect("location").to_string();
    assert!(
        location.starts_with(IDP_SSO_URL),
        "the AuthnRequest must go to the configured SSO URL: {location}"
    );
    StartedLogin {
        request_id: authn_request_id(&location),
        relay_state: query_value(&location, "RelayState"),
    }
}

/// HTTP-Redirect binding の `SAMLRequest`（base64(raw DEFLATE(XML))）から `ID` を取り出す。
fn authn_request_id(location: &str) -> String {
    let encoded = query_value(location, "SAMLRequest");
    let compressed = STANDARD.decode(encoded).expect("base64 SAMLRequest");
    let mut xml = String::new();
    flate2::read::DeflateDecoder::new(&compressed[..])
        .read_to_string(&mut xml)
        .expect("inflate SAMLRequest");
    let marker = " ID=\"";
    let start = xml.find(marker).expect("AuthnRequest ID") + marker.len();
    let rest = &xml[start..];
    rest[..rest.find('"').expect("closing quote")].to_string()
}

/// リダイレクト先 URL のクエリから値を 1 つ取り出す（percent デコード済み）。
fn query_value(location: &str, key: &str) -> String {
    url::Url::parse(location)
        .expect("redirect location is a URL")
        .query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
        .unwrap_or_else(|| panic!("{key} is missing from {location}"))
}

/// 外部 IdP になったつもりで、署名付きの `SAMLResponse`（base64）を作る。
fn signed_response(
    env: &support::TestEnv,
    issuer: &str,
    provider_code: &str,
    in_response_to: &str,
    name_id: &str,
) -> String {
    let now = Utc::now();
    let signer = SamlSigner::from_pem("RS256", TEST_KEY_PEM).expect("signer");
    let xml = build_signed_response_xml(
        &SamlResponseInput {
            response_id: &generate_saml_id(),
            assertion_id: &generate_saml_id(),
            issued_at: now,
            idp_entity_id: issuer,
            // 本 IdP の SP としての entityID・ACS URL。api が組み立てる規則と一致していないと
            // `AudienceRestriction` の検査に落ちる（この一致こそがここで確かめたいこと）。
            sp_entity_id: &format!("{}/{}/saml/sp", env.public_web_base_url, env.root_tenant_id),
            acs_url: &format!(
                "{}/{}/external/{provider_code}/saml/acs",
                env.public_web_base_url, env.root_tenant_id
            ),
            in_response_to: Some(in_response_to),
            name_id,
            name_id_format: NAME_ID_FORMAT_UNSPECIFIED,
            authn_instant: now,
            session_index: "_session-1",
            not_on_or_after: now + Duration::minutes(5),
            email: None,
        },
        &signer,
    )
    .expect("build signed response");
    STANDARD.encode(xml)
}

/// ACS へ応答を投げる。
async fn post_acs(env: &support::TestEnv, saml_response: &str, relay_state: &str) -> Value {
    let res = send(
        &env.app,
        post_internal(
            "/internal/external/saml/acs",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": env.root_tenant_id,
                "saml_response": saml_response,
                "relay_state": relay_state
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "acs");
    body_json(res).await
}

/// **登録 → 開始 → ACS → ログイン成立**まで通る。署名付きの応答が、登録した証明書で検証され、
/// 保存した `InResponseTo` と突き合わされ、連携済みの利用者へ解決されて SSO セッションになる。
#[tokio::test]
async fn a_registered_saml_provider_signs_a_user_in_end_to_end() {
    let Some(env) = support::setup("external saml login").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let (provider_id, provider_code, issuer) = register_saml_provider(&env, &admin_tok).await;

    let user_id = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let name_id = format!("external-{}", unique());
    link_identity(&env.pool, &user_id, &provider_id, &issuer, &name_id).await;

    let started = start_login(&env, &provider_code).await;
    let response = signed_response(&env, &issuer, &provider_code, &started.request_id, &name_id);
    let body = post_acs(&env, &response, &started.relay_state).await;

    assert_eq!(body["result"], "success", "{body}");
    let sso_session_id = body["sso_session_id"].as_str().expect("sso_session_id");
    // 発行された SSO セッションは**その利用者のもの**である（誰のログインになったかを確かめる）。
    let owner: String =
        sqlx::query_scalar("SELECT user_id FROM sso_sessions WHERE session_hash = ?")
            .bind(idp_api::infrastructure::crypto::sha256_hex(sso_session_id))
            .fetch_one(&env.pool)
            .await
            .expect("sso session row");
    assert_eq!(owner, user_id);
}

/// `RelayState` は単回使用。同じ応答をもう一度投げてもログインにならない
/// （ブラウザ経由で運ばれる値なので、盗まれた応答の再送は現実的な攻撃である）。
#[tokio::test]
async fn a_replayed_assertion_does_not_sign_anyone_in_twice() {
    let Some(env) = support::setup("external saml replay").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let (provider_id, provider_code, issuer) = register_saml_provider(&env, &admin_tok).await;
    let user_id = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let name_id = format!("external-{}", unique());
    link_identity(&env.pool, &user_id, &provider_id, &issuer, &name_id).await;

    let started = start_login(&env, &provider_code).await;
    let response = signed_response(&env, &issuer, &provider_code, &started.request_id, &name_id);
    assert_eq!(
        post_acs(&env, &response, &started.relay_state).await["result"],
        "success"
    );

    let replayed = post_acs(&env, &response, &started.relay_state).await;
    assert_eq!(replayed["result"], "state_expired", "{replayed}");
}

/// 改竄された応答は通らない。登録した証明書で検証していることの確認でもある——保存の途中で
/// 証明書が壊れていれば、正しい応答すら通らずここが落ちる。
#[tokio::test]
async fn a_tampered_assertion_is_rejected_by_the_registered_certificate() {
    let Some(env) = support::setup("external saml tampered").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let (provider_id, provider_code, issuer) = register_saml_provider(&env, &admin_tok).await;
    let user_id = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let name_id = format!("external-{}", unique());
    link_identity(&env.pool, &user_id, &provider_id, &issuer, &name_id).await;

    let started = start_login(&env, &provider_code).await;
    let response = signed_response(&env, &issuer, &provider_code, &started.request_id, &name_id);
    let xml = String::from_utf8(STANDARD.decode(&response).expect("base64")).expect("utf-8");
    let tampered = xml.replace(&name_id, &format!("other-{name_id}"));
    assert_ne!(tampered, xml, "the rewrite did not apply");

    let body = post_acs(&env, &STANDARD.encode(tampered), &started.relay_state).await;
    assert_eq!(body["result"], "external_failure", "{body}");
}

/// 連携されていない `NameID` はログインにならない。SAML のアサーションは「メールを検証した」と
/// 主張できないため、`allow_auto_link` があってもメール一致では入れない（ADR-0023）。
#[tokio::test]
async fn an_unlinked_name_id_does_not_sign_anyone_in() {
    let Some(env) = support::setup("external saml unlinked").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let (_provider_id, provider_code, issuer) = register_saml_provider(&env, &admin_tok).await;

    let started = start_login(&env, &provider_code).await;
    let response = signed_response(
        &env,
        &issuer,
        &provider_code,
        &started.request_id,
        &format!("stranger-{}", unique()),
    );
    let body = post_acs(&env, &response, &started.relay_state).await;
    assert_eq!(body["result"], "not_linked", "{body}");
}

/// IdP メタデータの取り込みは entityID・SSO URL・**すべての**署名証明書を返し、何も保存しない。
/// 権限の無い利用者は使えない（登録に至る前段でも管理操作である）。
#[tokio::test]
async fn importing_idp_metadata_extracts_the_registration_values_without_saving() {
    let Some(env) = support::setup("external saml metadata import").await else {
        return;
    };
    let uri = format!(
        "/{}/admin/external-idps/import-metadata",
        env.root_tenant_id
    );
    let metadata = r#"<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                     entityID="https://idp.corp.example.com/metadata">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIBCURRENT==</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIBNEXT==</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                            Location="https://idp.corp.example.com/sso"/>
  </md:IDPSSODescriptor>
  <md:Organization>
    <md:OrganizationDisplayName xml:lang="en">Corp IdP</md:OrganizationDisplayName>
  </md:Organization>
</md:EntityDescriptor>"#;

    // 権限の無い利用者 → 403。
    let plain_user_id = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let plain_token = admin_token(&env.app, &env.pool, &env.root_tenant_id, &plain_user_id).await;
    let res = send(
        &env.app,
        post(&plain_token, &uri, json!({ "metadata_xml": metadata })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "no perms -> 403");

    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let res = send(
        &env.app,
        post(&admin_tok, &uri, json!({ "metadata_xml": metadata })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let parsed = body_json(res).await;
    assert_eq!(parsed["entity_id"], "https://idp.corp.example.com/metadata");
    assert_eq!(parsed["sso_url"], "https://idp.corp.example.com/sso");
    // 証明書更新期間の 2 枚目を落とすと、切り替わった瞬間にログインが止まる。
    assert_eq!(
        parsed["certificates"],
        json!(["MIIBCURRENT==", "MIIBNEXT=="])
    );
    assert_eq!(parsed["display_name"], "Corp IdP");

    // 取り込みは登録ではない。プロバイダは 1 件も増えていない。
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM external_identity_providers WHERE tenant_id = ? AND issuer = ?",
    )
    .bind(&env.root_tenant_id)
    .bind("https://idp.corp.example.com/metadata")
    .fetch_one(&env.pool)
    .await
    .expect("count providers");
    assert_eq!(count, 0, "importing metadata must not register a provider");

    // SP のメタデータを貼った取り違えは 400 で弾く（IDPSSODescriptor が無い）。
    let sp_metadata = r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="urn:sp">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.test/acs"/>
  </SPSSODescriptor>
</EntityDescriptor>"#;
    let res = send(
        &env.app,
        post(&admin_tok, &uri, json!({ "metadata_xml": sp_metadata })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "SP metadata -> 400");
}
