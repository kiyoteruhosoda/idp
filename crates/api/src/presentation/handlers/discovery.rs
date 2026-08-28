//! OIDC Discovery（`GET /.well-known/openid-configuration`）と
//! JWKS（`GET /.well-known/jwks.json`）（設計仕様 §4.5 / §4.6）。

use crate::domain::issuer::tenant_issuer;
use crate::domain::jwt;
use crate::domain::saml_metadata::{build_idp_metadata_xml, named_curve_uri, IdpSigningKey};
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::{json, Value};

/// Discovery ドキュメント。`issuer` は末尾スラッシュ無しで ID Token の `iss` と完全一致する。
///
/// `issuer` はテナント毎に `<基底 issuer>/<tenant_id>` を合成する（ADR-0009 §6）。要求テナントは
/// パス由来（`resolve_tenant` が注入）。全エンドポイントもこの issuer から導出する。
#[utoipa::path(
    get,
    path = "/{tenant_id}/.well-known/openid-configuration",
    tag = "oidc",
    responses((status = 200, description = "OIDC Discovery ドキュメント"))
)]
pub async fn openid_configuration(
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
) -> Json<Value> {
    let issuer = tenant_issuer(state.config.issuer(), tenant.id());
    // end_session_endpoint は web が受ける（ADR-0018 決定 2。api はブラウザ Cookie を読まないため、
    // RP-initiated logout の起点は SSO Cookie を自ドメインで扱える web 側になる）。
    let end_session_endpoint = format!(
        "{}/{}/logout",
        state.config.public_web_base_url(),
        tenant.id()
    );
    Json(discovery_document(&issuer, &end_session_endpoint))
}

/// JWKS（ACTIVE + RETIRED の公開鍵）。
#[utoipa::path(
    get,
    path = "/{tenant_id}/.well-known/jwks.json",
    tag = "oidc",
    responses((status = 200, description = "JWK Set"))
)]
pub async fn jwks(State(state): State<AppState>) -> Response {
    match state.keys.jwks().await {
        Ok(jwks) => Json(jwks).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "failed to build JWKS");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// SAML IdP メタデータ（`GET /{tenant_id}/saml/metadata`）。
///
/// 本 IdP を記述する `EntityDescriptor`（`IDPSSODescriptor`）を XML で返す。SP（クライアント）がこの IdP を
/// 信頼するために取り込む公開メタデータで、テナント issuer を entityID とし、SSO URL も issuer から導出する。
/// 署名用 `KeyDescriptor` には ACTIVE 署名鍵（RSA）を `RSAKeyValue` で含める。広告する
/// SingleSignOnService は [`super::saml_sso`]（`/{tenant_id}/saml/sso`）が実装する。
#[utoipa::path(
    get,
    path = "/{tenant_id}/saml/metadata",
    tag = "saml",
    responses((status = 200, description = "SAML IdP メタデータ（application/xml。SP 取り込み用にダウンロード）"))
)]
pub async fn saml_idp_metadata(
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
) -> Response {
    let issuer = tenant_issuer(state.config.issuer(), tenant.id());
    let sso_url = format!("{issuer}/saml/sso");
    // 鍵集合が引けないときは**メタデータを返さない**。200 で `KeyDescriptor` の無いメタデータを
    // 返すと、そのタイミングで取り込み直した SP は検証鍵を 1 本も持たない状態になり、再取り込み
    // まで全アサーションを弾く（この変更が無くそうとしている断絶そのもの）。
    let signing_keys = match published_idp_signing_keys(&state).await {
        Ok(keys) => keys,
        Err(e) => {
            tracing::error!(error = %e, "failed to build SAML IdP metadata signing keys");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let xml = build_idp_metadata_xml(&issuer, &sso_url, &signing_keys);
    (
        [
            (header::CONTENT_TYPE, "application/xml; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"idp-metadata.xml\"",
            ),
        ],
        xml,
    )
        .into_response()
}

/// 公開中の署名鍵を SAML の `KeyDescriptor` 用へ変換する（ADR-0039）。
///
/// **JWKS と同じ集合を出す。** `jwks()` は公開中の鍵（署名中・まだ署名しない後継・有効期間内の
/// 退役）をすべて返すので、それをそのまま並べれば OIDC 側と SAML 側で見えるものが揃う。1 本しか
/// 出さないと、署名の切り替わりで SP の検証が落ちる。
///
/// **署名中の鍵を先頭に置く。** `jwks()` の並びは公開順（新しい鍵が先）なので、そのままだと
/// **まだ署名していない後継鍵**が先頭に来る。先頭の `KeyDescriptor` だけを読む SP の実装がある。
async fn published_idp_signing_keys(state: &AppState) -> anyhow::Result<Vec<IdpSigningKey>> {
    let jwks = state.keys.jwks().await?;
    let published = jwks.keys.len();
    // 署名中の鍵が引けないときは並べ替えないだけで、公開自体は続ける（検証側の鍵が
    // 消えるほうが困る）。`kid` しか要らないので秘密鍵は復号しない。
    let signing_kid = state.keys.signing_kid().await.ok().flatten();
    let keys = signing_key_first(jwks.keys, signing_kid.as_deref());
    let converted: Vec<IdpSigningKey> = keys.iter().filter_map(jwk_to_idp_signing_key).collect();
    // 1 本も変換できなかったときも**メタデータを返さない**。解釈できない鍵は 1 本ずつ落とすが、
    // 全滅したまま 200 を返すと `KeyDescriptor` の無いメタデータが出て行き、`jwks()` が失敗した
    // ときと同じ断絶（取り込み直した SP が検証鍵を 1 本も持たない）になる。
    if published > 0 && converted.is_empty() {
        anyhow::bail!(
            "none of the {published} published keys could be rendered as a KeyDescriptor"
        );
    }
    Ok(converted)
}

/// 署名中の鍵を先頭へ寄せる。**先頭の `KeyDescriptor` だけを読む SP の実装がある**ため、
/// 公開順（新しい鍵が先）のままだと、まだ署名していない後継鍵を掴ませることになる。
///
/// `signing_kid` が無い・見つからないときは並べ替えない（公開自体は続ける。検証側の鍵が
/// 消えるほうが困る）。
fn signing_key_first(mut keys: Vec<jwt::Jwk>, signing_kid: Option<&str>) -> Vec<jwt::Jwk> {
    if let Some(kid) = signing_kid {
        if let Some(at) = keys.iter().position(|k| k.kid == kid) {
            // 入れ替え（`swap`）ではなく前へ動かす。`swap` だと先頭に居た鍵が `at` へ飛び、
            // 残りの公開順（新しい鍵が先）が崩れる。
            let signing = keys.remove(at);
            keys.insert(0, signing);
        }
    }
    keys
}

/// 1 本の JWK を SAML `KeyValue` 用の表現へ変換する。RSA は `RSAKeyValue`（modulus/exponent）、
/// EC は `ECKeyValue`（NamedCurve URI と非圧縮点）。解釈できない鍵は `None`（その鍵だけ落とす）。
fn jwk_to_idp_signing_key(jwk: &jwt::Jwk) -> Option<IdpSigningKey> {
    match jwk.kty.as_str() {
        "RSA" => Some(IdpSigningKey::Rsa {
            modulus_b64: base64url_to_base64(jwk.n.as_deref()?)?,
            exponent_b64: base64url_to_base64(jwk.e.as_deref()?)?,
        }),
        "EC" => {
            let named_curve_uri = named_curve_uri(jwk.crv.as_deref()?)?.to_string();
            // XMLDSIG の ECKeyValue は非圧縮点（0x04 || X || Y）を base64 で持つ。
            let mut point = vec![0x04u8];
            point.extend_from_slice(
                &URL_SAFE_NO_PAD
                    .decode(jwk.x.as_deref()?.trim_end_matches('='))
                    .ok()?,
            );
            point.extend_from_slice(
                &URL_SAFE_NO_PAD
                    .decode(jwk.y.as_deref()?.trim_end_matches('='))
                    .ok()?,
            );
            Some(IdpSigningKey::Ec {
                named_curve_uri,
                public_key_b64: STANDARD.encode(point),
            })
        }
        _ => None,
    }
}

fn base64url_to_base64(value: &str) -> Option<String> {
    let bytes = URL_SAFE_NO_PAD.decode(value.trim_end_matches('=')).ok()?;
    Some(STANDARD.encode(bytes))
}

fn discovery_document(issuer: &str, end_session_endpoint: &str) -> Value {
    json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "userinfo_endpoint": format!("{issuer}/userinfo"),
        "end_session_endpoint": end_session_endpoint,
        "revocation_endpoint": format!("{issuer}/revoke"),
        "introspection_endpoint": format!("{issuer}/introspect"),
        "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        // クライアント認証（RFC 6749 §2.3.1）。`client_secret_post` は多くの RP ライブラリが
        // 既定にするため受け入れる（G3）。`private_key_jwt`（RFC 7523）は共有秘密を持たないシステム向け
        // （ADR-0030）。どれを使うかはクライアントの登録値が決める（併存は認めない）。
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt", "none"],
        // `private_key_jwt` の assertion に使える署名アルゴリズム。広告しないと、RP・クライアント
        // ライブラリが対応アルゴリズムを推測して食い違う。
        "token_endpoint_auth_signing_alg_values_supported": ["RS256", "ES256"],
        // `/revoke`・`/introspect` も同じ方式（RFC 7009 §2.1・RFC 7662 §2.1）。
        "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt", "none"],
        "revocation_endpoint_auth_signing_alg_values_supported": ["RS256", "ES256"],
        "introspection_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt"],
        "introspection_endpoint_auth_signing_alg_values_supported": ["RS256", "ES256"],
        "code_challenge_methods_supported": ["S256"],
        // 応答の返し方は `query` のみ（`form_post` は未実装。G12）。広告しないと、RP の
        // メタデータ検証が厳しい実装（OIDC 認定テストを含む）が既定を推測して食い違う。
        // `form_post` は認可コードを URL ではなくフォーム本文で返す（G12）。
        "response_modes_supported": ["query", "form_post"],
        // `prompt`（OIDC Core §3.1.2.1）。`select_account` は「現在のアカウントで黙って続けない」
        // ＝ SSO 復元を止めてログイン画面へ戻す形で扱う（本 IdP はブラウザごとに SSO セッションを
        // 1 つしか持たないため、複数アカウントの一覧は出せない。G12）。
        "prompt_values_supported": ["none", "login", "consent", "select_account"],
        // `request` / `request_uri`（署名付き要求オブジェクト）と `claims` は未対応。
        // 既定は false だが、明示しておく方が RP 側の実装判断が早い。
        "request_parameter_supported": false,
        "request_uri_parameter_supported": false,
        "claims_parameter_supported": false,
        // `acr_values` は受け付けるが**保証しない**（認証ポリシーの条件として参照するだけ。AP3）。
        // 保証できる値が無いので空配列を出す（キー自体を出さないより意図が明確）。
        "acr_values_supported": [],
        // ログイン画面が実際に描画できる言語（web の i18n リソースと一致させる）。
        "ui_locales_supported": ["ja", "en"],
        "frontchannel_logout_supported": true,
        "backchannel_logout_supported": true,
        // logout_token に `sid` を載せるため、RP はセッション単位で失効できる（G5）。
        "backchannel_logout_session_supported": true,
        "frontchannel_logout_session_supported": false,
        "claims_supported": [
            "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "sid",
            "email", "email_verified", "preferred_username", "name"
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jwk(kid: &str) -> jwt::Jwk {
        jwt::Jwk {
            kty: "RSA".to_string(),
            use_: "sig".to_string(),
            kid: kid.to_string(),
            alg: "RS256".to_string(),
            n: None,
            e: None,
            crv: None,
            x: None,
            y: None,
        }
    }

    fn kids(keys: &[jwt::Jwk]) -> Vec<&str> {
        keys.iter().map(|k| k.kid.as_str()).collect()
    }

    /// 公開順は新しい鍵が先なので、ADR-0039 の「公開してから署名」では**まだ署名していない
    /// 後継鍵**が先頭に来る。先頭の `KeyDescriptor` だけを読む SP に、それを掴ませない。
    #[test]
    fn the_signing_key_comes_first_even_when_a_successor_is_newer() {
        let keys = vec![jwk("successor"), jwk("signing"), jwk("retired")];
        assert_eq!(
            kids(&signing_key_first(keys, Some("signing"))),
            ["signing", "successor", "retired"]
        );
    }

    /// 既に先頭なら並びは変わらない。
    #[test]
    fn an_already_leading_signing_key_is_left_alone() {
        let keys = vec![jwk("signing"), jwk("retired")];
        assert_eq!(
            kids(&signing_key_first(keys, Some("signing"))),
            ["signing", "retired"]
        );
    }

    /// 署名中の鍵が引けない・公開集合に無いときは、並べ替えないだけで公開は続ける
    /// （検証に使える鍵がメタデータから消えるほうが困る）。
    #[test]
    fn an_unknown_signing_kid_leaves_the_published_set_intact() {
        let keys = vec![jwk("a"), jwk("b")];
        assert_eq!(kids(&signing_key_first(keys.clone(), None)), ["a", "b"]);
        assert_eq!(kids(&signing_key_first(keys, Some("gone"))), ["a", "b"]);
    }

    #[test]
    fn discovery_endpoints_derive_from_issuer() {
        // end_session_endpoint だけは web の URL（ADR-0018 決定 2: RP-initiated logout の起点は web）。
        let doc = discovery_document(
            "https://api.idp.example.com",
            "https://idp.example.com/tenant-a/logout",
        );
        assert_eq!(doc["issuer"], "https://api.idp.example.com");
        assert_eq!(
            doc["authorization_endpoint"],
            "https://api.idp.example.com/authorize"
        );
        assert_eq!(
            doc["jwks_uri"],
            "https://api.idp.example.com/.well-known/jwks.json"
        );
        assert_eq!(doc["code_challenge_methods_supported"], json!(["S256"]));
        // G3: `client_secret_post`、ADR-0030: `private_key_jwt` を広告する
        // （`/revoke`・`/introspect` も同じ方式）。
        assert_eq!(
            doc["token_endpoint_auth_methods_supported"],
            json!([
                "client_secret_basic",
                "client_secret_post",
                "private_key_jwt",
                "none"
            ])
        );
        assert_eq!(
            doc["token_endpoint_auth_signing_alg_values_supported"],
            json!(["RS256", "ES256"])
        );
        assert_eq!(
            doc["revocation_endpoint_auth_methods_supported"],
            json!([
                "client_secret_basic",
                "client_secret_post",
                "private_key_jwt",
                "none"
            ])
        );
        assert_eq!(
            doc["introspection_endpoint_auth_methods_supported"],
            json!([
                "client_secret_basic",
                "client_secret_post",
                "private_key_jwt"
            ])
        );
        // G12: RP のメタデータ検証が見る項目を明示的に広告する。
        assert_eq!(
            doc["response_modes_supported"],
            json!(["query", "form_post"])
        );
        assert_eq!(doc["request_parameter_supported"], json!(false));
        assert_eq!(doc["claims_parameter_supported"], json!(false));
        assert_eq!(doc["ui_locales_supported"], json!(["ja", "en"]));
        assert_eq!(
            doc["prompt_values_supported"],
            json!(["none", "login", "consent", "select_account"])
        );
        assert_eq!(
            doc["end_session_endpoint"],
            "https://idp.example.com/tenant-a/logout"
        );
        assert_eq!(
            doc["revocation_endpoint"],
            "https://api.idp.example.com/revoke"
        );
        assert_eq!(
            doc["introspection_endpoint"],
            "https://api.idp.example.com/introspect"
        );
        assert_eq!(doc["frontchannel_logout_supported"], true);
        assert_eq!(doc["backchannel_logout_supported"], true);
        // `sid` を載せる以上、セッション単位のログアウト対応も広告する（G5）。
        assert_eq!(doc["backchannel_logout_session_supported"], true);
        assert!(doc["claims_supported"]
            .as_array()
            .expect("claims_supported")
            .iter()
            .any(|v| v == "sid"));
    }
}
