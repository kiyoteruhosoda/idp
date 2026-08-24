//! トークン系エンドポイント（`/token`・`/introspect`・`/revoke`）に共通するクライアント認証の判定。
//!
//! 3 つのエンドポイントは RFC 6749 §2.3.1 の同じクライアント認証を使う（RFC 7009 §2.1・
//! RFC 7662 §2.1 がそれぞれ「トークンエンドポイントと同じ方式」と定める）。判定を 1 か所に
//! 集めることで、方式を増やしたとき（G3 の `client_secret_post`）に取りこぼす経路が出ないようにする。
//!
//! ここが担うのは**どの資格情報を照合すべきかの選択**と、その**照合そのもの**である
//! （[`ClientAuthenticator`]）。監査記録とエラー応答の形だけが経路ごとに違うので、それは
//! 各ユースケース（`token` / `introspection` / `revocation`）に残す。
//!
//! 照合まで 1 か所へ寄せているのは、方式が増えるたびに 3 経路へ書き足すと必ずどこかを取りこぼす
//! ためである（`private_key_jwt` の追加で 4 方式になった。ADR-0030）。

use crate::domain::client::Client;
use crate::domain::client_assertion::{
    unverified_subject, verify_client_assertion, ClientAssertionFailure,
};
use crate::domain::clock::Clock;
use crate::domain::password::PasswordHasher;
use crate::domain::repositories::ClientAssertionReplayRepository;
use crate::domain::tenant_context::TenantContext;
use crate::domain::values::{ClientType, TokenEndpointAuthMethod};
use std::sync::Arc;

/// リクエストが提示したクライアント資格情報。
///
/// `Authorization: Basic` と body（`client_secret_post`）の両方を保持し、どちらを採るかは
/// クライアントの登録方式（`token_endpoint_auth_method`）が決める。
#[derive(Debug, Clone, Default)]
pub struct PresentedClientCredentials {
    /// `Authorization: Basic` から取り出した `(client_id, client_secret)`。
    pub basic: Option<(String, String)>,
    /// body の `client_id`（public client では必須。confidential でも `client_secret_post` で使う）。
    pub body_client_id: Option<String>,
    /// body の `client_secret`（`client_secret_post`）。
    pub body_client_secret: Option<String>,
    /// body の `client_assertion`（`private_key_jwt`。RFC 7523 §2.2）。
    pub client_assertion: Option<String>,
    /// body の `client_assertion_type`。`jwt-bearer` 以外は受け付けない。
    pub client_assertion_type: Option<String>,
}

/// クライアント認証の失敗理由。文字列は監査ログの `reason` にそのまま載せる。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuthFailure {
    /// 1 リクエストで複数の認証方式を提示した（RFC 6749 §2.3.1 で禁止）。
    MultipleAuthMethods,
    /// `Authorization: Basic` の `client_id` と body の `client_id` が食い違う。
    ClientIdMismatch,
    /// client_id を特定できない（Basic も body も無い）。
    MissingClientId,
    /// 登録された方式の資格情報が提示されていない。
    MissingCredentials,
    /// 登録された方式と違う方式で提示した（例: `client_secret_post` のクライアントが Basic を送る）。
    UnsupportedAuthMethod,
    /// confidential として登録されているのに secret が保存されていない（データ不整合）。
    ClientHasNoSecret,
    /// `private_key_jwt` として登録されているのに検証鍵が保存されていない（データ不整合）。
    ClientHasNoJwks,
    /// 提示された secret が登録ハッシュと一致しない。
    InvalidClientSecret,
    /// client assertion が検証を通らなかった（詳細は [`ClientAssertionFailure`]）。
    InvalidAssertion(ClientAssertionFailure),
    /// 有効期間内に同じ `jti` の assertion が再提示された（ADR-0030 決定 5）。
    ReplayedAssertion,
}

impl ClientAuthFailure {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MultipleAuthMethods => "multiple_auth_methods",
            Self::ClientIdMismatch => "client_id_mismatch",
            Self::MissingClientId => "missing_client_id",
            Self::MissingCredentials => "missing_credentials",
            Self::UnsupportedAuthMethod => "unsupported_auth_method",
            Self::ClientHasNoSecret => "client_has_no_secret",
            Self::ClientHasNoJwks => "client_has_no_jwks",
            Self::InvalidClientSecret => "invalid_client_secret",
            Self::InvalidAssertion(failure) => failure.as_str(),
            Self::ReplayedAssertion => "replayed_client_assertion",
        }
    }
}

impl PresentedClientCredentials {
    /// RFC 6749 §2.3.1: クライアントは 1 リクエストで複数の認証方式を使ってはならない。
    ///
    /// 両方を受け入れて片方だけ照合すると、「Basic には誤った secret、body には正しい secret」の
    /// ような組み合わせで、どちらが検証されたのかリクエストからは決められなくなる。
    pub fn ensure_single_method(&self) -> Result<(), ClientAuthFailure> {
        let presented = [
            self.basic.is_some(),
            self.body_client_secret
                .as_deref()
                .is_some_and(|s| !s.is_empty()),
            self.client_assertion
                .as_deref()
                .is_some_and(|s| !s.is_empty()),
        ]
        .into_iter()
        .filter(|p| *p)
        .count();
        if presented > 1 {
            return Err(ClientAuthFailure::MultipleAuthMethods);
        }
        Ok(())
    }

    /// 提示された client assertion（空文字は未提示として落とす）。
    pub fn assertion(&self) -> Option<&str> {
        self.client_assertion.as_deref().filter(|s| !s.is_empty())
    }

    /// `client_id` を Basic ヘッダ優先で解決する。body と食い違う場合はエラー。
    ///
    /// どちらにも無い場合は client assertion の（**未検証の**）`sub` を使う。RFC 7521 §4.2 は
    /// assertion を使うときの `client_id` の省略を認めており、この値だけが手がかりになる。
    /// 未検証の値をここで使ってよいのは、決めているのが「どのクライアントの登録鍵で検証するか」
    /// だけだからである —— 偽っても、その鍵では署名が検証できずに落ちる。
    pub fn resolve_client_id(&self) -> Result<String, ClientAuthFailure> {
        let body_id = self.body_client_id.as_deref().filter(|s| !s.is_empty());
        match (&self.basic, body_id) {
            (Some((basic_id, _)), Some(body_id)) if basic_id != body_id => {
                Err(ClientAuthFailure::ClientIdMismatch)
            }
            (Some((basic_id, _)), _) => Ok(basic_id.clone()),
            (None, Some(body_id)) => Ok(body_id.to_string()),
            (None, None) => self
                .assertion()
                .and_then(unverified_subject)
                .ok_or(ClientAuthFailure::MissingClientId),
        }
    }

    /// クライアントの登録方式に対応する資格情報を選ぶ。
    ///
    /// 選ぶのは登録値（`token_endpoint_auth_method`）であって、リクエストが何を送ってきたかでは
    /// ない。「登録は `private_key_jwt` だが secret でも通る」といった併存を認めると、強い方式を
    /// 登録した意味が弱い方式の残存で消える（ADR-0030 決定 2）。
    pub fn select<'a>(
        &'a self,
        client: &Client,
    ) -> Result<SelectedCredential<'a>, ClientAuthFailure> {
        if client.client_type == ClientType::Public {
            return Ok(SelectedCredential::NotRequired);
        }
        let post = self.body_client_secret.as_deref().filter(|s| !s.is_empty());
        match client.token_endpoint_auth_method {
            TokenEndpointAuthMethod::ClientSecretBasic => {
                Self::require_secret(client)?;
                match (&self.basic, post, self.assertion()) {
                    (Some((_, secret)), _, _) => Ok(SelectedCredential::Secret(secret.as_str())),
                    (None, None, None) => Err(ClientAuthFailure::MissingCredentials),
                    (None, _, _) => Err(ClientAuthFailure::UnsupportedAuthMethod),
                }
            }
            TokenEndpointAuthMethod::ClientSecretPost => {
                Self::require_secret(client)?;
                match (post, &self.basic, self.assertion()) {
                    (Some(secret), _, _) => Ok(SelectedCredential::Secret(secret)),
                    (None, None, None) => Err(ClientAuthFailure::MissingCredentials),
                    (None, _, _) => Err(ClientAuthFailure::UnsupportedAuthMethod),
                }
            }
            TokenEndpointAuthMethod::PrivateKeyJwt => {
                // 検証鍵が保存されていないクライアントは、どんな assertion でも通してはならない。
                if client.jwks.is_none() {
                    return Err(ClientAuthFailure::ClientHasNoJwks);
                }
                match (self.assertion(), &self.basic, post) {
                    (Some(assertion), _, _) => Ok(SelectedCredential::Assertion {
                        assertion,
                        assertion_type: self.client_assertion_type.as_deref(),
                    }),
                    (None, None, None) => Err(ClientAuthFailure::MissingCredentials),
                    (None, _, _) => Err(ClientAuthFailure::UnsupportedAuthMethod),
                }
            }
            // confidential なのに `none`（＝認証なし）が登録されている状態。登録経路では作れないが、
            // DB を直接編集されたときに素通ししないよう fail-closed で拒否する。
            TokenEndpointAuthMethod::None => Err(ClientAuthFailure::UnsupportedAuthMethod),
        }
    }

    fn require_secret(client: &Client) -> Result<(), ClientAuthFailure> {
        client
            .client_secret_hash
            .as_deref()
            .map(|_| ())
            .ok_or(ClientAuthFailure::ClientHasNoSecret)
    }
}

/// 登録方式から選ばれた、照合すべき資格情報。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectedCredential<'a> {
    /// 認証不要（public client ＝ `token_endpoint_auth_method` が `none`）。
    NotRequired,
    /// 共有秘密。`client.client_secret_hash` と照合する。
    Secret(&'a str),
    /// 署名済み assertion。`client.jwks` で検証する（ADR-0030）。
    Assertion {
        assertion: &'a str,
        assertion_type: Option<&'a str>,
    },
}

/// クライアント認証の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuthOutcome {
    /// 資格情報の照合に成功した。
    Authenticated,
    /// public client のため認証は不要だった。
    NotRequired,
}

/// クライアント認証そのもの（[`SelectedCredential`] の照合）。
///
/// トークン系 3 経路が共有する。各ユースケースが持つのは、失敗時に記録する監査イベントと
/// クライアントへ返すエラーの形だけになる。
pub struct ClientAuthenticator {
    hasher: Arc<dyn PasswordHasher>,
    assertions: Arc<dyn ClientAssertionReplayRepository>,
    clock: Arc<dyn Clock>,
    /// 基底 issuer（`https://<host>`）。assertion の `aud` 候補はここからテナントごとに合成する。
    base_issuer: String,
}

impl ClientAuthenticator {
    pub fn new(
        hasher: Arc<dyn PasswordHasher>,
        assertions: Arc<dyn ClientAssertionReplayRepository>,
        clock: Arc<dyn Clock>,
        base_issuer: String,
    ) -> Self {
        Self {
            hasher,
            assertions,
            clock,
            base_issuer,
        }
    }

    /// 提示された資格情報を照合する。
    ///
    /// `Err(Ok(failure))` は認証の失敗（クライアントへは `invalid_client`）、
    /// `Err(Err(message))` は内部エラー（500 相当）。呼び出し側は前者だけを監査へ記録する。
    pub async fn authenticate(
        &self,
        tenant: TenantContext,
        client: &Client,
        credentials: &PresentedClientCredentials,
    ) -> Result<ClientAuthOutcome, ClientAuthError> {
        match credentials
            .select(client)
            .map_err(ClientAuthError::Failed)?
        {
            SelectedCredential::NotRequired => Ok(ClientAuthOutcome::NotRequired),
            SelectedCredential::Secret(secret) => {
                let hash = client
                    .client_secret_hash
                    .as_deref()
                    .ok_or(ClientAuthError::Failed(
                        ClientAuthFailure::ClientHasNoSecret,
                    ))?;
                let ok = self
                    .hasher
                    .verify(secret, hash)
                    .map_err(|e| ClientAuthError::Internal(e.to_string()))?;
                if ok {
                    Ok(ClientAuthOutcome::Authenticated)
                } else {
                    Err(ClientAuthError::Failed(
                        ClientAuthFailure::InvalidClientSecret,
                    ))
                }
            }
            SelectedCredential::Assertion {
                assertion,
                assertion_type,
            } => {
                self.authenticate_assertion(tenant, client, assertion, assertion_type)
                    .await
            }
        }
    }

    async fn authenticate_assertion(
        &self,
        tenant: TenantContext,
        client: &Client,
        assertion: &str,
        assertion_type: Option<&str>,
    ) -> Result<ClientAuthOutcome, ClientAuthError> {
        let jwks = client
            .jwks
            .as_ref()
            .ok_or(ClientAuthError::Failed(ClientAuthFailure::ClientHasNoJwks))?;
        let verified = verify_client_assertion(
            assertion_type,
            assertion,
            &client.client_id,
            jwks,
            &self.accepted_audiences(tenant),
            self.clock.now(),
        )
        .map_err(|failure| ClientAuthError::Failed(ClientAuthFailure::InvalidAssertion(failure)))?;

        // 署名が通ってから `jti` を記録する。順序が逆だと、署名が通らない assertion の `jti` で
        // 表を膨らませられる（外部から書き込める表になってしまう）。
        let unused = self
            .assertions
            .record_if_unused(
                tenant.tenant_id(),
                &client.client_id,
                &verified.jti,
                verified.expires_at,
            )
            .await
            .map_err(|e| ClientAuthError::Internal(e.to_string()))?;
        if !unused {
            return Err(ClientAuthError::Failed(
                ClientAuthFailure::ReplayedAssertion,
            ));
        }
        Ok(ClientAuthOutcome::Authenticated)
    }

    /// assertion の `aud` として受理する値（ADR-0030 決定 6）。
    ///
    /// テナント issuer とトークンエンドポイント URL の両方を認める。どちらを入れるかは
    /// クライアント実装によって分かれており、どちらもテナントを含むので、他テナント宛の
    /// assertion がここを通ることはない。
    fn accepted_audiences(&self, tenant: TenantContext) -> Vec<String> {
        let issuer = crate::domain::issuer::tenant_issuer(&self.base_issuer, tenant.tenant_id());
        vec![format!("{issuer}/token"), issuer]
    }
}

/// [`ClientAuthenticator::authenticate`] の失敗。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientAuthError {
    /// 認証の失敗。監査ログの `reason` は `failure.as_str()`。
    Failed(ClientAuthFailure),
    /// 内部エラー（ハッシュ照合・DB）。クライアントへは 500 相当を返す。
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::client_jwks::{parse_registration_jwks, ClientJwks};
    use crate::domain::tenant::TenantId;
    use crate::domain::values::ClientStatus;
    use chrono::Utc;
    use uuid::Uuid;

    fn client(client_type: ClientType, method: TokenEndpointAuthMethod) -> Client {
        Client {
            id: Uuid::nil(),
            tenant_id: TenantId::from(Uuid::nil()),
            client_id: "cid".into(),
            client_secret_hash: (client_type == ClientType::Confidential)
                .then(|| "hash".to_string()),
            client_type,
            client_status: ClientStatus::Active,
            app_name: "app".into(),
            redirect_uris: vec![],
            grant_types: vec![],
            response_types: vec![],
            scopes: vec![],
            token_endpoint_auth_method: method,
            jwks: None,
            post_logout_redirect_uris: vec![],
            frontchannel_logout_uri: None,
            backchannel_logout_uri: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn jwks() -> ClientJwks {
        const N: &str = "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl\
                         UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre\
                         cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_\
                         7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBI\
                         Y2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU\
                         7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw";
        parse_registration_jwks(&format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"k1","n":"{N}","e":"AQAB"}}]}}"#
        ))
        .unwrap()
    }

    fn private_key_jwt_client() -> Client {
        let mut c = client(
            ClientType::Confidential,
            TokenEndpointAuthMethod::PrivateKeyJwt,
        );
        // `private_key_jwt` のクライアントは secret を持たない（登録時に発行しない）。
        c.client_secret_hash = None;
        c.jwks = Some(jwks());
        c
    }

    fn basic() -> PresentedClientCredentials {
        PresentedClientCredentials {
            basic: Some(("cid".into(), "s3cret".into())),
            ..Default::default()
        }
    }

    fn post() -> PresentedClientCredentials {
        PresentedClientCredentials {
            body_client_id: Some("cid".into()),
            body_client_secret: Some("s3cret".into()),
            ..Default::default()
        }
    }

    fn assertion(token: &str) -> PresentedClientCredentials {
        PresentedClientCredentials {
            client_assertion: Some(token.into()),
            client_assertion_type: Some(
                crate::domain::client_assertion::JWT_BEARER_ASSERTION_TYPE.into(),
            ),
            ..Default::default()
        }
    }

    #[test]
    fn presenting_more_than_one_method_is_rejected() {
        let both = PresentedClientCredentials {
            basic: Some(("cid".into(), "a".into())),
            body_client_id: Some("cid".into()),
            body_client_secret: Some("b".into()),
            ..Default::default()
        };
        assert_eq!(
            both.ensure_single_method(),
            Err(ClientAuthFailure::MultipleAuthMethods)
        );
        // secret と assertion の併用も同じく禁止（どちらで認証されたのか決まらない）。
        let secret_and_assertion = PresentedClientCredentials {
            body_client_id: Some("cid".into()),
            body_client_secret: Some("b".into()),
            client_assertion: Some("a.b.c".into()),
            ..Default::default()
        };
        assert_eq!(
            secret_and_assertion.ensure_single_method(),
            Err(ClientAuthFailure::MultipleAuthMethods)
        );
        // body に client_id だけを載せるのは認証方式ではないため許される（public client の経路）。
        assert!(PresentedClientCredentials {
            basic: Some(("cid".into(), "a".into())),
            body_client_id: Some("cid".into()),
            ..Default::default()
        }
        .ensure_single_method()
        .is_ok());
    }

    #[test]
    fn client_id_comes_from_basic_and_must_match_the_body() {
        assert_eq!(basic().resolve_client_id().as_deref(), Ok("cid"));
        assert_eq!(post().resolve_client_id().as_deref(), Ok("cid"));
        assert_eq!(
            PresentedClientCredentials::default().resolve_client_id(),
            Err(ClientAuthFailure::MissingClientId)
        );
        assert_eq!(
            PresentedClientCredentials {
                basic: Some(("cid".into(), "s".into())),
                body_client_id: Some("other".into()),
                ..Default::default()
            }
            .resolve_client_id(),
            Err(ClientAuthFailure::ClientIdMismatch)
        );
    }

    /// `client_id` を省いた assertion 単独のリクエストでも、対象クライアントは決まる
    /// （RFC 7521 §4.2）。値は未検証なので、選ばれた鍵で署名が通らなければ落ちる。
    #[test]
    fn client_id_falls_back_to_the_unverified_assertion_subject() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let payload = URL_SAFE_NO_PAD.encode(br#"{"iss":"cid","sub":"cid"}"#);
        let token = format!("header.{payload}.signature");
        assert_eq!(assertion(&token).resolve_client_id().as_deref(), Ok("cid"));
    }

    #[test]
    fn the_registered_method_decides_which_credential_is_checked() {
        let basic_client = client(
            ClientType::Confidential,
            TokenEndpointAuthMethod::ClientSecretBasic,
        );
        let post_client = client(
            ClientType::Confidential,
            TokenEndpointAuthMethod::ClientSecretPost,
        );

        assert_eq!(
            basic().select(&basic_client),
            Ok(SelectedCredential::Secret("s3cret"))
        );
        assert_eq!(
            post().select(&post_client),
            Ok(SelectedCredential::Secret("s3cret"))
        );

        // 方式違い（登録は Basic なのに body で送る／その逆）は素通しさせない。
        assert_eq!(
            post().select(&basic_client),
            Err(ClientAuthFailure::UnsupportedAuthMethod)
        );
        assert_eq!(
            basic().select(&post_client),
            Err(ClientAuthFailure::UnsupportedAuthMethod)
        );
        assert_eq!(
            PresentedClientCredentials::default().select(&post_client),
            Err(ClientAuthFailure::MissingCredentials)
        );
    }

    /// 登録が `private_key_jwt` なら、正しい secret を送られても通さない（ADR-0030 決定 2）。
    /// 強い方式を登録した意味が、弱い方式の残存で消えないようにする。
    #[test]
    fn a_private_key_jwt_client_cannot_fall_back_to_a_secret() {
        let client = private_key_jwt_client();
        assert_eq!(
            assertion("a.b.c").select(&client),
            Ok(SelectedCredential::Assertion {
                assertion: "a.b.c",
                assertion_type: Some(crate::domain::client_assertion::JWT_BEARER_ASSERTION_TYPE),
            })
        );
        assert_eq!(
            basic().select(&client),
            Err(ClientAuthFailure::UnsupportedAuthMethod)
        );
        assert_eq!(
            post().select(&client),
            Err(ClientAuthFailure::UnsupportedAuthMethod)
        );
        assert_eq!(
            PresentedClientCredentials::default().select(&client),
            Err(ClientAuthFailure::MissingCredentials)
        );
    }

    /// 逆に、secret 方式のクライアントへ assertion を送っても通らない。
    #[test]
    fn a_secret_client_cannot_authenticate_with_an_assertion() {
        let basic_client = client(
            ClientType::Confidential,
            TokenEndpointAuthMethod::ClientSecretBasic,
        );
        assert_eq!(
            assertion("a.b.c").select(&basic_client),
            Err(ClientAuthFailure::UnsupportedAuthMethod)
        );
    }

    /// 検証鍵が保存されていない `private_key_jwt` クライアントは、どんな assertion でも通さない
    /// （DB を直接編集された行が素通りしないよう fail-closed）。
    #[test]
    fn a_private_key_jwt_client_without_keys_is_rejected() {
        let mut client = private_key_jwt_client();
        client.jwks = None;
        assert_eq!(
            assertion("a.b.c").select(&client),
            Err(ClientAuthFailure::ClientHasNoJwks)
        );
    }

    #[test]
    fn public_clients_need_no_credentials() {
        let public = client(ClientType::Public, TokenEndpointAuthMethod::None);
        assert_eq!(
            PresentedClientCredentials::default().select(&public),
            Ok(SelectedCredential::NotRequired)
        );
        // public に secret を送りつけても認証扱いにはしない（従来どおり素通し）。
        assert_eq!(post().select(&public), Ok(SelectedCredential::NotRequired));
    }
}
