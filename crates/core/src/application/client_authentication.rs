//! トークン系エンドポイント（`/token`・`/introspect`・`/revoke`）に共通するクライアント認証の判定。
//!
//! 3 つのエンドポイントは RFC 6749 §2.3.1 の同じクライアント認証を使う（RFC 7009 §2.1・
//! RFC 7662 §2.1 がそれぞれ「トークンエンドポイントと同じ方式」と定める）。判定を 1 か所に
//! 集めることで、方式を増やしたとき（G3 の `client_secret_post`）に取りこぼす経路が出ないようにする。
//!
//! ここが担うのは**どの secret を照合すべきか**の選択までで、ハッシュ照合と監査記録は
//! 各ユースケース（`token` / `introspection` / `revocation`）が行う。照合には
//! `PasswordHasher`（Argon2）が要り、失敗時に記録する監査イベント・エラー形も経路ごとに違うため。

use crate::domain::client::Client;
use crate::domain::values::{ClientType, TokenEndpointAuthMethod};

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
        }
    }
}

impl PresentedClientCredentials {
    /// RFC 6749 §2.3.1: クライアントは 1 リクエストで複数の認証方式を使ってはならない。
    ///
    /// 両方を受け入れて片方だけ照合すると、「Basic には誤った secret、body には正しい secret」の
    /// ような組み合わせで、どちらが検証されたのかリクエストからは決められなくなる。
    pub fn ensure_single_method(&self) -> Result<(), ClientAuthFailure> {
        let post_presented = self
            .body_client_secret
            .as_deref()
            .is_some_and(|s| !s.is_empty());
        if self.basic.is_some() && post_presented {
            return Err(ClientAuthFailure::MultipleAuthMethods);
        }
        Ok(())
    }

    /// `client_id` を Basic ヘッダ優先で解決する。body と食い違う場合はエラー。
    pub fn resolve_client_id(&self) -> Result<&str, ClientAuthFailure> {
        let body_id = self.body_client_id.as_deref().filter(|s| !s.is_empty());
        match (&self.basic, body_id) {
            (Some((basic_id, _)), Some(body_id)) if basic_id != body_id => {
                Err(ClientAuthFailure::ClientIdMismatch)
            }
            (Some((basic_id, _)), _) => Ok(basic_id.as_str()),
            (None, Some(body_id)) => Ok(body_id),
            (None, None) => Err(ClientAuthFailure::MissingClientId),
        }
    }

    /// クライアントの登録方式に対応する提示 secret を返す。
    ///
    /// `Ok(None)` は「認証不要」（public client ＝ `token_endpoint_auth_method` が `none`）。
    /// `Ok(Some(secret))` は呼び出し側が `client.client_secret_hash` と照合する。
    pub fn secret_for<'a>(&'a self, client: &Client) -> Result<Option<&'a str>, ClientAuthFailure> {
        if client.client_type == ClientType::Public {
            return Ok(None);
        }
        if client.client_secret_hash.is_none() {
            return Err(ClientAuthFailure::ClientHasNoSecret);
        }
        let post = self.body_client_secret.as_deref().filter(|s| !s.is_empty());
        match client.token_endpoint_auth_method {
            TokenEndpointAuthMethod::ClientSecretBasic => match (&self.basic, post) {
                (Some((_, secret)), _) => Ok(Some(secret.as_str())),
                (None, Some(_)) => Err(ClientAuthFailure::UnsupportedAuthMethod),
                (None, None) => Err(ClientAuthFailure::MissingCredentials),
            },
            TokenEndpointAuthMethod::ClientSecretPost => match (post, &self.basic) {
                (Some(secret), _) => Ok(Some(secret)),
                (None, Some(_)) => Err(ClientAuthFailure::UnsupportedAuthMethod),
                (None, None) => Err(ClientAuthFailure::MissingCredentials),
            },
            // confidential なのに `none`（＝認証なし）が登録されている状態。登録経路では作れないが、
            // DB を直接編集されたときに素通ししないよう fail-closed で拒否する。
            TokenEndpointAuthMethod::None => Err(ClientAuthFailure::UnsupportedAuthMethod),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
            post_logout_redirect_uris: vec![],
            frontchannel_logout_uri: None,
            backchannel_logout_uri: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
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

    #[test]
    fn presenting_both_methods_is_rejected() {
        let both = PresentedClientCredentials {
            basic: Some(("cid".into(), "a".into())),
            body_client_id: Some("cid".into()),
            body_client_secret: Some("b".into()),
        };
        assert_eq!(
            both.ensure_single_method(),
            Err(ClientAuthFailure::MultipleAuthMethods)
        );
        // body に client_id だけを載せるのは認証方式ではないため許される（public client の経路）。
        assert!(PresentedClientCredentials {
            basic: Some(("cid".into(), "a".into())),
            body_client_id: Some("cid".into()),
            body_client_secret: None,
        }
        .ensure_single_method()
        .is_ok());
    }

    #[test]
    fn client_id_comes_from_basic_and_must_match_the_body() {
        assert_eq!(basic().resolve_client_id(), Ok("cid"));
        assert_eq!(post().resolve_client_id(), Ok("cid"));
        assert_eq!(
            PresentedClientCredentials::default().resolve_client_id(),
            Err(ClientAuthFailure::MissingClientId)
        );
        assert_eq!(
            PresentedClientCredentials {
                basic: Some(("cid".into(), "s".into())),
                body_client_id: Some("other".into()),
                body_client_secret: None,
            }
            .resolve_client_id(),
            Err(ClientAuthFailure::ClientIdMismatch)
        );
    }

    #[test]
    fn the_registered_method_decides_which_secret_is_checked() {
        let basic_client = client(
            ClientType::Confidential,
            TokenEndpointAuthMethod::ClientSecretBasic,
        );
        let post_client = client(
            ClientType::Confidential,
            TokenEndpointAuthMethod::ClientSecretPost,
        );

        assert_eq!(basic().secret_for(&basic_client), Ok(Some("s3cret")));
        assert_eq!(post().secret_for(&post_client), Ok(Some("s3cret")));

        // 方式違い（登録は Basic なのに body で送る／その逆）は素通しさせない。
        assert_eq!(
            post().secret_for(&basic_client),
            Err(ClientAuthFailure::UnsupportedAuthMethod)
        );
        assert_eq!(
            basic().secret_for(&post_client),
            Err(ClientAuthFailure::UnsupportedAuthMethod)
        );
        assert_eq!(
            PresentedClientCredentials::default().secret_for(&post_client),
            Err(ClientAuthFailure::MissingCredentials)
        );
    }

    #[test]
    fn public_clients_need_no_secret() {
        let public = client(ClientType::Public, TokenEndpointAuthMethod::None);
        assert_eq!(
            PresentedClientCredentials::default().secret_for(&public),
            Ok(None)
        );
        // public に secret を送りつけても認証扱いにはしない（従来どおり素通し）。
        assert_eq!(post().secret_for(&public), Ok(None));
    }
}
