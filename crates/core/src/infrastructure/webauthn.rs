//! `webauthn-rs` ラッパー。
//!
//! `Webauthn` インスタンスの構築と、登録・認証の始終フロー（begin/finish）を一箇所に集約する。
//! RP ID は web の公開ベース URL（`PUBLIC_WEB_BASE_URL`。未設定時は issuer に追従）のホスト名部分、
//! RP オリジンはその URL のオリジン（scheme + host + port。パスは落とす）を使う。Passkey の
//! セレモニー（`navigator.credentials.*`）は web のページ上で実行されるため、RP ID・origin は
//! web のオリジンに対して成立させる（ADR-0019 決定 2。
//! issuer＝api のオリジンから導出すると、domain-split では api ホストが web ページの登録可能
//! サフィックスにならず、セレモニーがブラウザ側で常に失敗する）。
//!
//! エラー型は `webauthn_rs::WebauthnError` を文字列にしてアプリエラーとして返す。

use crate::domain::webauthn_port::WebAuthnPort;
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    AuthenticationResult, CreationChallengeResponse, DiscoverableAuthentication, DiscoverableKey,
    Passkey, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Webauthn, WebauthnBuilder,
};

#[derive(Clone)]
pub struct WebAuthnService {
    inner: Webauthn,
}

impl std::fmt::Debug for WebAuthnService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebAuthnService").finish()
    }
}

impl WebAuthnService {
    /// `web_base_url`（web の公開ベース URL）から RP ID（ホスト名）と RP オリジンを導出して
    /// `Webauthn` を構築する。
    ///
    /// # Panics
    /// `web_base_url` が有効な URL でない場合、またはホスト名がない場合は panic する
    /// （設定ミスなので起動時に即座に検出する）。
    pub fn new(web_base_url: &str) -> Self {
        let base = Url::parse(web_base_url)
            .unwrap_or_else(|e| panic!("PUBLIC_WEB_BASE_URL is not a valid URL: {e}"));
        let rp_id = base
            .host_str()
            .unwrap_or_else(|| panic!("PUBLIC_WEB_BASE_URL has no host: {web_base_url}"))
            .to_string();
        let origin = ceremony_origin(&base);
        let inner = WebauthnBuilder::new(&rp_id, &origin)
            .unwrap_or_else(|e| panic!("failed to build Webauthn: {e}"))
            .rp_name("OIDC IdP")
            .build()
            .unwrap_or_else(|e| panic!("failed to build Webauthn: {e}"));
        Self { inner }
    }
}

/// セレモニーの期待オリジン（scheme + host + port のみ）。ブラウザの `clientDataJSON.origin` は
/// 常にパス無しのオリジンのため、公開ベース URL がパスプレフィクス付き（例
/// `https://example.com/idp`。`validate_public_base_url` はパスを許容する）でも一致するよう、
/// パスを落としてから `WebauthnBuilder` へ渡す。
fn ceremony_origin(base: &Url) -> Url {
    Url::parse(&base.origin().ascii_serialization())
        .unwrap_or_else(|e| panic!("PUBLIC_WEB_BASE_URL has no valid origin: {e}"))
}

impl WebAuthnPort for WebAuthnService {
    // ─── 登録 ─────────────────────────────────────────────────────────────

    /// 登録開始: チャレンジと `PasskeyRegistration` 中間状態を返す。
    ///
    /// `exclude_credentials` には既存登録済みの `Passkey` スライスを渡すことで
    /// 同一デバイスの二重登録を防ぐ。
    fn begin_registration(
        &self,
        user_id: Uuid,
        user_name: &str,
        user_display_name: &str,
        exclude_credentials: &[Passkey],
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration), String> {
        self.inner
            .start_passkey_registration(
                user_id,
                user_name,
                user_display_name,
                if exclude_credentials.is_empty() {
                    None
                } else {
                    Some(
                        exclude_credentials
                            .iter()
                            .map(|p| p.cred_id().clone())
                            .collect(),
                    )
                },
            )
            .map_err(|e| e.to_string())
    }

    /// 登録完了: レスポンスを検証して `Passkey` を返す。
    fn finish_registration(
        &self,
        credential: &RegisterPublicKeyCredential,
        state: &PasskeyRegistration,
    ) -> Result<Passkey, String> {
        self.inner
            .finish_passkey_registration(credential, state)
            .map_err(|e| e.to_string())
    }

    // ─── 認証 ─────────────────────────────────────────────────────────────

    /// 認証開始（discoverable credentials）: チャレンジと `DiscoverableAuthentication` を返す。
    ///
    /// 認証器がユーザーハンドルを送ってくるため、ユーザーを事前に特定する必要がない。
    fn begin_authentication(
        &self,
    ) -> Result<(RequestChallengeResponse, DiscoverableAuthentication), String> {
        self.inner
            .start_discoverable_authentication()
            .map_err(|e| e.to_string())
    }

    /// 認証完了: クレデンシャルを検証して `AuthenticationResult` を返す。
    ///
    /// `creds` は `&[DiscoverableKey]`。認証レスポンスに含まれる credential ID から
    /// 対象クレデンシャルを引いた 1 件だけ `Passkey::from` で変換して渡す。
    fn finish_authentication(
        &self,
        credential: &PublicKeyCredential,
        state: DiscoverableAuthentication,
        creds: &[DiscoverableKey],
    ) -> Result<AuthenticationResult, String> {
        self.inner
            .finish_discoverable_authentication(credential, state, creds)
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ceremony_origin_strips_path_prefix() {
        let base = Url::parse("https://idp.example.com/prefix").expect("parse");
        assert_eq!(ceremony_origin(&base).as_str(), "https://idp.example.com/");
    }

    #[test]
    fn ceremony_origin_keeps_non_default_port() {
        let base = Url::parse("http://localhost:8081/idp").expect("parse");
        assert_eq!(ceremony_origin(&base).as_str(), "http://localhost:8081/");
    }

    #[test]
    fn builds_from_a_base_url_with_a_path_prefix() {
        // パス付きの公開ベース URL でも構築でき、RP ID はホスト名になる。
        let _ = WebAuthnService::new("https://idp.example.com/prefix");
    }
}
