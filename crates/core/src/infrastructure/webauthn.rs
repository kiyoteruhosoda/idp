//! `webauthn-rs` ラッパー。
//!
//! `Webauthn` インスタンスの構築と、登録・認証の始終フロー（begin/finish）を一箇所に集約する。
//! RP ID は issuer URL のホスト名部分、RP オリジンは issuer URL そのものを使う。
//!
//! エラー型は `webauthn_rs::WebauthnError` を文字列にしてアプリエラーとして返す。

use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    AuthenticationResult, CreationChallengeResponse, DiscoverableAuthentication,
    DiscoverableKey, Passkey, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, RequestChallengeResponse, Webauthn, WebauthnBuilder,
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
    /// `issuer` から RP ID（ホスト名）と RP オリジンを導出して `Webauthn` を構築する。
    ///
    /// # Panics
    /// `issuer` が有効な URL でない場合、またはホスト名がない場合は panic する
    /// （設定ミスなので起動時に即座に検出する）。
    pub fn new(issuer: &str) -> Self {
        let origin =
            Url::parse(issuer).unwrap_or_else(|e| panic!("ISSUER is not a valid URL: {e}"));
        let rp_id = origin
            .host_str()
            .unwrap_or_else(|| panic!("ISSUER URL has no host: {issuer}"));
        let inner = WebauthnBuilder::new(rp_id, &origin)
            .unwrap_or_else(|e| panic!("failed to build Webauthn: {e}"))
            .rp_name("OIDC IdP")
            .build()
            .unwrap_or_else(|e| panic!("failed to build Webauthn: {e}"));
        Self { inner }
    }

    // ─── 登録 ─────────────────────────────────────────────────────────────

    /// 登録開始: チャレンジと `PasskeyRegistration` 中間状態を返す。
    ///
    /// `exclude_credentials` には既存登録済みの `Passkey` スライスを渡すことで
    /// 同一デバイスの二重登録を防ぐ。
    pub fn begin_registration(
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
                    Some(exclude_credentials.iter().map(|p| p.cred_id().clone()).collect())
                },
            )
            .map_err(|e| e.to_string())
    }

    /// 登録完了: レスポンスを検証して `Passkey` を返す。
    pub fn finish_registration(
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
    pub fn begin_authentication(
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
    pub fn finish_authentication(
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
