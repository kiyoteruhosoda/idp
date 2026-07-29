//! `webauthn-rs` ラッパー。
//!
//! `Webauthn` インスタンスの構築と、登録・認証の始終フロー（begin/finish）を一箇所に集約する。
//! RP ID は web の公開ベース URL（`PUBLIC_WEB_BASE_URL`。未設定時は issuer に追従）のホスト名部分、
//! RP オリジンはその URL そのものを使う。Passkey のセレモニー（`navigator.credentials.*`）は web の
//! ページ上で実行されるため、RP ID・origin は web のオリジンに対して成立させる（ADR-0019 決定 2。
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
        let origin = Url::parse(web_base_url)
            .unwrap_or_else(|e| panic!("PUBLIC_WEB_BASE_URL is not a valid URL: {e}"));
        let rp_id = origin
            .host_str()
            .unwrap_or_else(|| panic!("PUBLIC_WEB_BASE_URL has no host: {web_base_url}"));
        let inner = WebauthnBuilder::new(rp_id, &origin)
            .unwrap_or_else(|e| panic!("failed to build Webauthn: {e}"))
            .rp_name("OIDC IdP")
            .build()
            .unwrap_or_else(|e| panic!("failed to build Webauthn: {e}"));
        Self { inner }
    }
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
