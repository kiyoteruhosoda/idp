//! WebAuthn の DIP 境界。
//!
//! Application 層は `webauthn-rs` を直接ラップする具象サービスではなく、この port に依存する。
//! composition root が Infrastructure 実装を選択することで、テスト時には別実装へ差し替えられる。

use uuid::Uuid;
use webauthn_rs::prelude::{
    AuthenticationResult, CreationChallengeResponse, DiscoverableAuthentication, DiscoverableKey,
    Passkey, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};

pub trait WebAuthnPort: Send + Sync {
    fn begin_registration(
        &self,
        user_id: Uuid,
        user_name: &str,
        user_display_name: &str,
        exclude_credentials: &[Passkey],
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration), String>;

    fn finish_registration(
        &self,
        credential: &RegisterPublicKeyCredential,
        state: &PasskeyRegistration,
    ) -> Result<Passkey, String>;

    fn begin_authentication(
        &self,
    ) -> Result<(RequestChallengeResponse, DiscoverableAuthentication), String>;

    fn finish_authentication(
        &self,
        credential: &PublicKeyCredential,
        state: DiscoverableAuthentication,
        creds: &[DiscoverableKey],
    ) -> Result<AuthenticationResult, String>;
}
