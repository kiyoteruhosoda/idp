//! `webauthn-rs` wrapper.
//!
//! Concentrates building the `Webauthn` instance and the registration/authentication flows (begin/finish) in one place.
//! The RP ID is the host name of web's public base URL (`PUBLIC_WEB_BASE_URL`; follows the issuer when unset),
//! and the RP origin is that URL's origin (scheme + host + port; the path is dropped). Passkey
//! ceremonies (`navigator.credentials.*`) run on web's pages, so the RP ID and origin
//! are established against web's origin (ADR-0019 decision 2.
//! Deriving them from the issuer = api's origin would, with a domain split, make the api host not a registrable
//! suffix of the web page, and the ceremony would always fail in the browser).
//!
//! Errors are returned as app errors with `webauthn_rs::WebauthnError` converted to a string.

use crate::domain::webauthn_port::WebAuthnPort;
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    AuthenticationResult, CreationChallengeResponse, DiscoverableAuthentication, DiscoverableKey,
    Passkey, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Webauthn, WebauthnBuilder,
};
use webauthn_rs_proto::ResidentKeyRequirement;

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
    /// Builds `Webauthn` by deriving the RP ID (host name) and RP origin from `web_base_url`
    /// (web's public base URL).
    ///
    /// # Panics
    /// Panics if `web_base_url` is not a valid URL or has no host name
    /// (a configuration mistake, so it is detected immediately at startup).
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

/// Expected origin of the ceremony (scheme + host + port only). The browser's `clientDataJSON.origin` is
/// always an origin without a path, so to match even when the public base URL has a path prefix (e.g.
/// `https://example.com/idp`; `validate_public_base_url` allows paths), the path is dropped
/// before passing it to `WebauthnBuilder`.
fn ceremony_origin(base: &Url) -> Url {
    Url::parse(&base.origin().ascii_serialization())
        .unwrap_or_else(|e| panic!("PUBLIC_WEB_BASE_URL has no valid origin: {e}"))
}

impl WebAuthnPort for WebAuthnService {
    // ─── Registration ─────────────────────────────────────────────────────────────

    /// Begin registration: returns the challenge and the intermediate `PasskeyRegistration` state.
    ///
    /// Passing the already-registered `Passkey` slice as `exclude_credentials`
    /// prevents registering the same device twice.
    fn begin_registration(
        &self,
        user_id: Uuid,
        user_name: &str,
        user_display_name: &str,
        exclude_credentials: &[Passkey],
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration), String> {
        let (mut challenge, state) = self
            .inner
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
            .map_err(|e| e.to_string())?;

        // **Require a discoverable (resident) key.**
        //
        // webauthn-rs's `start_passkey_registration` sets `residentKey: discouraged`
        // (`require_resident_key(false)`). Our authentication, on the other hand, **only has**
        // `start_discoverable_authentication` -- `allowCredentials` sent empty, with the authenticator naming the owner.
        // If these don't mesh, you get **a key that registers successfully but can never be used to log in**.
        // The browser can't find a matching key and returns `NotAllowedError`, so the screen only shows
        // "cancelled or timed out" and the cause can't be traced (actually hit on 2026-09-02).
        //
        // As with dropping `mediation` (`begin_authentication`), the value webauthn-rs built is fixed
        // afterwards here too (`start_passkey_registration` doesn't take this as an argument).
        //
        // Create it if absent. Branching with `if let Some(..)` would make **just this requirement silently vanish**
        // the day webauthn-rs stops including `authenticatorSelection`.
        // The default is `user_verification: Required`, the same value webauthn-rs sets.
        let selection = challenge
            .public_key
            .authenticator_selection
            .get_or_insert_with(Default::default);
        selection.resident_key = Some(ResidentKeyRequirement::Required);
        selection.require_resident_key = true;

        Ok((challenge, state))
    }

    /// Finish registration: verifies the response and returns a `Passkey`.
    fn finish_registration(
        &self,
        credential: &RegisterPublicKeyCredential,
        state: &PasskeyRegistration,
    ) -> Result<Passkey, String> {
        self.inner
            .finish_passkey_registration(credential, state)
            .map_err(|e| e.to_string())
    }

    // ─── Authentication ─────────────────────────────────────────────────────────────

    /// Begin authentication (discoverable credentials): returns the challenge and `DiscoverableAuthentication`.
    ///
    /// The authenticator sends the user handle, so the user need not be identified beforehand.
    ///
    /// **`mediation` is dropped.** `start_discoverable_authentication()` sets `mediation: Conditional`
    /// when the `conditional-ui` feature is enabled, but conditional is
    /// **a ceremony started from an input field's autofill**, needing an input on the page whose `autocomplete`
    /// includes `webauthn`. All of the IdP's login screens call `navigator.credentials.get()` on a button press
    /// and have no such field. Leaving this value in means
    /// **the first press does nothing and stays pending** (the browser keeps waiting for an autofill choice),
    /// and the second press gives `A request is already pending`.
    ///
    /// `mediation` is skipped in serialization via `Option::is_none`, so setting it to `None`
    /// removes the field from the response JSON entirely and the browser shows the default modal chooser UI.
    /// To add an autofill experience, the right way is to put `autocomplete="username webauthn"` on the input and
    /// separately start a conditional `get()` **on page load**, which is distinct from the button path.
    fn begin_authentication(
        &self,
    ) -> Result<(RequestChallengeResponse, DiscoverableAuthentication), String> {
        let (mut challenge, state) = self
            .inner
            .start_discoverable_authentication()
            .map_err(|e| e.to_string())?;
        challenge.mediation = None;
        Ok((challenge, state))
    }

    /// Finish authentication: verifies the credential and returns an `AuthenticationResult`.
    ///
    /// `creds` is `&[DiscoverableKey]`. Only the one credential looked up by the credential ID in the
    /// authentication response is converted with `Passkey::from` and passed.
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
        // Can be built even with a public base URL that has a path, and the RP ID becomes the host name.
        let _ = WebAuthnService::new("https://idp.example.com/prefix");
    }

    /// The options passed to the login screen don't carry `mediation`.
    ///
    /// With it, the ceremony becomes conditional (autofill), and on screens without an input whose `autocomplete`
    /// includes `webauthn`, pressing the button does nothing, and the second press gives
    /// `A request is already pending`. Checked on the JSON sent to the browser -- at the type level it is
    /// just one `Option`, but what determines screen behavior is the serialized result.
    #[test]
    fn the_authentication_options_do_not_ask_for_conditional_mediation() {
        let service = WebAuthnService::new("https://idp.example.com");
        let (challenge, _state) = service
            .begin_authentication()
            .expect("begin_authentication succeeds");
        assert!(challenge.mediation.is_none());
        let json = serde_json::to_value(&challenge).expect("serialize");
        assert!(
            json.get("mediation").is_none(),
            "the options must not carry a mediation hint: {json}"
        );
        assert_eq!(json["publicKey"]["rpId"], "idp.example.com");
    }

    /// Registration requires **a discoverable (resident) key** (see the note in `begin_registration` for why).
    ///
    /// webauthn-rs defaults to `discouraged`, so the override is checked in the serialized JSON.
    #[test]
    fn the_registration_options_require_a_discoverable_credential() {
        let service = WebAuthnService::new("https://idp.example.com");
        let (challenge, _state) = service
            .begin_registration(Uuid::new_v4(), "user@example.com", "User", &[])
            .expect("begin_registration succeeds");
        let json = serde_json::to_value(&challenge).expect("serialize");
        let selection = &json["publicKey"]["authenticatorSelection"];
        assert_eq!(
            selection["residentKey"], "required",
            "authentication is discoverable-only, so registration must ask for it: {json}"
        );
        assert_eq!(selection["requireResidentKey"], true);
    }
}
