//! RefreshTokens entity (design spec §9.1).
//! The DB stores `token_hash = SHA-256(refresh_token)` rather than plaintext.
//! `parent_hash` is used for rotation / reuse detection.
#![allow(dead_code)]

use crate::domain::tenant::TenantId;
use crate::domain::values::AuthenticationMethod;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct RefreshToken {
    pub token_hash: String,
    /// Set when issued by rotation (hash of the previous token in the chain).
    pub parent_hash: Option<String>,
    /// SHA-256 of the authorization grant (authorization code) that produced this token (SEC8). The
    /// root token issued by code exchange and all descendants derived from it by rotation share the
    /// same value = **the token family identifier**. When reuse is detected, the whole family is
    /// revoked by this value.
    ///
    /// `parent_hash` can follow the chain only one step at a time, so descendants cannot be traced
    /// on reuse detection. `None` only for rows rotated before the migration (before 0025); filled
    /// at the next rotation.
    pub grant_hash: Option<String>,
    /// The tenant that issued the token (ADR-0009 §8; use and revocation are limited to the same
    /// tenant).
    pub tenant_id: TenantId,
    pub user_id: Uuid,
    pub client_id: String,
    pub scope: Vec<String>,
    /// SSO session identifier put in the ID Token (G5). Carried over on rotation.
    pub sid: Option<String>,
    /// Methods verified by the authentication that produced this grant (ADR-0043). Like `sid`,
    /// carried over on rotation — refresh does not redo authentication, so the claimed strength
    /// does not change either. `None` = not recorded (tokens issued before this column existed).
    pub authentication_methods: Option<Vec<AuthenticationMethod>>,
    /// Time of the authentication that produced this grant (the ID Token's `auth_time`; task #584).
    /// Like `sid`, carried over on rotation — refresh does not redo authentication, so the "last
    /// login time" does not change either. `None` = not recorded (tokens issued before this column
    /// existed; [`Self::auth_time_or_issued`]).
    pub auth_time: Option<DateTime<Utc>>,
    /// Thumbprint of the key bound via DPoP (RFC 7638; ADR-0075). If `Some`, unusable without a
    /// proof by the same key. Carried over to children on rotation. `None` = unbound (usable by
    /// whoever holds it, as before).
    pub dpop_jkt: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl RefreshToken {
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }

    pub fn is_valid_at(&self, now: DateTime<Utc>) -> bool {
        !self.is_revoked() && !self.is_expired_at(now)
    }

    /// Family identifier carried over to the child issued from this token by rotation (SEC8).
    ///
    /// For a pre-migration row without its own `grant_hash`, **its own hash becomes the start of a
    /// new family**. Ancestors are not traced because the recursion to do so would sit on the
    /// rotation hot path. This way, chains alive since before the migration become subject to
    /// family revocation from the next rotation on. Time used for the ID Token's `auth_time`.
    /// Pre-migration rows without a record use the time the token was issued (the actual
    /// authentication was earlier, so at least it never claims "just logged in").
    pub fn auth_time_or_issued(&self) -> DateTime<Utc> {
        self.auth_time.unwrap_or(self.created_at)
    }

    pub fn family_hash(&self) -> String {
        self.grant_hash
            .clone()
            .unwrap_or_else(|| self.token_hash.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(token_hash: &str, grant_hash: Option<&str>) -> RefreshToken {
        let now = Utc::now();
        RefreshToken {
            token_hash: token_hash.to_string(),
            parent_hash: None,
            grant_hash: grant_hash.map(str::to_string),
            tenant_id: Uuid::nil().into(),
            user_id: Uuid::nil(),
            client_id: "rp".to_string(),
            scope: vec!["openid".to_string()],
            sid: None,
            authentication_methods: None,
            auth_time: None,
            dpop_jkt: None,
            expires_at: now,
            revoked_at: None,
            created_at: now,
        }
    }

    #[test]
    fn family_is_inherited_from_the_authorization_grant() {
        assert_eq!(token("child", Some("grant")).family_hash(), "grant");
    }

    #[test]
    fn legacy_rows_start_a_new_family_at_their_own_hash() {
        // Rows rotated before 0025 have no `grant_hash`. By using themselves as the start without
        // tracing ancestors, they become subject to family revocation from the next rotation on.
        assert_eq!(token("legacy", None).family_hash(), "legacy");
    }

    #[test]
    fn auth_time_falls_back_to_when_the_token_was_issued() {
        let mut t = token("t", None);
        let issued = t.created_at;
        assert_eq!(t.auth_time_or_issued(), issued);
        let signed_in = issued - chrono::Duration::hours(3);
        t.auth_time = Some(signed_in);
        assert_eq!(t.auth_time_or_issued(), signed_in);
    }
}
