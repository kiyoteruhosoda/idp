//! Verifies DPoP proofs (ADR-0075). Adds to the domain checks (shape, signature, `htm`/`htu`/`iat`/`ath`)
//! a lookup in the record that "never accepts a proof with the same key and same `jti` twice".
//!
//! The token endpoint (`/token`) and the resource endpoint (`/userinfo`) use the same thing.

use crate::domain::clock::Clock;
use crate::domain::dpop::{self, DpopProofRejection, DpopProofRequirements, VerifiedDpopProof};
use crate::domain::repositories::DpopProofReplayRepository;
use std::sync::Arc;

/// Why a proof could not be accepted.
#[derive(Debug)]
pub enum DpopProofFailure {
    /// The proof is invalid (`invalid_dpop_proof` to the peer).
    Rejected(DpopProofRejection),
    /// Could not reach the record (500 to the peer).
    Unavailable(String),
}

pub struct DpopProofVerifier {
    replays: Arc<dyn DpopProofReplayRepository>,
    clock: Arc<dyn Clock>,
}

impl DpopProofVerifier {
    pub fn new(replays: Arc<dyn DpopProofReplayRepository>, clock: Arc<dyn Clock>) -> Self {
        Self { replays, clock }
    }

    /// `method` is the uppercase HTTP method; `uri` is this endpoint's URL as assay announces it in discovery.
    /// At the resource endpoint, pass the token that came along in `access_token` (to check `ath`).
    pub async fn verify(
        &self,
        proof: &str,
        method: &str,
        uri: &str,
        access_token: Option<&str>,
    ) -> Result<VerifiedDpopProof, DpopProofFailure> {
        let verified = dpop::verify_proof(
            proof,
            &DpopProofRequirements {
                method,
                uri,
                access_token,
                now: self.clock.now(),
            },
        )
        .map_err(DpopProofFailure::Rejected)?;
        match self
            .replays
            .record_if_unused(&verified.replay_key(), verified.retain_until())
            .await
        {
            Ok(true) => Ok(verified),
            Ok(false) => Err(DpopProofFailure::Rejected(DpopProofRejection::Replayed)),
            Err(e) => Err(DpopProofFailure::Unavailable(e.to_string())),
        }
    }
}
