//! DPoP の証明を確かめる（ADR-0075）。ドメインの確かめ（形・署名・`htm`/`htu`/`iat`/`ath`）に、
//! 「同じ鍵・同じ `jti` の証明を 2 回受けない」記録の照合を足す。
//!
//! トークンの口（`/token`）とリソースの口（`/userinfo`）が同じものを使う。

use crate::domain::clock::Clock;
use crate::domain::dpop::{self, DpopProofRejection, DpopProofRequirements, VerifiedDpopProof};
use crate::domain::repositories::DpopProofReplayRepository;
use std::sync::Arc;

/// 証明を受けられなかった理由。
#[derive(Debug)]
pub enum DpopProofFailure {
    /// 証明が正しくない（相手へは `invalid_dpop_proof`）。
    Rejected(DpopProofRejection),
    /// 記録に届かなかった（相手へは 500）。
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

    /// `method` は大文字の HTTP メソッド、`uri` は assay が discovery で名乗るこの口の URL。
    /// リソースの口では `access_token` に一緒に来たトークンを渡す（`ath` を見る）。
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
