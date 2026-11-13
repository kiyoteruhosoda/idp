//! Domain errors and OAuth 2.0 / OIDC error codes.
#![allow(dead_code)]

use thiserror::Error;

pub type Result<T> = std::result::Result<T, DomainError>;

#[derive(Debug, Error)]
pub enum DomainError {
    #[error("resource not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("invalid value: {0}")]
    InvalidValue(String),
    #[error("repository error: {0}")]
    Repository(String),
}

/// OAuth 2.0 / OIDC error codes (used in authorize / token responses).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthErrorCode {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    UnsupportedResponseType,
    InvalidScope,
    AccessDenied,
    ServerError,
    /// Login is required under `prompt=none` (OIDC Core 3.1.2.6).
    LoginRequired,
    /// Consent is required under `prompt=none` (OIDC Core 3.1.2.6).
    ConsentRequired,
    /// Interaction is required under `prompt=none` (OIDC Core 3.1.2.6).
    InteractionRequired,
    /// The requested `resource` (RFC 8707 §2) is malformed, unknown, or not allowed.
    InvalidTarget,
    /// The DPoP proof is missing or invalid (RFC 9449 §5, §12.3; ADR-0075).
    InvalidDpopProof,
}

impl OAuthErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::InvalidScope => "invalid_scope",
            Self::AccessDenied => "access_denied",
            Self::ServerError => "server_error",
            Self::LoginRequired => "login_required",
            Self::ConsentRequired => "consent_required",
            Self::InteractionRequired => "interaction_required",
            Self::InvalidTarget => "invalid_target",
            Self::InvalidDpopProof => "invalid_dpop_proof",
        }
    }
}
