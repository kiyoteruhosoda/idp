//! ドメインエラーと OAuth 2.0 / OIDC エラーコード。
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

/// OAuth 2.0 / OIDC のエラーコード（authorize / token レスポンスで用いる）。
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
        }
    }
}
