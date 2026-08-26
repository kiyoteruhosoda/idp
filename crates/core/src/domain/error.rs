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
    /// `prompt=none` でログインが必要な場合（OIDC Core 3.1.2.6）。
    LoginRequired,
    /// `prompt=none` で同意が必要な場合（OIDC Core 3.1.2.6）。
    ConsentRequired,
    /// `prompt=none` でインタラクションが必要な場合（OIDC Core 3.1.2.6）。
    InteractionRequired,
    /// 要求された `resource`（RFC 8707 §2）が不正・未知・許可されていない場合。
    InvalidTarget,
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
        }
    }
}
