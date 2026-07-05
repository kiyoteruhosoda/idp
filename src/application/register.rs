//! ユーザー登録ユースケース（設計仕様 §4.1）。
//!
//! MVP ではメール検証フロー対象外のため、登録時 `status = ACTIVE` / `email_verified = false`。

use crate::domain::clock::Clock;
use crate::domain::error::DomainError;
use crate::domain::password::PasswordHasher;
use crate::domain::repositories::UserRepository;
use crate::domain::user::User;
use crate::domain::values::UserStatus;
use std::sync::Arc;
use uuid::Uuid;

/// パスワードの最小長。
const MIN_PASSWORD_LEN: usize = 8;

#[derive(Debug, Clone)]
pub struct RegisterCommand {
    pub email: String,
    pub preferred_username: Option<String>,
    pub password: String,
    pub name: Option<String>,
}

pub struct RegisteredUser {
    pub sub: Uuid,
    pub status: UserStatus,
}

#[derive(Debug, thiserror::Error)]
pub enum RegisterError {
    #[error("validation error: {0}")]
    Validation(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("internal error: {0}")]
    Internal(String),
}

pub struct RegisterService {
    users: Arc<dyn UserRepository>,
    hasher: Arc<dyn PasswordHasher>,
    clock: Arc<dyn Clock>,
}

impl RegisterService {
    pub fn new(
        users: Arc<dyn UserRepository>,
        hasher: Arc<dyn PasswordHasher>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            users,
            hasher,
            clock,
        }
    }

    pub async fn register(&self, cmd: RegisterCommand) -> Result<RegisteredUser, RegisterError> {
        let email = cmd.email.trim().to_string();
        validate_email(&email)?;
        validate_password(&cmd.password)?;
        let preferred_username = normalize_optional(cmd.preferred_username);
        let name = normalize_optional(cmd.name);

        // 一意性の事前チェック（利用者向けの分かりやすいエラーのため）。最終的な一意性は
        // DB の UNIQUE 制約が保証し、競合時は create() が Conflict を返す。
        if self
            .users
            .find_by_email(&email)
            .await
            .map_err(internal)?
            .is_some()
        {
            return Err(RegisterError::Conflict(
                "email already registered".to_string(),
            ));
        }
        if let Some(username) = &preferred_username {
            if self
                .users
                .find_by_username(username)
                .await
                .map_err(internal)?
                .is_some()
            {
                return Err(RegisterError::Conflict(
                    "preferred_username already taken".to_string(),
                ));
            }
        }

        let password_hash = self.hasher.hash(&cmd.password).map_err(internal)?;
        let now = self.clock.now();
        let user = User {
            id: Uuid::new_v4(),
            sub: Uuid::new_v4(),
            email,
            email_verified: false,
            preferred_username,
            name,
            password_hash,
            status: UserStatus::Active,
            failed_login_count: 0,
            locked_until: None,
            created_at: now,
            updated_at: now,
        };

        self.users.create(&user).await.map_err(|e| match e {
            DomainError::Conflict(m) => RegisterError::Conflict(m),
            other => RegisterError::Internal(other.to_string()),
        })?;

        Ok(RegisteredUser {
            sub: user.sub,
            status: user.status,
        })
    }
}

fn validate_email(email: &str) -> Result<(), RegisterError> {
    // 簡易チェック（MVP）: 空でなく、`@` を挟んで両側に文字がある。
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty() {
        Ok(())
    } else {
        Err(RegisterError::Validation(
            "invalid email format".to_string(),
        ))
    }
}

fn validate_password(password: &str) -> Result<(), RegisterError> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(RegisterError::Validation(format!(
            "password must be at least {MIN_PASSWORD_LEN} characters"
        )));
    }
    Ok(())
}

fn normalize_optional(value: Option<String>) -> Option<String> {
    value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn internal(e: DomainError) -> RegisterError {
    RegisterError::Internal(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_email_and_short_password() {
        assert!(validate_email("not-an-email").is_err());
        assert!(validate_email("a@b").is_ok());
        assert!(validate_password("short").is_err());
        assert!(validate_password("longenough").is_ok());
    }

    #[test]
    fn normalizes_empty_optional_to_none() {
        assert_eq!(normalize_optional(Some("  ".to_string())), None);
        assert_eq!(
            normalize_optional(Some("  bob ".to_string())),
            Some("bob".to_string())
        );
        assert_eq!(normalize_optional(None), None);
    }
}
