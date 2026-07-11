//! ユーザー登録ユースケース（設計仕様 §4.1）。
//!
//! MVP ではメール検証フロー対象外のため、登録時 `status = ACTIVE` / `email_verified = false`。
//! ユーザーは処理対象テナントを所属元（ホーム）として作成し、HOME メンバーシップを同時に
//! 生成する（ADR-0009 §2・§3）。

use crate::domain::clock::Clock;
use crate::domain::error::DomainError;
use crate::domain::id_generator::IdGenerator;
use crate::domain::password::{validate_password_strength, PasswordHasher};
use crate::domain::repositories::{TenantMembershipRepository, UserRepository};
use crate::domain::tenant_context::TenantContext;
use crate::domain::tenant_membership::TenantMembership;
use crate::domain::user::User;
use crate::domain::values::UserStatus;
use std::sync::Arc;
use uuid::Uuid;

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
    memberships: Arc<dyn TenantMembershipRepository>,
    hasher: Arc<dyn PasswordHasher>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
}

impl RegisterService {
    pub fn new(
        users: Arc<dyn UserRepository>,
        memberships: Arc<dyn TenantMembershipRepository>,
        hasher: Arc<dyn PasswordHasher>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
    ) -> Self {
        Self {
            users,
            memberships,
            hasher,
            clock,
            ids,
        }
    }

    pub async fn register(
        &self,
        tenant: TenantContext,
        cmd: RegisterCommand,
    ) -> Result<RegisteredUser, RegisterError> {
        let email = cmd.email.trim().to_string();
        validate_email(&email)?;
        validate_password(&cmd.password)?;
        let preferred_username = normalize_optional(cmd.preferred_username);
        let name = normalize_optional(cmd.name);
        let tenant_id = tenant.tenant_id();

        // 一意性の事前チェック（利用者向けの分かりやすいエラーのため）。一意キーは
        // `(tenant_id, email)` 等のテナント内一意（ADR-0009 §2）。最終的な一意性は
        // DB の UNIQUE 制約が保証し、競合時は create() が Conflict を返す。
        if self
            .users
            .find_by_email(tenant_id, &email)
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
                .find_by_username(tenant_id, username)
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
            id: self.ids.new_id(),
            tenant_id,
            sub: self.ids.new_id(),
            email,
            email_verified: false,
            preferred_username,
            name,
            password_hash,
            must_change_password: false,
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

        // HOME メンバーシップ（所属元の単一の出所は users.tenant_id。この行はフロー判定用の
        // 投影として自動生成する。ADR-0009 §3）。
        self.memberships
            .create(&TenantMembership::new_home(tenant_id, user.id, now))
            .await
            .map_err(internal)?;

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
    validate_password_strength(password).map_err(RegisterError::Validation)
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
