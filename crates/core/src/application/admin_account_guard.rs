//! 細粒度コードの持ち主から、管理者の口座と管理者の権限を守る（task #579。ADR-0037 の約束）。
//!
//! 細粒度コード（`idp.users:write` など）は「テナントの中の分担」のためのもので、集めても
//! `idp.tenant.admin` / `idp.system.admin` には届かない、というのが約束である。ところが口ごとの
//! 判定は「その口のコードを持つか」だけだったので、次の 2 つで約束が破れていた。
//!
//! - **口座の操作**: `idp.users:write` だけで管理者のパスワード再発行・MFA 解除ができ、
//!   返ってきた設定リンクでなりすませた
//! - **権限の付与**: `idp.permissions:write` / `idp.clients:write` だけで、自分の持たないコード
//!   （`idp.tenant.admin` など）を誰にでも付けられた
//!
//! 本サービスは各口の前に呼ぶ「もう 1 枚」で、判定そのものは `domain::permission` の
//! [`permission::may_assign`] / [`permission::may_manage_account`] が単一の出所である。
//! 呼び出し元の保有コードは管理トークンの `perms`（`RequirePerms` の判定と同じ材料）を使う。

use crate::domain::permission::{self, HeldByTarget, TargetScope};
use crate::domain::repositories::{
    ClientPermissionRepository, ClientRepository, TenantRepository, UserPermissionRepository,
    UserRepository,
};
use crate::domain::tenant_context::TenantContext;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum AdminAccountGuardError {
    /// 呼び出し元より強い口座・権限に触れようとした。
    #[error("forbidden")]
    Forbidden,
    #[error("internal error: {0}")]
    Internal(String),
}

pub struct AdminAccountGuard {
    users: Arc<dyn UserRepository>,
    permissions: Arc<dyn UserPermissionRepository>,
    clients: Arc<dyn ClientRepository>,
    client_permissions: Arc<dyn ClientPermissionRepository>,
    tenants: Arc<dyn TenantRepository>,
}

impl AdminAccountGuard {
    pub fn new(
        users: Arc<dyn UserRepository>,
        permissions: Arc<dyn UserPermissionRepository>,
        clients: Arc<dyn ClientRepository>,
        client_permissions: Arc<dyn ClientPermissionRepository>,
        tenants: Arc<dyn TenantRepository>,
    ) -> Self {
        Self {
            users,
            permissions,
            clients,
            client_permissions,
            tenants,
        }
    }

    /// 権限コード `code` の付与・剥奪の前に呼ぶ（利用者へもクライアントへも）。
    ///
    /// 剥奪も同じ判定にする ——自分の持たないコードを外せると、細粒度コードの持ち主が
    /// 管理者から `idp.tenant.admin` を外して締め出せる。
    pub fn ensure_may_assign(
        &self,
        held: &[String],
        code: &str,
        tenant_is_root: bool,
    ) -> Result<(), AdminAccountGuardError> {
        // `idp.system.admin` は保有者しか扱えない、という判定は付与の本体が持ち、理由も言い分ける
        // （`PermissionManagementService::ensure_system_admin_change_allowed`。クライアントへはそもそも
        // 付けられない）。ここで先に落とすと、その言い分けが届かなくなる。
        if code == permission::SYSTEM_ADMIN || permission::may_assign(held, code, tenant_is_root) {
            Ok(())
        } else {
            Err(AdminAccountGuardError::Forbidden)
        }
    }

    /// 口座の操作（パスワード・MFA の再発行、状態・プロフィール・ログイン識別子の変更、削除など）の
    /// 前に呼ぶ。対象が持つ権限を**すべての scope で**見る（ゲストとして他のテナントで持つものを含む）。
    ///
    /// ⚠ 対象が要求テナントの所属でない・存在しないときは何もしない。それは操作の側が 404 にする
    /// ——ここで 403 を返すと、テナントを越えて「その ID の利用者が居る」と分かってしまう。
    pub async fn ensure_may_manage_account(
        &self,
        tenant: TenantContext,
        tenant_is_root: bool,
        held: &[String],
        target: Uuid,
    ) -> Result<(), AdminAccountGuardError> {
        let user = self
            .users
            .find_by_id(target)
            .await
            .map_err(|e| AdminAccountGuardError::Internal(e.to_string()))?;
        match user {
            Some(user) if user.tenant_id == tenant.tenant_id() => {}
            _ => return Ok(()),
        }
        let scoped_codes = self
            .permissions
            .list_scoped_codes_for_user(target)
            .await
            .map_err(|e| AdminAccountGuardError::Internal(e.to_string()))?;
        // root の権限を持つゲストを見分ける（ADR-0070）。見分けが付かないときは操作させない。
        let root = self
            .tenants
            .find_root()
            .await
            .map_err(|e| AdminAccountGuardError::Internal(e.to_string()))?
            .ok_or_else(|| AdminAccountGuardError::Internal("root tenant not found".to_string()))?
            .id;
        let held_by_target: Vec<HeldByTarget> = scoped_codes
            .into_iter()
            .map(|(scope, code)| HeldByTarget {
                code,
                scope: if scope == tenant.tenant_id() {
                    TargetScope::RequestedTenant
                } else if scope == root {
                    TargetScope::RootTenant
                } else {
                    TargetScope::OtherTenant
                },
            })
            .collect();
        self.decide(held, &held_by_target, tenant_is_root)
    }

    /// クライアントの更新（鍵・認証方式を含む）・秘密の作り直し・削除の前に呼ぶ（task #756）。
    ///
    /// 秘密を作り直せる・公開鍵を差し替えられれば、そのクライアントの権限を行使できる。口座と同じく
    /// **対象の権限を全部、呼び出し元が付与できる**ときだけ許す。クライアントの権限の scope は所属
    /// テナントだけ（`client_permissions` に scope 列は無い）。
    ///
    /// ⚠ 対象が要求テナントに無いときは何もしない。それは操作の側が 404 にする。
    pub async fn ensure_may_manage_client(
        &self,
        tenant: TenantContext,
        tenant_is_root: bool,
        held: &[String],
        client_id: &str,
    ) -> Result<(), AdminAccountGuardError> {
        let client = self
            .clients
            .find_by_client_id(tenant.tenant_id(), client_id)
            .await
            .map_err(|e| AdminAccountGuardError::Internal(e.to_string()))?;
        let Some(client) = client else {
            return Ok(());
        };
        let held_by_target: Vec<HeldByTarget> = self
            .client_permissions
            .list_codes_for_client(client.id)
            .await
            .map_err(|e| AdminAccountGuardError::Internal(e.to_string()))?
            .into_iter()
            .map(|code| HeldByTarget {
                code,
                scope: TargetScope::RequestedTenant,
            })
            .collect();
        self.decide(held, &held_by_target, tenant_is_root)
    }

    /// メンバーシップの操作（停止・解除）の前に呼ぶ。見るのは**要求テナントの scope の**権限だけ
    /// （ゲストの所属元の権限は、参加先の管理者には関わりが無い。ADR-0009 §3）。
    pub async fn ensure_may_manage_membership(
        &self,
        tenant: TenantContext,
        tenant_is_root: bool,
        held: &[String],
        target: Uuid,
    ) -> Result<(), AdminAccountGuardError> {
        let held_by_target: Vec<HeldByTarget> = self
            .permissions
            .list_codes_for_user(tenant.tenant_id(), target)
            .await
            .map_err(|e| AdminAccountGuardError::Internal(e.to_string()))?
            .into_iter()
            .map(|code| HeldByTarget {
                code,
                scope: TargetScope::RequestedTenant,
            })
            .collect();
        self.decide(held, &held_by_target, tenant_is_root)
    }

    fn decide(
        &self,
        held: &[String],
        held_by_target: &[HeldByTarget],
        tenant_is_root: bool,
    ) -> Result<(), AdminAccountGuardError> {
        if permission::may_manage_account(held, held_by_target, tenant_is_root) {
            Ok(())
        } else {
            Err(AdminAccountGuardError::Forbidden)
        }
    }
}
