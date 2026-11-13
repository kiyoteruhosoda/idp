//! Admin console handlers (A2 foundation, ADR-0006).
//!
//! `GET /{tenant_id}/admin/whoami` can only be called by principals holding `idp.tenant.admin` (`idp.system.admin`
//! allowed as an alternative) (`RequirePerms<IdpAdmin>`; fine-grained codes alone don't pass, ADR-0037 decision 8).
//! As with the other admin APIs, the only credential is an admin token in `Authorization: Bearer` (ADR-0037).
//! Permission codes themselves are internal authorization and not listed in Discovery's `scopes_supported` (ADR-0006 §7).

use crate::domain::permission;
use crate::presentation::admin::{IdpAdmin, RequirePerms};
use crate::presentation::dto::WhoamiResponse;
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};

/// Returns the identity of the authorized admin user and the tenant being operated (admin console connectivity check).
/// Being able to access it itself means "valid admin token + holds `idp.tenant.admin`".
/// web's admin console calls this with the admin token exchanged from the SSO session (`POST /internal/admin/token`)
/// to get the auth state, identity and tenant display name (ADR-0007 §4 / ADR-0037). The tenant display name
/// appears in every screen's header, so it piggybacks here to avoid an extra call per screen (the tenant is
/// already resolved once `RequirePerms` passes).
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/whoami",
    tag = "admin",
    responses(
        (status = 200, description = "管理トークンの主体の身元・テナント表示名・行使できる権限コード", body = WhoamiResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.tenant.admin 必須。細粒度コードだけでは通らない）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn whoami(
    RequirePerms(admin, _): RequirePerms<IdpAdmin>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
) -> Response {
    let permissions =
        effective_permissions(&state, &admin.permission_codes, tenant.tenant().is_root()).await;
    Json(WhoamiResponse {
        // The admin console is a screen people sign in to, so the principal here is a user
        // (system clients cannot hold `idp.tenant.admin`, ADR-0037).
        user_id: admin
            .actor
            .user_id()
            .map(|id| id.to_string())
            .unwrap_or_default(),
        name: admin.name,
        preferred_username: admin.preferred_username,
        tenant_name: Some(tenant.tenant().name.clone()),
        permissions,
    })
    .into_response()
}

/// Builds, from the held codes, the list of codes this principal can actually exercise (expands implications).
///
/// The universe for expansion is the `permissions` master. "Return the held codes as is" would leave consumers
/// unable to decide without knowing the implications (`idp.system.admin` implies all, `:write` implies `:read`), scattering
/// the decision across core and web. The master is read once, on every console screen render.
///
/// If the master cannot be read, **only the held codes** are returned, because failing here would keep every
/// admin console screen from opening. The returned list is not expanded though, so consumers' checks become
/// exact matches (screens needing `idp.users:read` are hidden from `idp.tenant.admin` holders). This path
/// over-hides **only while the master is unreadable**, and `idp.system.admin`, which consumers check today,
/// is listed directly as a held code, so it is unaffected. When adding a check that needs implications, change
/// this branch to "return empty = no filtering".
///
/// ⚠ In non-root tenants, codes exercisable only within root (signing keys, `ROOT_SCOPED_CODES`) are
/// dropped. Even if held via implication, the endpoint requires root, so clicking through would dead-end at 403.
async fn effective_permissions(
    state: &AppState,
    held: &[String],
    tenant_is_root: bool,
) -> Vec<String> {
    let mut codes = match state.permissions_admin.available_codes().await {
        Ok(codes) => codes,
        Err(e) => {
            tracing::warn!(
                error = %e,
                consequence = "the console cannot hide the screens this admin may not open",
                "could not read the permission master for whoami"
            );
            return held.to_vec();
        }
    };
    codes.retain(|code| {
        permission::satisfies(held, code) && (tenant_is_root || !permission::is_root_scoped(code))
    });
    codes
}
