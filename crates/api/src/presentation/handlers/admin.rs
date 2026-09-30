//! 管理コンソールのハンドラ（A2 の基盤。ADR-0006）。
//!
//! `GET /{tenant_id}/admin/whoami` は `idp.tenant.admin` 権限（`idp.system.admin` は代替として許可）を
//! 保有する主体だけが呼べる（`RequirePerms<IdpAdmin>`。細粒度コードだけでは通らない。ADR-0037 の決定 8）。
//! 資格情報は他の管理 API と同じく `Authorization: Bearer` の管理トークンだけである（ADR-0037）。
//! 権限コードそのものは内部認可であり、Discovery の `scopes_supported` には載せない（ADR-0006 §7）。

use crate::domain::permission;
use crate::presentation::admin::{IdpAdmin, RequirePerms};
use crate::presentation::dto::WhoamiResponse;
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};

/// 認可済み管理利用者の身元と、操作中のテナントを返す（管理コンソール基盤の疎通確認用）。
/// アクセスできること自体が「有効な管理トークン ＋ `idp.tenant.admin` 保有」を意味する。
/// web の管理コンソールは SSO セッションを交換した管理トークン（`POST /internal/admin/token`）で
/// これを呼び、認証状態・身元・テナント表示名を得る（ADR-0007 §4 / ADR-0037）。テナント表示名は
/// 全画面のヘッダに出すため、画面ごとの追加呼び出しを避けてここに相乗りさせる（`RequirePerms` が
/// 通った時点でテナントは解決済み）。
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
    let permissions = effective_permissions(&state, &admin.permission_codes).await;
    Json(WhoamiResponse {
        // 管理コンソールは人がログインして使う画面なので、ここに来る主体は利用者である
        // （システム用クライアントは `idp.tenant.admin` を保有できない。ADR-0037）。
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

/// 保有コードから、この主体が実際に行使できるコードの一覧を作る（含意を展開する）。
///
/// 展開先の母集合は `permissions` マスタである。「保有コードをそのまま返す」では消費側が
/// 含意（`idp.system.admin` は全部・`:write` は `:read`）を知らないと判定できず、判定が
/// core と web の 2 か所に散る。マスタの読みは 1 回で、コンソールの画面表示のたびに走る。
///
/// マスタが読めなかったときは**保有コードだけ**を返す。ここで落とすと管理コンソールの全画面が
/// 開かなくなるためである。ただし返す並びは含意を展開していないので、消費側の判定は完全一致に
/// なる（`idp.tenant.admin` の保有者に `idp.users:read` を要する画面が隠れる）。この経路が
/// 隠しすぎになるのは**マスタが読めない間だけ**で、いま消費側が見る `idp.system.admin` は
/// 保有コードとして直接載るため影響しない。含意が要る判定を足すときは、この分岐を
/// 「空を返す＝絞り込まない」へ変えること。
async fn effective_permissions(state: &AppState, held: &[String]) -> Vec<String> {
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
    codes.retain(|code| permission::satisfies(held, code));
    codes
}
