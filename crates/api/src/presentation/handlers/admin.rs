//! 管理コンソールのハンドラ（A2 の基盤。ADR-0006）。
//!
//! 本エンドポイント群は `idp.tenant.admin` 権限（`idp.system.admin` は代替として許可）を保有する
//! 利用者のみアクセスできる（`RequirePerms<IdpAdmin>`）。
//! 内部認可であり第三者へ公開しない（OpenAPI/Discovery には載せない。ADR-0006 §7）。
//! ログイン/監査ログ一覧（A3）や RP 登録画面（A1）は今後この基盤の上に追加する。

use crate::presentation::admin::{IdpAdmin, RequirePerms};
use crate::presentation::tenant::ResolvedTenant;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use idp_contracts::admin::WhoamiResponse;

/// 認可済み管理利用者の身元と、操作中のテナントを返す（管理コンソール基盤の疎通確認用）。
/// アクセスできること自体が「有効な SSO セッション ＋ `idp.tenant.admin` 保有」を意味する。
/// web の管理コンソールはこれを SSO Cookie 転送で呼び、認証状態・身元・テナント表示名を得る
/// （ADR-0007 §4）。テナント表示名は全画面のヘッダに出すため、画面ごとの追加呼び出しを避けて
/// ここに相乗りさせる（`RequirePerms` が通った時点でテナントは解決済み）。
pub async fn whoami(
    RequirePerms(admin, _): RequirePerms<IdpAdmin>,
    Extension(tenant): Extension<ResolvedTenant>,
) -> Response {
    Json(WhoamiResponse {
        user_id: admin.user_id.to_string(),
        name: admin.name,
        preferred_username: admin.preferred_username,
        tenant_name: Some(tenant.tenant().name.clone()),
    })
    .into_response()
}
