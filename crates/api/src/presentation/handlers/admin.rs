//! 管理コンソールのハンドラ（A2 の基盤。ADR-0006）。
//!
//! 本エンドポイント群は `idp.admin` 権限を保有する利用者のみアクセスできる（`RequirePerms<IdpAdmin>`）。
//! 内部認可であり第三者へ公開しない（OpenAPI/Discovery には載せない。ADR-0006 §7）。
//! ログイン/監査ログ一覧（A3）や RP 登録画面（A1）は今後この基盤の上に追加する。

use crate::presentation::admin::{IdpAdmin, RequirePerms};
use axum::response::{IntoResponse, Response};
use axum::Json;
use idp_contracts::admin::WhoamiResponse;

/// 認可済み管理利用者の身元を返す（管理コンソール基盤の疎通確認用）。
/// アクセスできること自体が「有効な SSO セッション ＋ `idp.admin` 保有」を意味する。
/// web の管理コンソールはこれを SSO Cookie 転送で呼び、認証状態と身元を得る（ADR-0007 §4）。
pub async fn whoami(RequirePerms(admin, _): RequirePerms<IdpAdmin>) -> Response {
    Json(WhoamiResponse {
        user_id: admin.user_id.to_string(),
    })
    .into_response()
}
