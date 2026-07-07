//! 管理機能の認可 extractor（ADR-0006 §5、CLAUDE.md「権限管理」）。
//!
//! `RequirePerms<P>` はハンドラ引数に置くことで、SSO セッションから利用者を解決し、型パラメータ `P`
//! が表す**権限コード**を保有するかを検証する。判定そのものは Application 層（[`AdminAccessService`]）
//! が行い、本 extractor は結果を HTTP へ写すだけ（Presentation には可否のみが渡る）。
//!
//! 権限コードは文字列ではなく型（マーカ）で指定する。CLAUDE.md「動的呼び出しの制限」に従い、
//! 文字列で権限を渡して実行時解決する方式を避け、コンパイル時に確定させる。
//!
//! ADR-0007 で HTML 画面は web crate へ移設したため、api の管理 API は JSON の 401/403 を返す
//! [`RequirePerms`] のみを持つ（画面向けの誘導は web が行う）。
//!
//! ```ignore
//! async fn admin_api(RequirePerms(admin, _): RequirePerms<IdpAdmin>) -> impl IntoResponse { ... }
//! ```

use crate::application::admin_access::{AdminAccess, AuthorizedAdmin};
use crate::presentation::cookies;
use crate::presentation::state::AppState;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use std::marker::PhantomData;

/// 保護対象が要求する権限コードを型として表すマーカ。
///
/// 新しい権限で保護する場合はマーカ型を追加する（許可値そのものの単一出所は `permissions`
/// マスタテーブル。ここではそのうち「保護に使う」コードを型として束ねる）。
pub trait RequiredPermission {
    const CODE: &'static str;
}

/// 管理 API 全体（MVP-admin）を保護する権限コード `idp.admin`。
pub struct IdpAdmin;

impl RequiredPermission for IdpAdmin {
    const CODE: &'static str = "idp.admin";
}

/// 権限 `P` を保有する認可済み管理利用者を表す extractor。
///
/// 抽出に成功した時点で「有効な SSO セッションを持つ・アカウントが有効・`P::CODE` を保有」が保証される。
/// 拒否時は JSON の 401/403 を返す（画面向けのログイン誘導は web が担う。ADR-0007）。
pub struct RequirePerms<P: RequiredPermission>(pub AuthorizedAdmin, pub PhantomData<P>);

impl<P> FromRequestParts<AppState> for RequirePerms<P>
where
    P: RequiredPermission,
{
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let sso_session_id = cookies::get(&parts.headers, cookies::SSO_SESSION_COOKIE);
        match state
            .admin_access
            .authorize(sso_session_id.as_deref(), P::CODE)
            .await
        {
            AdminAccess::Granted(admin) => Ok(RequirePerms(admin, PhantomData)),
            AdminAccess::Unauthenticated => Err(error_response(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "authentication required",
            )),
            AdminAccess::Forbidden => Err(error_response(
                StatusCode::FORBIDDEN,
                "forbidden",
                "insufficient permission",
            )),
        }
    }
}

fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    (status, Json(json!({ "error": code, "message": message }))).into_response()
}
