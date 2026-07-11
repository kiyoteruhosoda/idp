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
//! [`RequirePerms`] を持つ（画面向けの誘導は web が行う）。権限を要求せず「ログイン済みであること」
//! だけを要求するフロー（招待の承諾。ADR-0009 §3）には [`AuthenticatedUser`] extractor を用いる。
//!
//! ```ignore
//! async fn admin_api(RequirePerms(admin, _): RequirePerms<IdpAdmin>) -> impl IntoResponse { ... }
//! ```

use crate::application::admin_access::{AdminAccess, AuthorizedAdmin};
use crate::presentation::cookies;
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
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

/// 管理 API 全体（MVP-admin）を保護する権限コード `idp.tenant.admin`（ADR-0009 §4）。
///
/// 判定は「要求テナントを scope に持つか」の完全一致で行う（`AdminAccessService`）。
/// `idp.system.admin`（scope = root のみ）は root テナント自身の管理を含むため、
/// 判定側で常に代替として許可される。
pub struct IdpAdmin;

impl RequiredPermission for IdpAdmin {
    const CODE: &'static str = "idp.tenant.admin";
}

/// テナントの作成・削除・更新を保護する権限コード `idp.system.admin`（ADR-0009 §4）。
///
/// `idp.system.admin` は root scope でしか存在できない（DB CHECK ＋アプリ層の二重防御）ため、
/// 要求テナントを scope として保有できるのは root テナントの system 管理者だけになる。判定は
/// `AdminAccessService::authorize` が完全一致で行い、`idp.system.admin` 要求時は代替フォールバックしない。
pub struct IdpSystemAdmin;

impl RequiredPermission for IdpSystemAdmin {
    const CODE: &'static str = "idp.system.admin";
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
        // 要求テナントはパス由来の `ResolvedTenant`（`resolve_tenant` middleware が注入。ADR-0009 §7）。
        // 権限判定は「要求テナントを scope に持つか」の完全一致（§4）。middleware 未通過は配線ミス。
        let Some(resolved) = parts.extensions.get::<ResolvedTenant>() else {
            tracing::error!("RequirePerms used on a route without the tenant resolver middleware");
            return Err(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "tenant context missing",
            ));
        };
        match state
            .admin_access
            .authorize(resolved.context(), sso_session_id.as_deref(), P::CODE)
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

/// ログイン済み利用者（権限は問わない）を表す extractor。
///
/// SSO セッション Cookie から利用者を解決できた時点で「有効な SSO セッションを持つ・アカウントが有効」が
/// 保証される。テナント権限を要求しないフロー（招待の承諾。ADR-0009 §3）で使う。抽出できなければ 401。
pub struct AuthenticatedUser(pub uuid::Uuid);

impl FromRequestParts<AppState> for AuthenticatedUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let sso_session_id = cookies::get(&parts.headers, cookies::SSO_SESSION_COOKIE);
        match state
            .admin_access
            .authenticated_user(sso_session_id.as_deref())
            .await
        {
            Some(user_id) => Ok(AuthenticatedUser(user_id)),
            None => Err(error_response(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "authentication required",
            )),
        }
    }
}

fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    (status, Json(json!({ "error": code, "message": message }))).into_response()
}
