//! 管理機能の認可 extractor（ADR-0006 §5、CLAUDE.md「権限管理」）。
//!
//! `RequirePerms<P>` はハンドラ引数に置くことで、SSO セッションから利用者を解決し、型パラメータ `P`
//! が表す**権限コード**を保有するかを検証する。判定そのものは Application 層（[`AdminAccessService`]）
//! が行い、本 extractor は結果を HTTP へ写すだけ（Presentation には可否のみが渡る）。
//!
//! 権限コードは文字列ではなく型（マーカ）で指定する。CLAUDE.md「動的呼び出しの制限」に従い、
//! 文字列で権限を渡して実行時解決する方式を避け、コンパイル時に確定させる。
//!
//! ```ignore
//! async fn admin_page(RequirePerms(admin, _): RequirePerms<IdpAdmin>) -> impl IntoResponse { ... }
//! ```

use crate::application::admin_access::{AdminAccess, AuthorizedAdmin};
use crate::presentation::cookies;
use crate::presentation::i18n::{Locale, Messages};
use crate::presentation::state::AppState;
use axum::extract::FromRequestParts;
use axum::http::header::LOCATION;
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use serde_json::json;
use std::marker::PhantomData;

/// ブラウザ向け管理コンソールのベースパス。JSON 管理 API（`/admin/<resource>`、OpenAPI の正典）とは
/// 経路を分離し、`/admin/console/<画面>` 配下に置く（認可も HTML 用 [`AdminHtmlSession`] と API 用
/// [`RequirePerms`] で使い分ける）。
pub const CONSOLE_BASE_PATH: &str = "/admin/console";
/// 管理コンソールのホーム。
pub const CONSOLE_HOME_PATH: &str = CONSOLE_BASE_PATH;
/// 管理コンソールのログイン画面パス（未認証時の誘導先）。
pub const ADMIN_LOGIN_PATH: &str = "/admin/console/login";
/// 管理コンソールのログアウトパス。
pub const CONSOLE_LOGOUT_PATH: &str = "/admin/console/logout";

/// 保護対象が要求する権限コードを型として表すマーカ。
///
/// 新しい権限で保護する場合はマーカ型を追加する（許可値そのものの単一出所は `permissions`
/// マスタテーブル。ここではそのうち「保護に使う」コードを型として束ねる）。
pub trait RequiredPermission {
    const CODE: &'static str;
}

/// 管理コンソール全体（MVP-admin）を保護する権限コード `idp.admin`。
pub struct IdpAdmin;

impl RequiredPermission for IdpAdmin {
    const CODE: &'static str = "idp.admin";
}

/// 権限 `P` を保有する認可済み管理利用者を表す extractor。
///
/// 抽出に成功した時点で「有効な SSO セッションを持つ・アカウントが有効・`P::CODE` を保有」が保証される。
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
            // 未ログイン・期限切れ等。管理画面（A2）実装時にログイン誘導へ差し替え得る。
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

/// 管理コンソール**画面**（HTML）向けの `idp.admin` 認可 extractor。
///
/// 判定は [`RequirePerms`] と同じ [`AdminAccessService`] で行うが、拒否時の写し方が異なる。
/// API 用の [`RequirePerms`] は JSON の 401/403 を返すのに対し、本 extractor は
/// **未認証ならログイン画面へ 302**（ブラウザの導線）、**権限不足なら 403 の HTML** を返す。
pub struct AdminHtmlSession(pub AuthorizedAdmin);

impl FromRequestParts<AppState> for AdminHtmlSession {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let sso_session_id = cookies::get(&parts.headers, cookies::SSO_SESSION_COOKIE);
        match state
            .admin_access
            .authorize(sso_session_id.as_deref(), IdpAdmin::CODE)
            .await
        {
            AdminAccess::Granted(admin) => Ok(AdminHtmlSession(admin)),
            // 未ログイン・期限切れ等 → ログイン画面へ誘導する。
            AdminAccess::Unauthenticated => Err(redirect_to_login()),
            AdminAccess::Forbidden => Err(forbidden_page(&parts.headers)),
        }
    }
}

/// ログイン画面（`/admin/login`）への 302 リダイレクト。
pub fn redirect_to_login() -> Response {
    (StatusCode::FOUND, [(LOCATION, ADMIN_LOGIN_PATH)]).into_response()
}

/// 権限不足を伝える最小限の HTML ページ（403）。
fn forbidden_page(headers: &HeaderMap) -> Response {
    let messages = Messages::new(Locale::from_accept_language(
        headers
            .get(axum::http::header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok()),
    ));
    let title = messages.get("admin-forbidden-title");
    let message = messages.get("admin-forbidden-message");
    let body = format!(
        "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\"><title>{title}</title></head>\
         <body><h1>{title}</h1><p>{message}</p></body></html>"
    );
    (StatusCode::FORBIDDEN, Html(body)).into_response()
}
