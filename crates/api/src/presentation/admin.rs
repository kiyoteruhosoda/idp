//! 管理機能の認可 extractor（ADR-0006 §5 / ADR-0037、CLAUDE.md「権限管理」）。
//!
//! `RequirePerms<P>` はハンドラ引数に置くことで、**管理アクセストークン**（`Authorization: Bearer`）
//! を検証し、型パラメータ `P` が表す**権限コード**を満たすかを判定する。判定そのものは Application 層
//! （[`ManagementTokenService`]）が行い、本 extractor は結果を HTTP へ写すだけ（Presentation には
//! 可否のみが渡る）。
//!
//! 権限コードは文字列ではなく型（マーカ）で指定する。CLAUDE.md「動的呼び出しの制限」に従い、
//! 文字列で権限を渡して実行時解決する方式を避け、コンパイル時に確定させる。マーカと文字列の
//! 対応は本モジュールの [`permission_markers!`] が一度だけ書く。
//!
//! ## 資格情報はトークンだけ（ADR-0037）
//!
//! 以前は web が転送した SSO セッション Cookie を資格情報にしていた。Cookie は ambient（ブラウザが
//! 自動で付ける）なので api 側にもオリジン検証（CSRF 対策）が必要だったが、Bearer は ambient では
//! ないため、**管理面から CSRF の論点そのものが消える**。管理コンソール（web）は SSO セッションを
//! `POST /internal/admin/token` で管理トークンへ交換してから api を呼ぶ。ブラウザ経路の CSRF は
//! web が同期トークンで閉じて扱う（`assay_web::csrf`）。
//!
//! 権限を要求せず「ログイン済みであること」だけを要求するフロー（招待の承諾。ADR-0009 §3）には
//! [`AuthenticatedUser`] extractor を用いる。こちらはブラウザの Cookie を直接読むため、
//! オリジン検証を従来どおり残す。
//!
//! ```ignore
//! async fn admin_api(RequirePerms(admin, _): RequirePerms<UsersRead>) -> impl IntoResponse { ... }
//! ```

use crate::application::management_token::{AuthorizedPrincipal, ManagementAccess};
use crate::domain::permission;
use crate::presentation::i18n::{ApiLocale, ApiMessages};
use crate::presentation::origin;
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use std::marker::PhantomData;

/// 保護対象が要求する権限コードを型として表すマーカ。
///
/// 新しい権限で保護する場合はマーカ型を追加する（許可値そのものの単一出所は `permissions`
/// マスタテーブル、含意関係の単一出所は `domain::permission`。ここではそのうち「保護に使う」
/// コードを型として束ねる）。
pub trait RequiredPermission {
    const CODE: &'static str;
}

/// 権限コードのマーカ型をまとめて定義する。
///
/// マクロにするのは、マーカ型と権限コード文字列の対応を**1 行 1 対応**で並べるためである。
/// 型ごとに `struct` と `impl` を手書きすると、対応表が 20 個以上の宣言に散らばって
/// 「どの型がどのコードか」を一望できなくなる。
macro_rules! permission_markers {
    ($($(#[$doc:meta])* $name:ident => $code:path;)*) => {
        $(
            $(#[$doc])*
            pub struct $name;
            impl RequiredPermission for $name {
                const CODE: &'static str = $code;
            }
        )*
    };
}

permission_markers! {
    /// 管理コンソール全体（テナント管理者。ADR-0009 §4）。細粒度コードをすべて含意する。
    IdpAdmin => permission::TENANT_ADMIN;
    /// システム管理（scope = root のみ）。テナントの作成・削除、システム設定、再起動、
    /// テナント横断のログ参照。**細粒度コードへは分割しない**（ADR-0037）。
    IdpSystemAdmin => permission::SYSTEM_ADMIN;

    /// 利用者の参照・検索。
    UsersRead => permission::USERS_READ;
    /// 利用者の作成・更新・削除・パスワード再発行・MFA 解除・ロック解除・ログイン識別子。
    UsersWrite => permission::USERS_WRITE;
    /// クライアント（RP）の参照。
    ClientsRead => permission::CLIENTS_READ;
    /// クライアント（RP）の作成・更新・削除・secret 再発行・権限付与。
    ClientsWrite => permission::CLIENTS_WRITE;
    /// テナントメンバーの参照。
    MembersRead => permission::MEMBERS_READ;
    /// メンバーの招待・一時停止・解除。
    MembersWrite => permission::MEMBERS_WRITE;
    /// 権限付与状況の参照。
    PermissionsRead => permission::PERMISSIONS_READ;
    /// 権限の付与・剥奪。
    PermissionsWrite => permission::PERMISSIONS_WRITE;
    /// 監査ログの参照。
    AuditRead => permission::AUDIT_READ;
    /// 署名鍵の参照。
    KeysRead => permission::KEYS_READ;
    /// 署名鍵の生成・retire・削除。
    KeysWrite => permission::KEYS_WRITE;
    /// 要求テナント自身の設定の参照。
    TenantSettingsRead => permission::TENANT_SETTINGS_READ;
    /// 要求テナント自身の設定の変更。
    TenantSettingsWrite => permission::TENANT_SETTINGS_WRITE;
    /// 認証ポリシーの参照。
    AuthenticationPoliciesRead => permission::AUTHENTICATION_POLICIES_READ;
    /// 認証ポリシーの作成・更新・削除。
    AuthenticationPoliciesWrite => permission::AUTHENTICATION_POLICIES_WRITE;
    /// 外部 IdP 設定の参照。
    ExternalIdpsRead => permission::EXTERNAL_IDPS_READ;
    /// 外部 IdP 設定の登録・更新・削除。
    ExternalIdpsWrite => permission::EXTERNAL_IDPS_WRITE;
    /// SAML SP の参照。
    SamlServiceProvidersRead => permission::SAML_SERVICE_PROVIDERS_READ;
    /// SAML SP の登録・更新・削除。
    SamlServiceProvidersWrite => permission::SAML_SERVICE_PROVIDERS_WRITE;
}

/// 権限 `P` を満たす認可済み管理主体を表す extractor。
///
/// 抽出に成功した時点で「有効な管理トークンを提示した・主体がまだ有効・`P::CODE` を満たす」が
/// 保証される。拒否時は JSON の 401/403 を返す（画面向けのログイン誘導は web が担う。ADR-0007）。
pub struct RequirePerms<P: RequiredPermission>(pub AuthorizedPrincipal, pub PhantomData<P>);

impl<P> FromRequestParts<AppState> for RequirePerms<P>
where
    P: RequiredPermission,
{
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // 要求テナントはパス由来の `ResolvedTenant`（`resolve_tenant` middleware が注入。ADR-0009 §7）。
        // トークンの `iss`・`aud` はこのテナントの値と厳密一致すること（他テナントのトークンを弾く）。
        // middleware 未通過は配線ミス。
        let Some(resolved) = parts.extensions.get::<ResolvedTenant>() else {
            tracing::error!("RequirePerms used on a route without the tenant resolver middleware");
            return Err(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "tenant context missing",
            ));
        };
        let token = bearer_token(parts);
        match state
            .management_tokens
            .authorize(resolved.context(), token.as_deref(), P::CODE)
            .await
        {
            ManagementAccess::Granted(principal) => Ok(RequirePerms(principal, PhantomData)),
            ManagementAccess::Unauthenticated => Err(unauthorized(parts)),
            ManagementAccess::Forbidden => Err(error_response(
                StatusCode::FORBIDDEN,
                "forbidden",
                &messages(parts).get("api-permission-insufficient"),
            )),
        }
    }
}

/// `Authorization: Bearer <token>` を取り出す（スキーム名は大小無視。RFC 6750 §2.1）。
fn bearer_token(parts: &Parts) -> Option<String> {
    let raw = parts.headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, value) = raw.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("Bearer")
        .then(|| value.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// ログイン済み利用者（権限は問わない）を表す extractor。
///
/// SSO セッション Cookie から利用者を解決できた時点で「有効な SSO セッションを持つ・アカウントが有効」が
/// 保証される。テナント権限を要求しないフロー（招待の承諾。ADR-0009 §3）で使う。抽出できなければ 401。
///
/// 管理 API と違い Cookie を直接資格情報にするため、オリジン検証（SEC4）を残す。
pub struct AuthenticatedUser(pub uuid::Uuid);

impl FromRequestParts<AppState> for AuthenticatedUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        if !origin::is_allowed(parts, &state.config) {
            return Err(forbidden_origin(parts));
        }
        let sso_session_id = crate::presentation::cookies::get(
            &parts.headers,
            crate::presentation::cookies::SSO_SESSION_COOKIE,
        );
        match state
            .admin_access
            .authenticated_user(sso_session_id.as_deref())
            .await
        {
            Some(user_id) => Ok(AuthenticatedUser(user_id)),
            None => Err(unauthorized(parts)),
        }
    }
}

fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    (status, Json(json!({ "error": code, "message": message }))).into_response()
}

/// 401（RFC 6750 §3 に従い `WWW-Authenticate` を添える。管理 API の資格情報は Bearer だけ）。
fn unauthorized(parts: &Parts) -> Response {
    let mut response = error_response(
        StatusCode::UNAUTHORIZED,
        "unauthorized",
        &messages(parts).get("api-authentication-required"),
    );
    response.headers_mut().insert(
        axum::http::header::WWW_AUTHENTICATE,
        axum::http::HeaderValue::from_static("Bearer"),
    );
    response
}

/// 許可外オリジンからの Cookie 認証変更操作（SEC4）。認可の可否は明かさず 403 で落とす。
fn forbidden_origin(parts: &Parts) -> Response {
    tracing::warn!(
        method = %parts.method,
        path = %parts.uri.path(),
        "rejected cookie-authenticated request from a disallowed origin"
    );
    error_response(
        StatusCode::FORBIDDEN,
        "forbidden",
        &messages(parts).get("api-origin-not-allowed"),
    )
}

/// リクエストの `Accept-Language` に従う翻訳辞書（MT19）。extractor の拒否応答（401 / 403）も
/// 利用者に見えるメッセージであり、ハンドラ内のエラーと同じ言語で返す。
fn messages(parts: &Parts) -> ApiMessages {
    let header = parts
        .headers
        .get(axum::http::header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok());
    ApiMessages::new(ApiLocale::from_accept_language(header))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    fn parts_with(header: Option<&str>) -> Parts {
        let mut builder = Request::builder().uri("/t/admin/users");
        if let Some(value) = header {
            builder = builder.header(AUTHORIZATION, value);
        }
        builder.body(()).unwrap().into_parts().0
    }

    #[test]
    fn reads_the_bearer_scheme_case_insensitively() {
        assert_eq!(
            bearer_token(&parts_with(Some("Bearer abc.def.ghi"))).as_deref(),
            Some("abc.def.ghi")
        );
        // RFC 6750 §2.1 の scheme は大小を区別しない。
        assert_eq!(
            bearer_token(&parts_with(Some("bearer abc"))).as_deref(),
            Some("abc")
        );
        assert_eq!(
            bearer_token(&parts_with(Some("BEARER abc"))).as_deref(),
            Some("abc")
        );
    }

    #[test]
    fn rejects_anything_that_is_not_a_bearer_token() {
        // 他方式は読まない（Basic をここで受けると、クライアント認証と管理認可が混ざる）。
        assert_eq!(bearer_token(&parts_with(Some("Basic abc"))), None);
        assert_eq!(bearer_token(&parts_with(None)), None);
        // スキームだけ・値が空は資格情報として扱わない（`Some("")` で 401 の分岐を通さない）。
        assert_eq!(bearer_token(&parts_with(Some("Bearer"))), None);
        assert_eq!(bearer_token(&parts_with(Some("Bearer "))), None);
        assert_eq!(bearer_token(&parts_with(Some("Bearer    "))), None);
    }

    /// マーカ型と権限コードの対応が `domain::permission` の定数と一致していること。
    #[test]
    fn markers_map_to_the_permission_codes_they_are_named_after() {
        assert_eq!(IdpAdmin::CODE, "idp.tenant.admin");
        assert_eq!(IdpSystemAdmin::CODE, "idp.system.admin");
        assert_eq!(UsersRead::CODE, "idp.users:read");
        assert_eq!(UsersWrite::CODE, "idp.users:write");
        assert_eq!(AuditRead::CODE, "idp.audit:read");
        assert_eq!(
            SamlServiceProvidersWrite::CODE,
            "idp.saml-service-providers:write"
        );
    }
}
