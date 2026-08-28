//! 進行中の認可要求がログイン画面へ持ち込む文脈（`login_hint` / `ui_locales`。G12）。
//!
//! `/authorize` が受け取ったこれらのパラメータは api の auth_session に保存されるが、web は
//! resume の 303（単回ハンドルを URL から外す付け替え）で状態を落とすため、画面を描くときには
//! 手元に無い。ここで **host-only `auth_session_id` Cookie を持つリクエストに限り** api の
//! `/internal/authorize/login-context` から取り直し、`Extension` で下流へ渡す。
//!
//! middleware に置くのは、消費者が 2 つに分かれるためである。`ui_locales` は表示言語の決定
//! （[`crate::display_preferences`]）が、`login_hint` と表示名（クライアント名・テナント名）はログイン画面の
//! ハンドラが使う。ハンドラ側で取ると、言語決定より後になって「画面は英語、文言は日本語」のような
//! 食い違いが起きるか、同じ文脈を 2 度取りに行くことになる。取得は 1 回にし、決定順の判断は
//! [`crate::display_preferences`] に残す。
//!
//! 費用は **OIDC フロー中の画面表示ごとに api への 1 リクエスト**（ローカルホップ）。
//! `auth_session_id` Cookie はログイン・同意・MFA・強制パスワード変更の間しか存在しないため、
//! 管理コンソールやポータルの画面には増分が無い。取得失敗は画面を落とさない（文脈なしで描く）。

use crate::cookies;
use crate::correlation::CorrelationId;
use crate::state::WebState;
use crate::tenant::WebTenant;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use idp_contracts::auth::{
    InternalAuthorizeLoginContextRequest, InternalAuthorizeLoginContextResponse,
};

/// 進行中の認可要求が持ち込んだ表示ヒント。`Extension` で下流のハンドラ・middleware へ渡す。
///
/// `login_hint` は **RP が指定した任意の文字列**で、実在するアカウントを意味しない。
/// 画面に出す値であり、認証・認可の判断には使わない。
#[derive(Debug, Clone, Default)]
pub struct RpLoginContext {
    pub login_hint: Option<String>,
    pub ui_locales: Option<String>,
    /// 進行中の認可要求の `redirect_uri`。ログイン画面の CSP `form-action` に許可するオリジンの
    /// 出所（`security_headers::csp_allowing_form_action`）。OIDC フロー外では `None`。
    pub redirect_uri: Option<String>,
    /// 認可要求を出したクライアントの表示名（api が登録済みの `Clients.app_name` から引いた値。
    /// **RP の申告ではない**）。ログイン画面の見出しに出し、どのアプリへ入るのかを示す。
    pub client_name: Option<String>,
    /// フローのテナントの表示名。ログイン画面のナビバーに出し、どの組織のアカウントで入るのかを示す。
    pub tenant_name: Option<String>,
}

/// `auth_session_id` Cookie があれば認可要求の文脈を取り直して `Extension` へ載せる middleware。
///
/// [`crate::tenant::capture_tenant`] より内側・[`crate::display_preferences::resolve_display_preferences`] より外側に
/// 置く（テナントが要り、言語決定が結果を読むため）。
/// 文脈が無い（OIDC フロー外・取得失敗）ときも空の値を載せる。下流は常に
/// `Extension<RpLoginContext>` で受け取れる。
pub async fn load_rp_login_context(
    State(state): State<WebState>,
    mut request: Request,
    next: Next,
) -> Response {
    // リクエストへの参照は await をまたげない（`axum::body::Body` が `Sync` でないため
    // `&Request` が `Send` にならない）。必要な値だけ先に取り出す。
    let identifiers = cookies::get(request.headers(), cookies::AUTH_SESSION_COOKIE).zip(
        request
            .extensions()
            .get::<WebTenant>()
            .map(|tenant| tenant.0.clone()),
    );
    let correlation_id = request
        .extensions()
        .get::<CorrelationId>()
        .map(|c| c.0.clone())
        .unwrap_or_default();

    let context = match identifiers {
        Some((auth_session_id, tenant_id)) => {
            fetch(&state, &correlation_id, tenant_id, auth_session_id).await
        }
        // OIDC フロー外（`auth_session_id` Cookie が無い）。api は呼ばない。
        None => None,
    };
    request.extensions_mut().insert(context.unwrap_or_default());
    next.run(request).await
}

/// 文脈を取得する。取得失敗・期限切れは `None`。
async fn fetch(
    state: &WebState,
    correlation_id: &str,
    tenant_id: String,
    auth_session_id: String,
) -> Option<RpLoginContext> {
    let req = InternalAuthorizeLoginContextRequest {
        tenant_id: Some(tenant_id),
        auth_session_id,
    };
    match state
        .api
        .authorize_login_context(correlation_id, &req)
        .await
    {
        Ok(InternalAuthorizeLoginContextResponse::Ok {
            login_hint,
            ui_locales,
            redirect_uri,
            client_name,
            tenant_name,
        }) => Some(RpLoginContext {
            login_hint,
            ui_locales,
            redirect_uri,
            client_name,
            tenant_name,
        }),
        // 期限切れの Cookie が残っているだけ。文脈なしで描き、失効はハンドラ側の経路に任せる。
        Ok(InternalAuthorizeLoginContextResponse::SessionExpired) => None,
        // 文脈なしで描き続けるのは意図した挙動だが、**代償が login_hint の欠落だけではなくなった**。
        // `redirect_uri` が取れないとログイン画面の CSP に RP のオリジンを足せず、ログイン成功後の
        // RP への遷移がブラウザに遮断される（SEC3）。画面にもサーバログにも異常が出ない止まり方に
        // なるので、ここで結果まで名指しして記録する。
        Ok(InternalAuthorizeLoginContextResponse::Internal) => {
            tracing::warn!(
                consequence = "login page falls back to the default CSP; the redirect to the RP will be blocked",
                "api could not read the authorization request context"
            );
            None
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                consequence = "login page falls back to the default CSP; the redirect to the RP will be blocked",
                "could not read the authorization request context"
            );
            None
        }
    }
}
