//! ログイン画面（`GET /login`）とログイン処理（`POST /login`、設計仕様 §4.3）。
//!
//! ADR-0007: web はフォーム描画とリダイレクトのみを担い、資格情報検証・SSO/code 発行は api の
//! `POST /internal/authenticate` に委ねる。web は接続元情報（`X-Forwarded-For` 由来 IP・User-Agent）を
//! 転送し、成功時に api が返す `sso_session_id` を Cookie 化して `redirect_to` へ 302 する。エラーは
//! ローカライズして再描画する。CSRF は `auth_session_id` 由来の同期トークン（`idp-contracts`）で、
//! api の LoginService が検証する。
//!
//! 画面文言は `fluent` の翻訳リソースで管理する（`Accept-Language` で en / ja を切替）。

use super::locale;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::dto::{LoginForm, LoginPageQuery};
use crate::handlers::{form_retry_error_key, forwarded_context, found, portal, see_other};
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, LoginTemplate, MessagePage};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use idp_contracts::auth::{
    InternalAuthenticateRequest, InternalAuthenticateResponse, InternalAuthorizeResumeRequest,
    InternalAuthorizeResumeResponse,
};
use idp_contracts::csrf::login_csrf_token;

/// ログインフォームを表示する。OIDC フローは api の `/authorize` からのハンドオフ
/// （`?auth_session=` の単回ハンドル。ADR-0018 決定 2）または host-only の `auth_session_id`
/// Cookie で継続する。
pub async fn login_page(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<LoginPageQuery>,
) -> Response {
    // ハンドオフ受領: ハンドルを即座に `/internal/authorize/resume` で交換し（SSO 判定を含む）、
    // `auth_session_id` を自ドメインの host-only Cookie へ移して 303 で URL から除去する。
    if let Some(handle) = query.auth_session.filter(|h| !h.is_empty()) {
        return resume_authorize_handoff(&state, &correlation, &tenant, &headers, handle).await;
    }

    // PRG で戻ったときのエラーバナー（CSRF 不一致 → `?error=csrf`）。
    let error_key = form_retry_error_key(query.error.as_deref());

    let Some(auth_session_id) = cookies::get(&headers, cookies::AUTH_SESSION_COOKIE) else {
        // OIDC の `auth_session_id` が無い直接アクセスは、IdP 自身のアカウント画面へ入るための
        // ポータルログインとして扱う（`/{tenant_id}/login` を単独で開けるようにする）。
        // 注: `Messages`（FluentBundle）は !Send のため、await をまたぐ前に生成してはならない。
        return portal::login_page(&state, &tenant, &headers, error_key).await;
    };
    let messages = Messages::new(locale(&headers));
    Html(render_form(
        &messages,
        &tenant.prefix(),
        &login_csrf_token(&auth_session_id, state.config.csrf_secret()),
        error_key,
    ))
    .into_response()
}

/// `/authorize` ハンドオフの再開（ADR-0018 決定 2）。web が自ドメインの `sso_session_id` を読み、
/// 単回ハンドルとともに api へ渡す。SSO 有効なら code 付き RP URL が返り、ログイン画面を出さずに
/// フローが完了する（従来 api が Cookie で行っていた SSO 復元と同じ振る舞い）。
async fn resume_authorize_handoff(
    state: &WebState,
    correlation: &CorrelationId,
    tenant: &WebTenant,
    headers: &HeaderMap,
    handle: String,
) -> Response {
    let ctx = forwarded_context(headers, correlation);
    let sso_session_id = cookies::get(headers, cookies::SSO_SESSION_COOKIE);
    let request = InternalAuthorizeResumeRequest {
        tenant_id: Some(tenant.0.clone()),
        handle,
        sso_session_id: sso_session_id.clone(),
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let outcome = match state
        .api
        .authorize_resume(&ctx.correlation_id, &request)
        .await
    {
        Ok(outcome) => outcome,
        Err(e) => {
            tracing::error!(error = %e, "authorize resume call to api failed");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    // SSO 復元に成功した応答では、手元の `sso_session_id` を host-only で再発行する。
    // `COOKIE_DOMAIN`（旧 ADR-0012 構成の掃除）設定中は旧 `Domain` 付き Cookie の削除が併送される
    // ため、明示的なログイン・ログアウトを経ない既存セッションもサイレント復元の時点で host-only へ
    // 移行し、旧親ドメイン配下へ bearer credential が送信され続ける露出を閉じる（ADR-0018 決定 4）。
    let refresh_sso =
        |set_cookies: crate::cookies::SetCookies, ttl_secs: u64| match sso_session_id.as_deref() {
            Some(sso) => set_cookies.set_session(cookies::SSO_SESSION_COOKIE, sso, ttl_secs),
            None => set_cookies,
        };

    let messages = Messages::new(locale(headers));
    let auth_session_ttl = state.config.auth_session_ttl_secs();
    match outcome {
        // SSO 復元で code 発行済み。残っている古い auth_session Cookie を掃除して RP へ返す。
        InternalAuthorizeResumeResponse::Redirect {
            redirect_to,
            sso_absolute_ttl_secs,
        } => (
            refresh_sso(
                state
                    .set_cookies()
                    .expire_session(cookies::AUTH_SESSION_COOKIE),
                sso_absolute_ttl_secs,
            )
            .into_headers(),
            found(&redirect_to),
        )
            .into_response(),
        // フロー終了のエラー（prompt=none 失敗等）。RP へエラーを返す。
        InternalAuthorizeResumeResponse::ErrorRedirect { redirect_to } => (
            state
                .set_cookies()
                .expire_session(cookies::AUTH_SESSION_COOKIE)
                .into_headers(),
            found(&redirect_to),
        )
            .into_response(),
        InternalAuthorizeResumeResponse::ConsentRequired {
            auth_session_id,
            sso_absolute_ttl_secs,
        } => (
            refresh_sso(
                state.set_cookies().set_session(
                    cookies::AUTH_SESSION_COOKIE,
                    &auth_session_id,
                    auth_session_ttl,
                ),
                sso_absolute_ttl_secs,
            )
            .into_headers(),
            see_other(&format!("{}/consent", tenant.prefix())),
        )
            .into_response(),
        InternalAuthorizeResumeResponse::LoginRequired { auth_session_id } => (
            state
                .set_cookies()
                .set_session(
                    cookies::AUTH_SESSION_COOKIE,
                    &auth_session_id,
                    auth_session_ttl,
                )
                .into_headers(),
            // 303 で自 URL へ付け替え、ハンドルをアドレスバー・履歴から除去する。
            see_other(&format!("{}/login", tenant.prefix())),
        )
            .into_response(),
        InternalAuthorizeResumeResponse::ExpiredHandle => {
            // リロード等で消費済みのハンドル。初回受領時の Cookie が残っていれば通常表示へ戻す。
            if cookies::get(headers, cookies::AUTH_SESSION_COOKIE).is_some() {
                see_other(&format!("{}/login", tenant.prefix()))
            } else {
                error_page(
                    &messages,
                    StatusCode::BAD_REQUEST,
                    "login-error-session-expired",
                )
            }
        }
        InternalAuthorizeResumeResponse::Internal => {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// ログインフォームの HTML をテンプレートから描画する。埋め込む値（翻訳文言・CSRF トークン）は
/// テンプレート側で自動 HTML エスケープされる。
fn render_form(
    messages: &Messages,
    tenant_prefix: &str,
    csrf: &str,
    error_key: Option<&str>,
) -> String {
    render(&LoginTemplate {
        messages,
        tenant_prefix,
        csrf,
        error_key,
    })
}

/// ログインを実行する。api の内部認証を呼び、成功時は SSO Cookie を発行して `redirect_to` へ 302 する。
pub async fn login(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let ctx = forwarded_context(&headers, &correlation);
    let auth_session_id = cookies::get(&headers, cookies::AUTH_SESSION_COOKIE);

    // OIDC の `auth_session_id` を持たない POST はポータルログイン（クライアント非依存）として処理する。
    if auth_session_id.is_none() {
        return portal::login(&state, &correlation, &tenant, &headers, form).await;
    }

    let request = InternalAuthenticateRequest {
        tenant_id: Some(tenant.0.clone()),
        auth_session_id: auth_session_id.clone(),
        username: form.username,
        password: form.password,
        csrf_token: form.csrf_token,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };

    let outcome = match state.api.authenticate(&ctx.correlation_id, &request).await {
        Ok(outcome) => outcome,
        Err(e) => {
            tracing::error!(error = %e, "internal authenticate call to api failed");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    // FluentBundle は Send でないため、await をまたがないようここで生成する。
    let messages = Messages::new(locale(&headers));
    match outcome {
        InternalAuthenticateResponse::Success {
            redirect_to,
            sso_session_id,
            sso_absolute_ttl_secs,
            user_language,
        } => {
            // SSO Cookie を発行し、短命の auth_session_id Cookie は失効させる。
            let mut set_cookies = state
                .set_cookies()
                .set_session(
                    cookies::SSO_SESSION_COOKIE,
                    &sso_session_id,
                    sso_absolute_ttl_secs,
                )
                .expire_session(cookies::AUTH_SESSION_COOKIE);
            // ユーザーの DB 言語設定があれば lang Cookie に同期する（MT20: DB > Cookie の優先順）。
            if let Some(lang) = user_language
                .as_deref()
                .and_then(crate::i18n::Locale::from_tag)
            {
                set_cookies = set_cookies.set_local(
                    cookies::LANG_COOKIE,
                    lang.as_tag(),
                    cookies::LANG_COOKIE_MAX_AGE_SECS,
                );
            }
            (set_cookies.into_headers(), found(&redirect_to)).into_response()
        }
        InternalAuthenticateResponse::MfaRequired { auth_session_id } => {
            // パスワード認証成功・MFA 必要: auth_session_id Cookie を維持して TOTP 入力画面へ。
            let set_cookies = state.set_cookies().set_session(
                cookies::AUTH_SESSION_COOKIE,
                &auth_session_id,
                state.config.auth_session_ttl_secs(),
            );
            (
                set_cookies.into_headers(),
                found(&format!("{}/mfa/totp", tenant.prefix())),
            )
                .into_response()
        }
        InternalAuthenticateResponse::PasswordChangeRequired { auth_session_id } => {
            // パスワード認証成功・強制変更必要（ADR-0009 §5）: auth_session_id Cookie を維持して
            // パスワード変更画面へ。
            let set_cookies = state.set_cookies().set_session(
                cookies::AUTH_SESSION_COOKIE,
                &auth_session_id,
                state.config.auth_session_ttl_secs(),
            );
            (
                set_cookies.into_headers(),
                found(&format!("{}/password-change", tenant.prefix())),
            )
                .into_response()
        }
        InternalAuthenticateResponse::SessionExpired => {
            // 期限切れ・不正な auth_session_id はここでクリアして `/login` へ戻す。Cookie が無くなれば
            // 次の GET はポータルログイン（クライアント非依存）を表示するため、放置された OIDC セッション
            // Cookie が残ってもエンドユーザーが自分のアカウント画面へ入れなくなる状態を自己回復する。
            tracing::warn!(
                correlation_id = %ctx.correlation_id,
                "login failed: auth session expired; clearing cookie and redirecting to /login"
            );
            let set_cookies = state
                .set_cookies()
                .expire_session(cookies::AUTH_SESSION_COOKIE);
            (
                set_cookies.into_headers(),
                found(&format!("{}/login", tenant.prefix())),
            )
                .into_response()
        }
        InternalAuthenticateResponse::CsrfMismatch => {
            // PRG: 303 で GET へ付け替え、現在の Cookie から導出した新しいトークンのフォームを自動で
            // 再表示する（従来はエラーページを返すだけで、リロードすると POST が再送されて復帰できなかった）。
            tracing::warn!(
                correlation_id = %ctx.correlation_id,
                "login failed: csrf token mismatch; redirecting to fresh login form"
            );
            see_other(&format!("{}/login?error=csrf", tenant.prefix()))
        }
        InternalAuthenticateResponse::RateLimited => error_page(
            &messages,
            StatusCode::TOO_MANY_REQUESTS,
            "login-error-rate-limited",
        ),
        InternalAuthenticateResponse::InvalidCredentials => reshow_form(
            &messages,
            &tenant.prefix(),
            StatusCode::UNAUTHORIZED,
            auth_session_id.as_deref(),
            "login-error-invalid-credentials",
            state.config.csrf_secret(),
        ),
        InternalAuthenticateResponse::Locked => reshow_form(
            &messages,
            &tenant.prefix(),
            StatusCode::FORBIDDEN,
            auth_session_id.as_deref(),
            "login-error-locked",
            state.config.csrf_secret(),
        ),
        // 自己登録アカウントのメール未検証（SEC6b）。確認リンクを踏むよう案内する。
        InternalAuthenticateResponse::EmailVerificationRequired => error_page(
            &messages,
            StatusCode::FORBIDDEN,
            "login-error-email-not-verified",
        ),
        // 認証ポリシーによる拒否。資格情報は検証済みのため、資格情報エラーとは別の文言で表示する。
        InternalAuthenticateResponse::PolicyDenied => reshow_form(
            &messages,
            &tenant.prefix(),
            StatusCode::FORBIDDEN,
            auth_session_id.as_deref(),
            "login-error-policy-denied",
            state.config.csrf_secret(),
        ),
        // ポリシーが MFA 必須だが認証器（TOTP）が未設定。ポータルで設定するよう案内する。
        InternalAuthenticateResponse::MfaEnrollmentRequired => error_page(
            &messages,
            StatusCode::FORBIDDEN,
            "login-error-mfa-enrollment-required",
        ),
        InternalAuthenticateResponse::ConsentRequired {
            auth_session_id: new_auth_session_id,
            sso_session_id,
            sso_absolute_ttl_secs,
        } => {
            // SSO Cookie を発行し、同意画面用の auth_session_id Cookie を設定する。
            // auth_session_id はまだ有効（同意画面で使う）ので期限をそのまま保持する。
            // 具体的な TTL は api 側で設定済みのため、ここでは既存の Cookie を上書きする。
            let set_cookies = state
                .set_cookies()
                .set_session(
                    cookies::SSO_SESSION_COOKIE,
                    &sso_session_id,
                    sso_absolute_ttl_secs,
                )
                .set_session(
                    cookies::AUTH_SESSION_COOKIE,
                    &new_auth_session_id,
                    state.config.auth_session_ttl_secs(),
                );
            (
                set_cookies.into_headers(),
                found(&format!("{}/consent", tenant.prefix())),
            )
                .into_response()
        }
        InternalAuthenticateResponse::Internal => {
            (StatusCode::INTERNAL_SERVER_ERROR, Html(String::new())).into_response()
        }
    }
}

/// エラー付きでフォームを再表示する（AuthSession はまだ有効なため再入力できる）。
fn reshow_form(
    messages: &Messages,
    tenant_prefix: &str,
    status: StatusCode,
    auth_session_id: Option<&str>,
    error_key: &str,
    csrf_secret: &[u8],
) -> Response {
    match auth_session_id {
        Some(id) => (
            status,
            Html(render_form(
                messages,
                tenant_prefix,
                &login_csrf_token(id, csrf_secret),
                Some(error_key),
            )),
        )
            .into_response(),
        None => error_page(
            messages,
            StatusCode::BAD_REQUEST,
            "login-error-session-expired",
        ),
    }
}

fn error_page(messages: &Messages, status: StatusCode, error_key: &str) -> Response {
    let body = render(&MessagePage {
        title: messages.get("login-title"),
        message: messages.get(error_key),
    });
    (status, Html(body)).into_response()
}
