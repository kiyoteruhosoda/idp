//! MFA TOTP 自己登録ハンドラ（`GET/POST /account/mfa/totp/*`）と
//! ログインフロー TOTP 入力ハンドラ（`GET/POST /mfa/totp`）。
//!
//! * セットアップ画面（`/account/mfa/totp/setup`）: SSO 認証済みユーザーが TOTP を自己登録する。
//!   QR コード（SVG）と生シークレット（base32）を表示する。QR が使えない場合は生コードを入力する。
//! * ログイン TOTP 画面（`/mfa/totp`）: パスワード認証後に TOTP 入力を求める。

use super::locale;
use crate::client_ip::ClientIp;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::dto::{FormPageQuery, TotpConfirmForm};
use crate::handlers::step_up::{self, MANAGE_AUTHENTICATORS};
use crate::handlers::{form_retry_error_key, forwarded_context, found, see_other};
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, MessagePage, TotpSetupTemplate, TotpVerifyTemplate};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use idp_contracts::auth::{
    InternalTotpConfirmRequest, InternalTotpDeleteRequest, InternalTotpSetupRequest,
    InternalVerifyTotpRequest, InternalVerifyTotpResponse,
};
use idp_contracts::csrf::login_csrf_token;
use serde::Deserialize;

// ── TOTP セットアップ ────────────────────────────────────────────────────────

/// TOTP セットアップ画面（`GET /account/mfa/totp/setup`）。
///
/// SSO Cookie が必要。api から QR URI と生シークレットを取得し、QR SVG + 生コードを表示する。
pub async fn setup_page(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
) -> Response {
    // 認証器の追加は step-up の対象（AP5）。盗まれたセッションで自分の認証器を足されると、
    // 以後は正規の資格情報として振る舞われてしまう。
    if let Err(response) = step_up::require_step_up(
        &state,
        &correlation,
        &tenant,
        &headers,
        MANAGE_AUTHENTICATORS,
        &format!("{}/account/mfa/totp/setup", tenant.prefix()),
    )
    .await
    {
        return response;
    }
    let Some(sso_session_id) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        // FluentBundle は !Send なので await の前に作成・消費する。
        let messages = Messages::new(locale(&headers));
        return error_page(
            &messages,
            StatusCode::UNAUTHORIZED,
            "mfa-error-not-signed-in",
        );
    };

    // ユーザー名は SSO から特定できないため、メールは取得が複雑になる。
    // API に account_name は表示目的のみなので空文字でも機能する。
    let req = InternalTotpSetupRequest {
        sso_session_id: sso_session_id.clone(),
        account_name: String::new(),
    };
    let result = match state.api.totp_setup(&correlation.0, &req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "totp setup call to api failed");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };
    // FluentBundle は !Send なので await の後に作成する。
    let messages = Messages::new(locale(&headers));

    use idp_contracts::auth::InternalTotpSetupResponse;
    match result {
        InternalTotpSetupResponse::Ok {
            totp_uri,
            secret_base32,
        } => {
            let qr_svg = generate_qr_svg(&totp_uri);
            Html(render(&TotpSetupTemplate {
                messages: &messages,
                qr_svg: &qr_svg,
                secret_base32: &secret_base32,
                error_key: None,
            }))
            .into_response()
        }
        InternalTotpSetupResponse::AlreadyConfigured => error_page(
            &messages,
            StatusCode::CONFLICT,
            "mfa-error-already-configured",
        ),
        InternalTotpSetupResponse::SessionExpired => error_page(
            &messages,
            StatusCode::UNAUTHORIZED,
            "mfa-error-session-expired",
        ),
        InternalTotpSetupResponse::Internal => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// TOTP 確認フォーム（`POST /account/mfa/totp/setup`）。6 桁コードを検証して有効化する。
pub async fn setup_confirm(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<TotpConfirmForm>,
) -> Response {
    let Some(sso_session_id) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        let messages = Messages::new(locale(&headers));
        return error_page(
            &messages,
            StatusCode::UNAUTHORIZED,
            "mfa-error-not-signed-in",
        );
    };
    // 認証器を有効化するのはこの POST（画面のゲートだけでは守れない。passkey と同じ理由）。
    if let Err(response) = step_up::require_step_up(
        &state,
        &correlation,
        &tenant,
        &headers,
        MANAGE_AUTHENTICATORS,
        &format!("{}/account/mfa/totp/setup", tenant.prefix()),
    )
    .await
    {
        return response;
    }

    let req = InternalTotpConfirmRequest {
        sso_session_id: sso_session_id.clone(),
        code: form.code.trim().to_string(),
    };
    let result = match state.api.totp_confirm(&correlation.0, &req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "totp confirm call to api failed");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    // InvalidCode の場合は QR を再取得するため先にもう一度 await する（Messages 取得前）。
    use idp_contracts::auth::InternalTotpConfirmResponse;
    let refetch_qr = matches!(result, InternalTotpConfirmResponse::InvalidCode);
    let qr_data = if refetch_qr {
        let setup_req = InternalTotpSetupRequest {
            sso_session_id: sso_session_id.clone(),
            account_name: String::new(),
        };
        state.api.totp_setup(&correlation.0, &setup_req).await.ok()
    } else {
        None
    };

    // FluentBundle は !Send なので全 await の後に作成する。
    let messages = Messages::new(locale(&headers));

    match result {
        InternalTotpConfirmResponse::Ok => {
            let body = render(&MessagePage {
                title: messages.get("mfa-setup-confirmed-title"),
                message: messages.get("mfa-setup-confirmed-message"),
            });
            Html(body).into_response()
        }
        InternalTotpConfirmResponse::InvalidCode => {
            if let Some(idp_contracts::auth::InternalTotpSetupResponse::Ok {
                totp_uri,
                secret_base32,
            }) = qr_data
            {
                let qr_svg = generate_qr_svg(&totp_uri);
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Html(render(&TotpSetupTemplate {
                        messages: &messages,
                        qr_svg: &qr_svg,
                        secret_base32: &secret_base32,
                        error_key: Some("mfa-error-invalid-code"),
                    })),
                )
                    .into_response();
            }
            error_page(
                &messages,
                StatusCode::UNPROCESSABLE_ENTITY,
                "mfa-error-invalid-code",
            )
        }
        InternalTotpConfirmResponse::NotFound | InternalTotpConfirmResponse::SessionExpired => {
            error_page(
                &messages,
                StatusCode::UNAUTHORIZED,
                "mfa-error-session-expired",
            )
        }
        InternalTotpConfirmResponse::AlreadyConfigured => error_page(
            &messages,
            StatusCode::CONFLICT,
            "mfa-error-already-configured",
        ),
        InternalTotpConfirmResponse::Internal => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// TOTP 削除（`POST /account/mfa/totp/delete`）。MFA を無効化する。
pub async fn setup_delete(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
) -> Response {
    // 認証器の削除も step-up の対象（AP5）。MFA を外せれば以後は単一要素で入れてしまう。
    if let Err(response) = step_up::require_step_up(
        &state,
        &correlation,
        &tenant,
        &headers,
        MANAGE_AUTHENTICATORS,
        &format!("{}/settings", tenant.prefix()),
    )
    .await
    {
        return response;
    }
    let Some(sso_session_id) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        let messages = Messages::new(locale(&headers));
        return error_page(
            &messages,
            StatusCode::UNAUTHORIZED,
            "mfa-error-not-signed-in",
        );
    };

    let req = InternalTotpDeleteRequest { sso_session_id };
    let result = match state.api.totp_delete(&correlation.0, &req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "totp delete call to api failed");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };
    // FluentBundle は !Send なので await の後に作成する。
    let messages = Messages::new(locale(&headers));

    use idp_contracts::auth::InternalTotpDeleteResponse;
    match result {
        InternalTotpDeleteResponse::Ok => {
            let body = render(&MessagePage {
                title: messages.get("mfa-deleted-title"),
                message: messages.get("mfa-deleted-message"),
            });
            Html(body).into_response()
        }
        InternalTotpDeleteResponse::SessionExpired => error_page(
            &messages,
            StatusCode::UNAUTHORIZED,
            "mfa-error-session-expired",
        ),
        InternalTotpDeleteResponse::Internal => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

// ── ログインフロー TOTP 入力 ─────────────────────────────────────────────────

/// TOTP 入力ページ（`GET /mfa/totp`）。ログインフロー中（パスワード認証後）に表示する。
/// `?error=csrf` は CSRF 不一致の POST から PRG で戻ったときのエラーバナー表示。
pub async fn verify_page(
    State(state): State<WebState>,
    Extension(tenant): Extension<WebTenant>,
    Query(query): Query<FormPageQuery>,
    headers: HeaderMap,
) -> Response {
    let messages = Messages::new(locale(&headers));
    let Some(auth_session_id) = cookies::get(&headers, cookies::AUTH_SESSION_COOKIE) else {
        return error_page(
            &messages,
            StatusCode::BAD_REQUEST,
            "mfa-error-session-expired",
        );
    };
    Html(render_verify_form(
        &messages,
        &login_csrf_token(&auth_session_id, state.config.csrf_secret()),
        // 送信結果の案内も同じ `?error=` に載せる（PRG のため）。
        verify_banner_key(query.error.as_deref()),
        &tenant.prefix(),
    ))
    .into_response()
}

/// TOTP 入力処理（`POST /mfa/totp`）。コードを検証し、成功時に SSO Cookie を発行してリダイレクトする。
pub async fn verify(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<TotpLoginForm>,
) -> Response {
    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let auth_session_id = cookies::get(&headers, cookies::AUTH_SESSION_COOKIE);

    let req = InternalVerifyTotpRequest {
        tenant_id: Some(tenant.0.clone()),
        auth_session_id: auth_session_id.clone(),
        totp_code: form.totp_code,
        csrf_token: form.csrf_token,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };

    let outcome = match state.api.verify_totp(&ctx.correlation_id, &req).await {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "verify_totp call to api failed");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    let messages = Messages::new(locale(&headers));

    match outcome {
        InternalVerifyTotpResponse::Success {
            redirect_to,
            sso_session_id,
            sso_absolute_ttl_secs,
            user_language,
        } => {
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
        InternalVerifyTotpResponse::ConsentRequired {
            auth_session_id: new_auth_session_id,
            sso_session_id,
            sso_absolute_ttl_secs,
        } => {
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
        InternalVerifyTotpResponse::InvalidCode => reshow_verify_form(
            &messages,
            StatusCode::UNAUTHORIZED,
            auth_session_id.as_deref(),
            "mfa-error-invalid-code",
            state.config.csrf_secret(),
            &tenant.prefix(),
        ),
        // レート制限・ロックはフォームを出しても再試行できないため、案内だけのページにする（SEC3）。
        InternalVerifyTotpResponse::RateLimited => error_page(
            &messages,
            StatusCode::TOO_MANY_REQUESTS,
            "mfa-error-rate-limited",
        ),
        InternalVerifyTotpResponse::Locked => {
            error_page(&messages, StatusCode::FORBIDDEN, "mfa-error-locked")
        }
        InternalVerifyTotpResponse::CsrfMismatch => {
            // PRG: 303 で GET へ付け替え、現在の Cookie から導出した新しいトークンのフォームを自動で
            // 再表示する（従来はエラーページを返すだけで、リロードすると POST が再送されて復帰できなかった）。
            tracing::warn!(
                correlation_id = %ctx.correlation_id,
                "totp verify failed: csrf token mismatch; redirecting to fresh form"
            );
            see_other(&format!("{}/mfa/totp?error=csrf", tenant.prefix()))
        }
        InternalVerifyTotpResponse::SessionExpired => {
            tracing::warn!(
                correlation_id = %ctx.correlation_id,
                "totp verify failed: auth session expired"
            );
            error_page(
                &messages,
                StatusCode::BAD_REQUEST,
                "mfa-error-session-expired",
            )
        }
        InternalVerifyTotpResponse::Internal => {
            (StatusCode::INTERNAL_SERVER_ERROR, Html(String::new())).into_response()
        }
    }
}

// ── QR コード生成 ────────────────────────────────────────────────────────────

/// `otpauth://` URI から QR コードを SVG 文字列として生成する。
/// テンプレートへ直接埋め込む（`|safe` で rawに出力する）。
pub fn generate_qr_svg(uri: &str) -> String {
    use qrcode::render::svg;
    use qrcode::{EcLevel, QrCode};

    let code = match QrCode::with_error_correction_level(uri.as_bytes(), EcLevel::M) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "failed to generate QR code");
            return String::new();
        }
    };
    code.render::<svg::Color<'_>>()
        .min_dimensions(200, 200)
        .build()
}

// ── ヘルパー ────────────────────────────────────────────────────────────────

/// TOTP 入力画面のバナー用に、`?error=` の値を翻訳キーへ写す。
///
/// CSRF・再試行のエラー（`form_retry_error_key`）に加えて、email OTP の送信結果も同じクエリで
/// 運ぶ（PRG のため）。未知の値は何も出さない。
fn verify_banner_key(value: Option<&str>) -> Option<&'static str> {
    match value {
        Some("email-sent") => Some("mfa-verify-email-sent"),
        Some("email-unavailable") => Some("mfa-verify-email-unavailable"),
        Some("session") => Some("mfa-error-session-expired"),
        other => form_retry_error_key(other),
    }
}

fn render_verify_form(
    messages: &Messages,
    csrf: &str,
    error_key: Option<&str>,
    tenant_prefix: &str,
) -> String {
    render(&TotpVerifyTemplate {
        messages,
        csrf,
        error_key,
        // メール送信の可否（SMTP 設定の有無）は api しか知らないため、導線は常に出し、
        // 未設定なら送信結果として案内する（画面から設定状況を推測させない）。
        email_otp_available: true,
        email_otp_action: &format!("{tenant_prefix}/mfa/totp/email-code"),
    })
}

/// email OTP の送信要求（`POST /{tenant_id}/mfa/totp/email-code`。AP9）。
///
/// MFA 待ちの `auth_session_id` を api へ渡し、登録済みメールアドレスへ短命コードを送らせる。
/// 送信の成否は画面のバナーで返し、いずれの場合も TOTP 入力画面に留まる。
pub async fn send_email_code(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<EmailCodeForm>,
) -> Response {
    let messages_locale = locale(&headers);
    let Some(auth_session_id) = cookies::get(&headers, cookies::AUTH_SESSION_COOKIE) else {
        let messages = Messages::new(messages_locale);
        return error_page(
            &messages,
            StatusCode::BAD_REQUEST,
            "mfa-error-session-expired",
        );
    };
    // CSRF は TOTP フォームと同じ同期トークン（`auth_session_id` 由来）で照合する。
    if login_csrf_token(&auth_session_id, state.config.csrf_secret()) != form.csrf_token {
        return see_other(&format!("{}/mfa/totp?error=csrf", tenant.prefix()));
    }

    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let request = idp_contracts::auth::InternalEmailOtpRequest {
        tenant_id: Some(tenant.0.clone()),
        auth_session_id: Some(auth_session_id),
        mfa_ticket: None,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let error = match state
        .api
        .account_email_otp(&ctx.correlation_id, &request)
        .await
    {
        Ok(idp_contracts::auth::InternalEmailOtpResponse::Sent) => "email-sent",
        Ok(idp_contracts::auth::InternalEmailOtpResponse::Unavailable) => "email-unavailable",
        Ok(idp_contracts::auth::InternalEmailOtpResponse::SessionExpired) => "session",
        Ok(idp_contracts::auth::InternalEmailOtpResponse::Internal) => {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "email otp request to api failed");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };
    see_other(&format!("{}/mfa/totp?error={error}", tenant.prefix()))
}

/// email OTP 送信フォーム（CSRF トークンのみ）。
#[derive(Debug, Deserialize)]
pub struct EmailCodeForm {
    pub csrf_token: String,
}

fn reshow_verify_form(
    messages: &Messages,
    status: StatusCode,
    auth_session_id: Option<&str>,
    error_key: &str,
    csrf_secret: &[u8],
    tenant_prefix: &str,
) -> Response {
    match auth_session_id {
        Some(id) => (
            status,
            Html(render_verify_form(
                messages,
                &login_csrf_token(id, csrf_secret),
                Some(error_key),
                tenant_prefix,
            )),
        )
            .into_response(),
        None => error_page(
            messages,
            StatusCode::BAD_REQUEST,
            "mfa-error-session-expired",
        ),
    }
}

fn error_page(messages: &Messages, status: StatusCode, error_key: &str) -> Response {
    let body = render(&MessagePage {
        title: messages.get("mfa-title"),
        message: messages.get(error_key),
    });
    (status, Html(body)).into_response()
}

/// ログインフロー TOTP 入力フォーム。
#[derive(Deserialize)]
pub struct TotpLoginForm {
    pub totp_code: String,
    pub csrf_token: String,
}
