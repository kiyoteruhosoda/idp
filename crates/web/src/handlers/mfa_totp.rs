//! MFA TOTP 自己登録ハンドラ（`GET/POST /account/mfa/totp/*`）と
//! ログインフロー TOTP 入力ハンドラ（`GET/POST /mfa/totp`）。
//!
//! * セットアップ画面（`/account/mfa/totp/setup`）: SSO 認証済みユーザーが TOTP を自己登録する。
//!   QR コード（SVG）と生シークレット（base32）を表示する。QR が使えない場合は生コードを入力する。
//! * ログイン TOTP 画面（`/mfa/totp`）: パスワード認証後に TOTP 入力を求める。

use crate::cookies;
use crate::correlation::CorrelationId;
use crate::dto::TotpConfirmForm;
use crate::handlers::{forwarded_context, found};
use crate::i18n::{Locale, Messages};
use crate::state::WebState;
use crate::templates::{render, MessagePage, TotpSetupTemplate, TotpVerifyTemplate};
use crate::tenant::WebTenant;
use axum::extract::{Extension, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{AppendHeaders, Html, IntoResponse, Response};
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
    headers: HeaderMap,
) -> Response {
    let Some(sso_session_id) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        // FluentBundle は !Send なので await の前に作成・消費する。
        let messages = Messages::new(locale(&headers));
        return error_page(&messages, StatusCode::UNAUTHORIZED, "mfa-error-not-signed-in");
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
        InternalTotpSetupResponse::AlreadyConfigured => {
            error_page(&messages, StatusCode::CONFLICT, "mfa-error-already-configured")
        }
        InternalTotpSetupResponse::SessionExpired => {
            error_page(&messages, StatusCode::UNAUTHORIZED, "mfa-error-session-expired")
        }
        InternalTotpSetupResponse::Internal => {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// TOTP 確認フォーム（`POST /account/mfa/totp/setup`）。6 桁コードを検証して有効化する。
pub async fn setup_confirm(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    headers: HeaderMap,
    Form(form): Form<TotpConfirmForm>,
) -> Response {
    let Some(sso_session_id) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        let messages = Messages::new(locale(&headers));
        return error_page(&messages, StatusCode::UNAUTHORIZED, "mfa-error-not-signed-in");
    };

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
            error_page(&messages, StatusCode::UNPROCESSABLE_ENTITY, "mfa-error-invalid-code")
        }
        InternalTotpConfirmResponse::NotFound
        | InternalTotpConfirmResponse::SessionExpired => {
            error_page(&messages, StatusCode::UNAUTHORIZED, "mfa-error-session-expired")
        }
        InternalTotpConfirmResponse::AlreadyConfigured => {
            error_page(&messages, StatusCode::CONFLICT, "mfa-error-already-configured")
        }
        InternalTotpConfirmResponse::Internal => {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// TOTP 削除（`POST /account/mfa/totp/delete`）。MFA を無効化する。
pub async fn setup_delete(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    headers: HeaderMap,
) -> Response {
    let Some(sso_session_id) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        let messages = Messages::new(locale(&headers));
        return error_page(&messages, StatusCode::UNAUTHORIZED, "mfa-error-not-signed-in");
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
        InternalTotpDeleteResponse::SessionExpired => {
            error_page(&messages, StatusCode::UNAUTHORIZED, "mfa-error-session-expired")
        }
        InternalTotpDeleteResponse::Internal => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

// ── ログインフロー TOTP 入力 ─────────────────────────────────────────────────

/// TOTP 入力ページ（`GET /mfa/totp`）。ログインフロー中（パスワード認証後）に表示する。
pub async fn verify_page(headers: HeaderMap) -> Response {
    let messages = Messages::new(locale(&headers));
    let Some(auth_session_id) = cookies::get(&headers, cookies::AUTH_SESSION_COOKIE) else {
        return error_page(&messages, StatusCode::BAD_REQUEST, "mfa-error-session-expired");
    };
    Html(render_verify_form(
        &messages,
        &login_csrf_token(&auth_session_id),
        None,
    ))
    .into_response()
}

/// TOTP 入力処理（`POST /mfa/totp`）。コードを検証し、成功時に SSO Cookie を発行してリダイレクトする。
pub async fn verify(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<TotpLoginForm>,
) -> Response {
    let ctx = forwarded_context(&headers, &correlation);
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
    let secure = state.config.cookie_secure();

    match outcome {
        InternalVerifyTotpResponse::Success {
            redirect_to,
            sso_session_id,
            sso_absolute_ttl_secs,
        } => {
            let sso_cookie = cookies::build(
                cookies::SSO_SESSION_COOKIE,
                &sso_session_id,
                sso_absolute_ttl_secs,
                secure,
            );
            let expire_auth = cookies::expire(cookies::AUTH_SESSION_COOKIE, secure);
            (
                AppendHeaders([
                    (header::SET_COOKIE, sso_cookie),
                    (header::SET_COOKIE, expire_auth),
                ]),
                found(&redirect_to),
            )
                .into_response()
        }
        InternalVerifyTotpResponse::ConsentRequired {
            auth_session_id: new_auth_session_id,
            sso_session_id,
            sso_absolute_ttl_secs,
        } => {
            let sso_cookie = cookies::build(
                cookies::SSO_SESSION_COOKIE,
                &sso_session_id,
                sso_absolute_ttl_secs,
                secure,
            );
            let auth_cookie = cookies::build(
                cookies::AUTH_SESSION_COOKIE,
                &new_auth_session_id,
                state.config.auth_session_ttl_secs(),
                secure,
            );
            (
                AppendHeaders([
                    (header::SET_COOKIE, sso_cookie),
                    (header::SET_COOKIE, auth_cookie),
                ]),
                found(&format!("{}/consent", tenant.prefix())),
            )
                .into_response()
        }
        InternalVerifyTotpResponse::InvalidCode => reshow_verify_form(
            &messages,
            StatusCode::UNAUTHORIZED,
            auth_session_id.as_deref(),
            "mfa-error-invalid-code",
        ),
        InternalVerifyTotpResponse::CsrfMismatch => {
            error_page(&messages, StatusCode::BAD_REQUEST, "login-error-csrf")
        }
        InternalVerifyTotpResponse::SessionExpired => {
            error_page(&messages, StatusCode::BAD_REQUEST, "mfa-error-session-expired")
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
    use qrcode::{EcLevel, QrCode};
    use qrcode::render::svg;

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

fn locale(headers: &HeaderMap) -> Locale {
    Locale::from_accept_language(
        headers
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok()),
    )
}

fn render_verify_form(messages: &Messages, csrf: &str, error_key: Option<&str>) -> String {
    render(&TotpVerifyTemplate {
        messages,
        csrf,
        error_key,
    })
}

fn reshow_verify_form(
    messages: &Messages,
    status: StatusCode,
    auth_session_id: Option<&str>,
    error_key: &str,
) -> Response {
    match auth_session_id {
        Some(id) => (
            status,
            Html(render_verify_form(
                messages,
                &login_csrf_token(id),
                Some(error_key),
            )),
        )
            .into_response(),
        None => error_page(messages, StatusCode::BAD_REQUEST, "mfa-error-session-expired"),
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
