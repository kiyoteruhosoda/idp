//! 利用者のセルフサービス設定画面（web。`/{tenant_id}/settings`。MT15・MT20）。
//!
//! ログイン済み（SSO セッション保有）利用者が、自分のパスワード変更・表示言語の選択・MFA（TOTP /
//! Passkey）の管理導線にアクセスする。パスワード変更は api の `POST /internal/account/change-password`
//! に委ね、MFA は既存の `/{tenant_id}/account/*` 画面へ誘導する。
//!
//! 言語設定（MT20）: `?lang=` を受けたら `lang` Cookie に保存し、ログイン中なら DB へも永続化する
//! （`POST /internal/account/update-language`）。

use crate::cookies;
use crate::correlation::CorrelationId;
use crate::dto::{AccountPasswordForm, SettingsQuery};
use crate::handlers::{forwarded_context, found};
use crate::i18n::{Locale, Messages};
use crate::state::WebState;
use crate::templates::{render, UserSettings};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{AppendHeaders, Html, IntoResponse, Response};
use axum::Form;
use idp_contracts::auth::{
    InternalAccountChangePasswordRequest, InternalAccountChangePasswordResponse,
    InternalAccountUpdateLanguageRequest, InternalAccountUpdateLanguageResponse,
};

/// 設定画面（`GET /{tenant_id}/settings`）。`?lang=` があれば言語 Cookie を保存し、ログイン中なら DB へも永続化する。
pub async fn page(
    State(state): State<WebState>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<SettingsQuery>,
) -> Response {
    let cookie_lang = cookies::get(&headers, cookies::LANG_COOKIE);
    let accept = headers
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok());
    let locale = Locale::resolve(query.lang.as_deref(), None, cookie_lang.as_deref(), accept);
    let from_admin = query.from.as_deref() == Some("admin");

    // Messages は FluentBundle を含み !Send のため、await をまたがないよう先にレンダリングして解放する。
    let body = {
        let messages = Messages::new(locale);
        render(&UserSettings {
            messages: &messages,
            tenant: &tenant.prefix(),
            current_lang: locale.as_tag(),
            saved_key: query.saved.as_deref().and_then(saved_key_for),
            error_key: query.error.as_deref().and_then(error_key_for),
            from_admin,
        })
    };

    // 明示的な言語選択（有効な `?lang=`）のときのみ Cookie を保存し、ログイン中なら DB へも永続化する。
    let set_lang = query
        .lang
        .as_deref()
        .and_then(Locale::from_tag)
        .map(|l| l.as_tag());
    match set_lang {
        Some(tag) => {
            // ログイン中なら DB にも言語設定を保存する（MT20）。
            if let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) {
                let req = InternalAccountUpdateLanguageRequest {
                    sso_session_id: sso,
                    language: tag.to_string(),
                };
                match state.api.account_update_language(&req).await {
                    Ok(InternalAccountUpdateLanguageResponse::Ok) => {}
                    Ok(InternalAccountUpdateLanguageResponse::SessionExpired) => {
                        // セッション切れ — Cookie のみ更新して続行。
                        tracing::debug!("SSO session expired during language update");
                    }
                    Ok(other) => {
                        tracing::warn!(?other, "unexpected outcome from update-language");
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "account update-language call to api failed");
                    }
                }
            }
            let cookie = cookies::build(
                cookies::LANG_COOKIE,
                tag,
                cookies::LANG_COOKIE_MAX_AGE_SECS,
                state.config.cookie_secure(),
            );
            (AppendHeaders([(header::SET_COOKIE, cookie)]), Html(body)).into_response()
        }
        None => Html(body).into_response(),
    }
}

/// セルフサービスのパスワード変更（`POST /{tenant_id}/settings/password`）。
pub async fn change_password(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<AccountPasswordForm>,
) -> Response {
    let base = format!("{}/settings", tenant.prefix());
    // 管理コンソール発の文脈（戻るリンク）を PRG リダイレクト後も維持する。
    let suffix = if form.from.as_deref() == Some("admin") {
        "&from=admin"
    } else {
        ""
    };
    if form.new_password != form.new_password_confirm {
        return found(&format!("{base}?error=mismatch{suffix}"));
    }
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{base}?error=session{suffix}"));
    };
    let ctx = forwarded_context(&headers, &correlation);
    let request = InternalAccountChangePasswordRequest {
        sso_session_id: sso,
        current_password: form.current_password,
        new_password: form.new_password,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let outcome = match state
        .api
        .account_change_password(&ctx.correlation_id, &request)
        .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "account change-password call to api failed");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };
    match outcome {
        InternalAccountChangePasswordResponse::Ok => {
            found(&format!("{base}?saved=password{suffix}"))
        }
        InternalAccountChangePasswordResponse::SessionExpired => {
            found(&format!("{base}?error=session{suffix}"))
        }
        InternalAccountChangePasswordResponse::InvalidCurrentPassword => {
            found(&format!("{base}?error=invalid-current{suffix}"))
        }
        InternalAccountChangePasswordResponse::WeakPassword => {
            found(&format!("{base}?error=weak{suffix}"))
        }
        InternalAccountChangePasswordResponse::Internal => {
            found(&format!("{base}?error=internal{suffix}"))
        }
    }
}

fn saved_key_for(saved: &str) -> Option<&'static str> {
    match saved {
        "password" => Some("user-settings-password-saved"),
        _ => None,
    }
}

fn error_key_for(error: &str) -> Option<&'static str> {
    match error {
        "mismatch" => Some("user-settings-error-mismatch"),
        "invalid-current" => Some("user-settings-error-invalid-current"),
        "weak" => Some("user-settings-error-weak"),
        "session" => Some("user-settings-error-session"),
        "internal" => Some("user-settings-error-internal"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render_settings(from_admin: bool) -> String {
        let messages = Messages::new(Locale::Ja);
        render(&UserSettings {
            messages: &messages,
            tenant: "/00000000-0000-7000-8000-000000000000",
            current_lang: "ja",
            saved_key: None,
            error_key: None,
            from_admin,
        })
    }

    #[test]
    fn back_link_to_admin_console_is_shown_only_when_opened_from_admin() {
        let html = render_settings(true);
        assert!(html.contains("/00000000-0000-7000-8000-000000000000/admin\""));
        // フォーム送信（言語・パスワード）でも管理コンソール文脈を hidden で引き継ぐ。
        assert_eq!(
            html.matches(r#"<input type="hidden" name="from" value="admin">"#)
                .count(),
            2
        );

        let html = render_settings(false);
        assert!(!html.contains("/00000000-0000-7000-8000-000000000000/admin\""));
        assert!(!html.contains(r#"name="from""#));
    }
}
