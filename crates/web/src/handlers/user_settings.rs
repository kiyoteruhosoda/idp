//! 利用者のセルフサービス設定画面（web。`/{tenant_id}/settings`。MT15・MT20）。
//!
//! ログイン済み（SSO セッション保有）利用者が、自分のパスワード変更・表示言語の選択・MFA（TOTP /
//! Passkey）の管理導線にアクセスする。パスワード変更は api の `POST /internal/account/change-password`
//! に委ね、MFA は既存の `/{tenant_id}/account/*` 画面へ誘導する。
//!
//! 言語設定（MT20）: `?lang=` を受けたら `lang` Cookie に保存し、ログイン中なら DB へも永続化する
//! （`POST /internal/account/update-language`）。

use super::internal_call_status;
use crate::client_ip::ClientIp;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::dto::{AccountNameForm, AccountPasswordForm, SettingsQuery};
use crate::handlers::{forwarded_context, found, locale};
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, UserSettings};
use crate::tenant::WebTenant;
use crate::theme::Theme;
use assay_contracts::auth::{
    InternalAccountChangePasswordRequest, InternalAccountChangePasswordResponse,
    InternalAccountProfileRequest, InternalAccountProfileResponse,
    InternalAccountUpdateNameRequest, InternalAccountUpdateNameResponse,
};
use axum::extract::{Extension, Query, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};
use axum::Form;

/// 設定画面（`GET /{tenant_id}/settings`）。
///
/// `?lang=` / `?theme=` の解釈・Cookie の保存・ユーザー設定（DB）への永続化は
/// [`crate::display_preferences::resolve_display_preferences`] middleware が全画面共通で行う
/// （MT20）。ここは決定済みの値で描画するだけで、セレクタは `?lang=` / `?theme=` を付けた
/// 同一 URL へのリンクとして機能する。
pub async fn page(
    State(state): State<WebState>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<SettingsQuery>,
) -> Response {
    let locale = locale(&headers);
    let from_admin = query.from.as_deref() == Some("admin");

    // 表示名・ログイン識別子のプリフィル値を api から取得する（Messages は !Send のため await より先に）。
    // 未ログイン・取得失敗時は空文字で描画する（フェイルソフト）。
    let (current_name, preferred_username, stored_theme) =
        match cookies::get(&headers, cookies::SSO_SESSION_COOKIE) {
            Some(sso) => {
                let req = InternalAccountProfileRequest {
                    sso_session_id: sso,
                };
                match state.api.account_profile(&req).await {
                    Ok(InternalAccountProfileResponse::Ok {
                        name,
                        preferred_username,
                        theme,
                        ..
                    }) => (
                        name.unwrap_or_default(),
                        preferred_username.unwrap_or_default(),
                        theme,
                    ),
                    Ok(_) => (String::new(), String::new(), None),
                    Err(e) => {
                        tracing::error!(error = %e, "account profile fetch call to api failed");
                        (String::new(), String::new(), None)
                    }
                }
            }
            None => (String::new(), String::new(), None),
        };
    // 決定順は middleware と同じ（`?theme=` > ユーザー設定 > Cookie）。**`?theme=` を自分でも
    // 読む**のが要点で、保存は応答より後（DB）・応答の中（Cookie）に起きるため、保存直後の
    // このリクエストでは api も Cookie もまだ古い値を返す。読まないと「保存したのに
    // セレクタは元のまま」に見える（画面の配色だけが変わる）。
    // 未選択（`?theme=` も DB も Cookie も無い）は「OS に合わせる」を選択済みとして見せる ——
    // セレクタに「未選択」という選択肢は無く、実際の見え方も OS 追従だからである。
    let current_theme = query
        .theme
        .as_deref()
        .and_then(Theme::from_tag)
        .or_else(|| stored_theme.as_deref().and_then(Theme::from_tag))
        .or_else(|| cookies::get(&headers, cookies::THEME_COOKIE).and_then(|t| Theme::from_tag(&t)))
        .unwrap_or(Theme::System);

    // Messages は FluentBundle を含み !Send のため、await をまたがないよう先にレンダリングして解放する。
    let body = {
        let messages = Messages::new(locale);
        render(&UserSettings {
            messages: &messages,
            tenant: &tenant.prefix(),
            current_lang: locale.as_tag(),
            current_theme: current_theme.as_tag(),
            current_name: &current_name,
            preferred_username: &preferred_username,
            saved_key: query.saved.as_deref().and_then(saved_key_for),
            error_key: query.error.as_deref().and_then(error_key_for),
            from_admin,
        })
    };

    Html(body).into_response()
}

/// セルフサービスのパスワード変更（`POST /{tenant_id}/settings/password`）。
pub async fn change_password(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
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
    let ctx = forwarded_context(&headers, &correlation, &client_ip);
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
            return internal_call_status(&e).into_response();
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
        InternalAccountChangePasswordResponse::WeakPassword { reason } => {
            let code = super::password_rejection_error_code(reason, "weak");
            found(&format!("{base}?error={code}{suffix}"))
        }
        InternalAccountChangePasswordResponse::Internal => {
            found(&format!("{base}?error=internal{suffix}"))
        }
    }
}

/// セルフサービスの表示名変更（`POST /{tenant_id}/settings/name`）。
pub async fn change_name(
    State(state): State<WebState>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<AccountNameForm>,
) -> Response {
    let base = format!("{}/settings", tenant.prefix());
    let suffix = if form.from.as_deref() == Some("admin") {
        "&from=admin"
    } else {
        ""
    };
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{base}?error=session{suffix}"));
    };
    let request = InternalAccountUpdateNameRequest {
        sso_session_id: sso,
        name: form.name,
    };
    let outcome = match state.api.account_update_name(&request).await {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "account update-name call to api failed");
            return internal_call_status(&e).into_response();
        }
    };
    match outcome {
        InternalAccountUpdateNameResponse::Ok => found(&format!("{base}?saved=name{suffix}")),
        InternalAccountUpdateNameResponse::SessionExpired => {
            found(&format!("{base}?error=session{suffix}"))
        }
        InternalAccountUpdateNameResponse::Invalid => {
            found(&format!("{base}?error=name-invalid{suffix}"))
        }
        InternalAccountUpdateNameResponse::Internal => {
            found(&format!("{base}?error=internal{suffix}"))
        }
    }
}

fn saved_key_for(saved: &str) -> Option<&'static str> {
    match saved {
        "password" => Some("user-settings-password-saved"),
        "name" => Some("user-settings-name-saved"),
        _ => None,
    }
}

fn error_key_for(error: &str) -> Option<&'static str> {
    match error {
        "mismatch" => Some("user-settings-error-mismatch"),
        "invalid-current" => Some("user-settings-error-invalid-current"),
        "weak" => Some("user-settings-error-weak"),
        "breached" => Some("password-error-breached"),
        "reused" => Some("password-error-reused"),
        "session" => Some("user-settings-error-session"),
        "internal" => Some("user-settings-error-internal"),
        "name-invalid" => Some("user-settings-error-name-invalid"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::Locale;

    fn render_settings(from_admin: bool) -> String {
        let messages = Messages::new(Locale::Ja);
        render(&UserSettings {
            messages: &messages,
            tenant: "/00000000-0000-7000-8000-000000000000",
            current_lang: "ja",
            current_theme: "system",
            current_name: "",
            preferred_username: "",
            saved_key: None,
            error_key: None,
            from_admin,
        })
    }

    /// 配色セレクタは保存済みの値を選択状態で出す（保存したのに戻って見ると既定に見える、を防ぐ）。
    #[test]
    fn the_appearance_selector_shows_the_saved_choice() {
        let messages = Messages::new(Locale::Ja);
        let render_with = |current_theme| {
            render(&UserSettings {
                messages: &messages,
                tenant: "/t",
                current_lang: "ja",
                current_theme,
                current_name: "",
                preferred_username: "",
                saved_key: None,
                error_key: None,
                from_admin: false,
            })
        };

        let html = render_with("dark");
        assert!(html.contains(r#"<option value="dark" selected>"#), "{html}");
        assert!(
            !html.contains(r#"<option value="light" selected>"#),
            "{html}"
        );

        // 未選択は「端末の設定に合わせる」として見せる（実際の見え方と一致させる）。
        let html = render_with("system");
        assert!(
            html.contains(r#"<option value="system" selected>"#),
            "{html}"
        );
    }

    #[test]
    fn back_link_to_admin_console_is_shown_only_when_opened_from_admin() {
        let html = render_settings(true);
        assert!(html.contains("/00000000-0000-7000-8000-000000000000/admin\""));
        // フォーム送信（表示名・言語・配色・パスワード）でも管理コンソール文脈を hidden で引き継ぐ。
        assert_eq!(
            html.matches(r#"<input type="hidden" name="from" value="admin">"#)
                .count(),
            4
        );

        let html = render_settings(false);
        assert!(!html.contains("/00000000-0000-7000-8000-000000000000/admin\""));
        assert!(!html.contains(r#"name="from""#));
    }
}
