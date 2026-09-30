//! 利用者のセルフサービス設定画面（web。`/{tenant_id}/settings`。MT15・MT20）。
//!
//! ログイン済み（SSO セッション保有）利用者が、自分のパスワード変更・表示言語の選択・MFA（TOTP /
//! Passkey）の管理導線にアクセスする。パスワード変更は api の `POST /internal/account/change-password`
//! に委ね、MFA は既存の `/{tenant_id}/account/*` 画面へ誘導する。
//!
//! 表示設定（言語・配色。MT20）の保存は [`save_display_preferences`]
//! （`POST /{tenant_id}/settings/display`）だけが行う。GET の `?lang=` / `?theme=` は一時切替
//! （[`crate::display_preferences`] middleware が Cookie とその画面の表示に効かせるだけ）で、
//! ユーザー設定（DB）へは書かない（task #79）。
//!
//! この画面の状態変更（表示名・パスワード・言語・配色）はすべて CSRF 同期トークン
//! （`console_csrf_token`。SSO セッション id 由来）で守る（task #79・#118）。SameSite=Lax の SSO
//! Cookie だけに頼らない —— 利用者向けの他の画面（セッション一覧・認証器）と同じ作法である。
//! トークンが合わなければ何も保存せず、設定画面へ戻してバナーで伝える。

use super::internal_call_status;
use crate::client_ip::ClientIp;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::{console_csrf_token, console_csrf_valid};
use crate::display_preferences::{fetch_account_profile, FetchedAccountProfile};
use crate::dto::{AccountNameForm, AccountPasswordForm, DisplayPreferencesForm, SettingsQuery};
use crate::handlers::{forwarded_context, found, locale, see_other, step_up};
use crate::i18n::{Locale, Messages};
use crate::state::WebState;
use crate::templates::{render, UserSettings};
use crate::tenant::WebTenant;
use crate::theme::Theme;
use assay_contracts::auth::{
    InternalAccountChangePasswordRequest, InternalAccountChangePasswordResponse,
    InternalAccountProfileResponse, InternalAccountUpdateLanguageRequest,
    InternalAccountUpdateLanguageResponse, InternalAccountUpdateNameRequest,
    InternalAccountUpdateNameResponse, InternalAccountUpdateThemeRequest,
    InternalAccountUpdateThemeResponse,
};
use axum::extract::{Extension, Query, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};
use axum::Form;

/// 設定画面（`GET /{tenant_id}/settings`）。
///
/// `?lang=` / `?theme=` の解釈（一時切替）と Cookie の保存は
/// [`crate::display_preferences::resolve_display_preferences`] middleware が全画面共通で行う
/// （MT20）。ここは決定済みの値で描画するだけで、セレクタは [`save_display_preferences`] へ
/// CSRF トークン付きで POST する（task #79）。
pub async fn page(
    State(state): State<WebState>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<SettingsQuery>,
    fetched: Option<Extension<FetchedAccountProfile>>,
) -> Response {
    let locale = locale(&headers);
    let from_admin = query.from.as_deref() == Some("admin");

    // 未ログイン・セッション切れはログイン画面へ送る（task #121）。認証器・セッション一覧など
    // 他のアカウント画面と同じ形（戻り先は付けない）。
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{}/login", tenant.prefix()));
    };
    // 表示名・ログイン識別子のプリフィル値。プロフィールは表示設定の middleware が引いたものを
    // 使い、api を引き直さない（task #80）。middleware が引かなかったとき（`?lang=` と `?theme=` の
    // 両方で決まった）だけここで引く。取得失敗時は空文字で描画する（フェイルソフト）。
    let profile = match fetched {
        Some(Extension(FetchedAccountProfile(profile))) => profile,
        None => fetch_account_profile(&state, &sso).await,
    };
    if matches!(
        profile,
        Some(InternalAccountProfileResponse::SessionExpired)
    ) {
        return found(&format!("{}/login", tenant.prefix()));
    }
    let (current_name, preferred_username, stored_theme) = match profile {
        Some(InternalAccountProfileResponse::Ok {
            name,
            preferred_username,
            theme,
            ..
        }) => (
            name.unwrap_or_default(),
            preferred_username.unwrap_or_default(),
            theme,
        ),
        _ => (String::new(), String::new(), None),
    };
    // 決定順は middleware と同じ（`?theme=` > ユーザー設定 > Cookie）。**`?theme=` を自分でも
    // 読む**のが要点で、一時切替の Cookie は応答の中で書かれるため、このリクエストでは Cookie も
    // ユーザー設定もまだ切替前の値を返す。読まないと「画面は切り替わったのにセレクタは元のまま」
    // に見える。
    // 未選択（`?theme=` も DB も Cookie も無い）は「OS に合わせる」を選択済みとして見せる ——
    // セレクタに「未選択」という選択肢は無く、実際の見え方も OS 追従だからである。
    let current_theme = query
        .theme
        .as_deref()
        .and_then(Theme::from_tag)
        .or_else(|| stored_theme.as_deref().and_then(Theme::from_tag))
        .or_else(|| cookies::get(&headers, cookies::THEME_COOKIE).and_then(|t| Theme::from_tag(&t)))
        .unwrap_or(Theme::System);

    let csrf = console_csrf_token(&sso, state.config.csrf_secret());

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
            csrf: &csrf,
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
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{base}?error=session{suffix}"));
    };
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        tracing::warn!("self-service password change rejected: csrf token mismatch");
        return found(&format!("{base}?error=csrf{suffix}"));
    }
    if form.new_password != form.new_password_confirm {
        return found(&format!("{base}?error=mismatch{suffix}"));
    }
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
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        tracing::warn!("self-service name change rejected: csrf token mismatch");
        return found(&format!("{base}?error=csrf{suffix}"));
    }
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

/// 表示設定（言語・配色）の保存（`POST /{tenant_id}/settings/display`。task #79）。
///
/// ユーザー設定（`users.language` / `users.theme`）へ書く**唯一の経路**。設定画面のセレクタと、
/// 管理コンソールのヘッダの言語ドロップダウン（ログイン中）が送る。GET の `?lang=` / `?theme=` は
/// 一時切替で保存しない（[`crate::display_preferences`]）。
///
/// - CSRF トークン（`console_csrf_token`）が合わなければ何も保存せず、設定画面へ戻してバナーで伝える。
/// - 保存したら Cookie も揃えて（ログアウト後の前回選択として残る）、`return_to` の画面へ 303 で
///   戻す。`return_to` はこのテナント配下のパスだけを受け（オープンリダイレクトにしない）、
///   `lang` / `theme` のクエリは落とす（戻った先で一時切替が保存を上書きして見えないように）。
/// - 別端末への追随は従来どおり: 保存先は DB で、ログイン中は DB が Cookie より強い。
pub async fn save_display_preferences(
    State(state): State<WebState>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<DisplayPreferencesForm>,
) -> Response {
    let settings = format!("{}/settings", tenant.prefix());
    let suffix = if form.from.as_deref() == Some("admin") {
        "&from=admin"
    } else {
        ""
    };
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{}/login", tenant.prefix()));
    };
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        tracing::warn!("display preference change rejected: csrf token mismatch");
        return see_other(&format!("{settings}?error=csrf{suffix}"));
    }
    let locale = form.lang.as_deref().and_then(Locale::from_tag);
    let theme = form.theme.as_deref().and_then(Theme::from_tag);

    if let Some(locale) = locale {
        let request = InternalAccountUpdateLanguageRequest {
            sso_session_id: sso.clone(),
            language: locale.as_tag().to_string(),
        };
        match state.api.account_update_language(&request).await {
            Ok(InternalAccountUpdateLanguageResponse::Ok) => {}
            Ok(InternalAccountUpdateLanguageResponse::SessionExpired) => {
                return found(&format!("{}/login", tenant.prefix()));
            }
            Ok(other) => {
                tracing::warn!(?other, "unexpected outcome from update-language");
                return see_other(&format!("{settings}?error=internal{suffix}"));
            }
            Err(e) => {
                tracing::error!(error = %e, "account update-language call to api failed");
                return see_other(&format!("{settings}?error=internal{suffix}"));
            }
        }
    }
    if let Some(theme) = theme {
        let request = InternalAccountUpdateThemeRequest {
            sso_session_id: sso.clone(),
            theme: theme.as_tag().to_string(),
        };
        match state.api.account_update_theme(&request).await {
            Ok(InternalAccountUpdateThemeResponse::Ok) => {}
            Ok(InternalAccountUpdateThemeResponse::SessionExpired) => {
                return found(&format!("{}/login", tenant.prefix()));
            }
            Ok(other) => {
                tracing::warn!(?other, "unexpected outcome from update-theme");
                return see_other(&format!("{settings}?error=internal{suffix}"));
            }
            Err(e) => {
                tracing::error!(error = %e, "account update-theme call to api failed");
                return see_other(&format!("{settings}?error=internal{suffix}"));
            }
        }
    }

    let back = without_display_overrides(&step_up::safe_next(&tenant, form.return_to.as_deref()));
    let mut set_cookies = state.set_cookies();
    if let Some(locale) = locale {
        set_cookies = set_cookies.set_local(
            cookies::LANG_COOKIE,
            locale.as_tag(),
            cookies::PREFERENCE_COOKIE_MAX_AGE_SECS,
        );
    }
    if let Some(theme) = theme {
        set_cookies = set_cookies.set_preference(
            cookies::THEME_COOKIE,
            theme.as_tag(),
            cookies::PREFERENCE_COOKIE_MAX_AGE_SECS,
        );
    }
    (set_cookies.into_headers(), see_other(&back)).into_response()
}

/// 戻り先から一時切替のクエリ（`lang` / `theme`）を落とす。
///
/// 一時切替を付けたままの画面（`/admin/clients?lang=en`）でヘッダから日本語を保存すると、
/// そのまま戻した先で `?lang=en` がまた効き、保存が効いていないように見える。
fn without_display_overrides(path: &str) -> String {
    let Some((base, query)) = path.split_once('?') else {
        return path.to_string();
    };
    let kept: Vec<&str> = query
        .split('&')
        .filter(|pair| {
            let name = pair.split('=').next().unwrap_or("");
            !pair.is_empty() && name != "lang" && name != "theme"
        })
        .collect();
    if kept.is_empty() {
        base.to_string()
    } else {
        format!("{base}?{}", kept.join("&"))
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
        // CSRF トークンの不一致（task #79・#118）。セッション一覧・認証器の画面と同じ文言。
        "csrf" => Some("user-security-error-csrf"),
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
            current_theme: "system",
            current_name: "",
            preferred_username: "",
            saved_key: None,
            error_key: None,
            from_admin,
            csrf: "test-csrf",
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
                csrf: "test-csrf",
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

    /// 戻り先から一時切替（`lang` / `theme`）だけを落とし、他のクエリは保つ。
    #[test]
    fn the_return_path_drops_only_the_temporary_switches() {
        assert_eq!(without_display_overrides("/t/admin"), "/t/admin");
        assert_eq!(without_display_overrides("/t/admin?lang=en"), "/t/admin");
        assert_eq!(
            without_display_overrides("/t/admin/clients?page=2&lang=en&theme=dark&q=x"),
            "/t/admin/clients?page=2&q=x"
        );
        // 名前が前方一致するだけの別パラメータは落とさない。
        assert_eq!(
            without_display_overrides("/t/admin?language=x&themes=y"),
            "/t/admin?language=x&themes=y"
        );
        assert_eq!(without_display_overrides("/t/settings?"), "/t/settings");
    }

    #[test]
    fn back_link_to_admin_console_is_shown_only_when_opened_from_admin() {
        let html = render_settings(true);
        assert!(html.contains("/00000000-0000-7000-8000-000000000000/admin\""));
        // フォーム送信（表示名・言語・配色・パスワード・ログアウト）でも管理コンソール文脈を hidden で
        // 引き継ぐ（ログアウトはトークンが合わずに戻したとき。task #143）。
        assert_eq!(
            html.matches(r#"<input type="hidden" name="from" value="admin">"#)
                .count(),
            5
        );

        let html = render_settings(false);
        assert!(!html.contains("/00000000-0000-7000-8000-000000000000/admin\""));
        assert!(!html.contains(r#"name="from""#));
    }
}
