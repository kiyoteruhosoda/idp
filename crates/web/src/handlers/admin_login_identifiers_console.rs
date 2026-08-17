//! ログイン識別子の管理コンソール画面（`/{tenant_id}/admin/users/{user_id}/login-identifiers`。AP16）。
//!
//! AP8 で「1 人の利用者が複数のログイン識別子（別名のユーザー名・メール・電話番号・社員番号）を
//! 持てる」登録簿を入れたが、画面が無く curl でしか触れなかった。ここは**その利用者がどの値で
//! ログインできるか**を決める設定で、ヘルプデスクが日常的に触る面である。
//!
//! データ操作は api の `/admin/users/{user_id}/login-identifiers` へ SSO Cookie 転送で委譲する。
//! HTML フォームは PATCH/DELETE を送れないため、専用の POST パス（`/{id}/active`・`/{id}/delete`）を
//! 経由して api の PATCH/DELETE へ変換する。
//!
//! # 登録値と照合キーを両方出す
//!
//! api は `display_value`（登録どおり）と `normalized_value`（実際に一致する値）を返す。画面は
//! 両方を出す。片方しか見えないと、電話番号のように書き方が揺れる識別子の設定ミス
//! （`03-1234-5678` を登録したつもりが別の正規化になっている）に気づけない。

use super::locale;
use crate::api_client::AdminApiError;
use crate::correlation::CorrelationId;
use crate::csrf::console_csrf_token;
use crate::handlers::admin_console::{redirect_to_login, resolve_admin, AdminResolution};
use crate::handlers::found;
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{
    render, LoginIdentifierRow, LoginIdentifierTypeOption, LoginIdentifiersConsole,
};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use idp_contracts::admin::LOGIN_IDENTIFIER_TYPE_CODES;
use serde::Deserialize;
use serde_json::json;

#[derive(Debug, Default, Deserialize)]
pub struct ViewQuery {
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub notice: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AddForm {
    pub identifier_type: String,
    pub value: String,
    pub csrf_token: String,
}

#[derive(Debug, Deserialize)]
pub struct ActiveForm {
    /// `"true"` / `"false"`。切り替え先の状態をフォームが持つ（画面の表示と一致させるため、
    /// 現在値を api から読み直してから反転する形にしない）。
    pub is_active: String,
    pub csrf_token: String,
}

#[derive(Debug, Deserialize)]
pub struct DeleteForm {
    pub csrf_token: String,
}

pub async fn list(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_tenant_id, user_id)): Path<(String, String)>,
    Query(query): Query<ViewQuery>,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };
    let sso = sso(&headers);
    let (identifiers, mut error_key) = match state
        .api
        .list_login_identifiers(&correlation.0, &tenant.0, &sso, &user_id)
        .await
    {
        Ok(v) => (v, query.error.as_deref().and_then(error_key_for)),
        Err(AdminApiError::Unauthorized) => return redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => (Vec::new(), Some("admin-settings-error-forbidden")),
        Err(AdminApiError::NotFound) => (Vec::new(), Some("admin-members-error-user-notfound")),
        Err(e) => {
            tracing::error!(error = %e, "failed to load login identifiers");
            (Vec::new(), Some("admin-error-internal"))
        }
    };
    error_key = error_key.or(query.error.as_deref().and_then(error_key_for));

    let messages = Messages::new(locale(&headers));
    // 種別の訳文は Rust 側で解決する（テンプレートで翻訳キーを組み立てると、キーの存在を
    // コンパイル時にも検索でも確かめられなくなる）。
    let type_options: Vec<LoginIdentifierTypeOption> = LOGIN_IDENTIFIER_TYPE_CODES
        .iter()
        .map(|code| LoginIdentifierTypeOption {
            code,
            label: type_label(&messages, code),
        })
        .collect();
    let rows: Vec<LoginIdentifierRow> = identifiers
        .iter()
        .map(|i| LoginIdentifierRow {
            id: i.id.as_deref(),
            type_label: type_label(&messages, &i.identifier_type),
            display_value: &i.display_value,
            normalized_value: &i.normalized_value,
            is_active: i.is_active,
            is_primary: i.is_primary,
        })
        .collect();

    Html(render(&LoginIdentifiersConsole {
        messages: &messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        csrf: &console_csrf_token(&sso, state.config.csrf_secret()),
        user_id: &user_id,
        identifiers: &rows,
        type_options: &type_options,
        error_key,
        notice_key: query.notice.as_deref().and_then(notice_key_for),
    }))
    .into_response()
}

pub async fn add(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_tenant_id, user_id)): Path<(String, String)>,
    Form(form): Form<AddForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = base_path(&tenant, &user_id);
    let sso = sso(&headers);
    if !csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
    }
    let body = json!({
        "identifier_type": form.identifier_type.trim(),
        "value": form.value.trim(),
        "is_active": true,
    });
    match state
        .api
        .add_login_identifier(&correlation.0, &tenant.0, &sso, &user_id, body)
        .await
    {
        Ok(_) => found(&format!("{base}?notice=added")),
        Err(e) => found(&format!("{base}?error={}", error_code(&e))),
    }
}

pub async fn set_active(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_tenant_id, user_id, identifier_id)): Path<(String, String, String)>,
    Form(form): Form<ActiveForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = base_path(&tenant, &user_id);
    let sso = sso(&headers);
    if !csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
    }
    let is_active = form.is_active == "true";
    match state
        .api
        .set_login_identifier_active(
            &correlation.0,
            &tenant.0,
            &sso,
            &user_id,
            &identifier_id,
            is_active,
        )
        .await
    {
        Ok(_) if is_active => found(&format!("{base}?notice=enabled")),
        Ok(_) => found(&format!("{base}?notice=disabled")),
        Err(e) => found(&format!("{base}?error={}", error_code(&e))),
    }
}

pub async fn delete(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_tenant_id, user_id, identifier_id)): Path<(String, String, String)>,
    Form(form): Form<DeleteForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = base_path(&tenant, &user_id);
    let sso = sso(&headers);
    if !csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
    }
    match state
        .api
        .delete_login_identifier(&correlation.0, &tenant.0, &sso, &user_id, &identifier_id)
        .await
    {
        Ok(()) => found(&format!("{base}?notice=deleted")),
        Err(e) => found(&format!("{base}?error={}", error_code(&e))),
    }
}

fn base_path(tenant: &WebTenant, user_id: &str) -> String {
    format!(
        "{}/admin/users/{user_id}/login-identifiers",
        tenant.prefix()
    )
}

/// 種別コードの訳文。未知のコードは（api が新しい種別を増やした直後などに）コードのまま出す
/// ——訳が無いことを空欄で隠すと、画面から種別が消えたように見える。
fn type_label(messages: &Messages, code: &str) -> String {
    let key = match code {
        "username" => "admin-login-identifier-type-username",
        "email" => "admin-login-identifier-type-email",
        "phone_number" => "admin-login-identifier-type-phone-number",
        "employee_number" => "admin-login-identifier-type-employee-number",
        other => return other.to_string(),
    };
    messages.get(key)
}

fn error_code(e: &AdminApiError) -> &'static str {
    match e {
        AdminApiError::Forbidden => "forbidden",
        AdminApiError::Validation(_) => "validation",
        AdminApiError::Conflict(_) => "conflict",
        AdminApiError::NotFound => "notfound",
        _ => "internal",
    }
}

fn error_key_for(error: &str) -> Option<&'static str> {
    match error {
        "csrf" => Some("admin-error-csrf"),
        "forbidden" => Some("admin-settings-error-forbidden"),
        "validation" => Some("admin-login-identifiers-error-validation"),
        "conflict" => Some("admin-login-identifiers-error-conflict"),
        "notfound" => Some("admin-login-identifiers-error-not-found"),
        "internal" => Some("admin-error-internal"),
        _ => None,
    }
}

fn notice_key_for(notice: &str) -> Option<&'static str> {
    match notice {
        "added" => Some("admin-login-identifiers-added"),
        "enabled" => Some("admin-login-identifiers-enabled-done"),
        "disabled" => Some("admin-login-identifiers-disabled-done"),
        "deleted" => Some("admin-login-identifiers-deleted"),
        _ => None,
    }
}

fn sso(headers: &HeaderMap) -> String {
    crate::cookies::get(headers, crate::cookies::SSO_SESSION_COOKIE).unwrap_or_default()
}

fn csrf_valid(sso: &str, submitted: &str, key: &[u8]) -> bool {
    idp_contracts::csrf::verify(&console_csrf_token(sso, key), submitted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::Locale;

    /// 種別プルダウンの選択肢は contracts の語彙（＝ api の保存値）そのものを使い、
    /// すべてに訳がある。訳が無いとコードがそのまま画面に出る。
    #[test]
    fn every_identifier_type_code_has_a_label_in_both_locales() {
        for locale in [Locale::Ja, Locale::En] {
            let messages = Messages::new(locale);
            for code in LOGIN_IDENTIFIER_TYPE_CODES {
                let label = type_label(&messages, code);
                assert_ne!(
                    &label.as_str(),
                    code,
                    "{locale:?}: no translation for identifier type {code}"
                );
                assert!(!label.is_empty());
            }
        }
    }

    /// 未知のコードはコードのまま出す（訳が無いことを空欄で隠さない）。
    #[test]
    fn an_unknown_identifier_type_falls_back_to_its_code() {
        let messages = Messages::new(Locale::Ja);
        assert_eq!(type_label(&messages, "passport_number"), "passport_number");
    }
}
