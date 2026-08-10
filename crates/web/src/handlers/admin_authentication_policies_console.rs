//! 認証ポリシーの管理コンソール画面（`/{tenant_id}/admin/authentication-policies`、AP1）。
//!
//! これまで認証ポリシー（deny / require_mfa / allow / require_specific_method と、AP3 で増えた
//! ネットワークゾーン・時間帯・`acr_values` の条件）は API からしか設定できなかった。**ログインを
//! 止める設定**を curl でしか触れない状態は、設定ミスの確認も切り戻しも運用者に curl を強いる。
//!
//! データ操作は api の `/admin/authentication-policies` へ SSO Cookie 転送で委譲する。HTML フォームは
//! PUT/DELETE を送れないため、更新・削除は専用の POST パス（`/{id}/update`・`/{id}/delete`）を経由し、
//! api 側の PUT/DELETE へ変換する（SAML SP 画面と同じ方式）。
//!
//! # 更新が全項目置換であることの含意
//!
//! api の更新は全項目置換なので、**フォームに出せなかった項目は保存時に消える**。可変長の条件
//! （対象クライアント・利用者・CIDR・`acr_values`・時間帯）をテキスト領域で往復させているのは
//! このためで、書式と解析は [`crate::authentication_policy_form`] に集約する。時間帯は 1 行でも
//! 読めなければ保存自体を拒否する（読めた行だけ保存すると、書いたはずの条件が黙って消える）。

use super::locale;
use crate::api_client::AdminApiError;
use crate::authentication_policy_form::{
    format_list, format_time_windows, parse_list, parse_time_windows, selected_methods,
};
use crate::correlation::CorrelationId;
use crate::csrf::console_csrf_token;
use crate::dto::{AdminAuthenticationPolicyDeleteForm, AdminAuthenticationPolicyForm};
use crate::handlers::admin_console::{redirect_to_login, resolve_admin, AdminResolution};
use crate::handlers::found;
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, AuthenticationPoliciesConsole, AuthenticationPolicyFormValues};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use idp_contracts::admin::{
    AuthenticationPolicyResponse, AuthenticationPolicyUpsertRequest, RequiredMethodsPayload,
    AUTHENTICATION_METHOD_CODES,
};
use serde::Deserialize;

/// 選べる効果（api の `effect` 許可値。表示順）。
const EFFECT_OPTIONS: &[&str] = &["allow", "deny", "require_mfa", "require_specific_method"];

#[derive(Debug, Default, Deserialize)]
pub struct AuthenticationPolicyQuery {
    /// 編集対象のポリシー ID（指定時はフォームが編集モードで開く）。
    #[serde(default)]
    pub edit: Option<String>,
    #[serde(default)]
    pub saved: Option<String>,
    #[serde(default)]
    pub updated: Option<String>,
    #[serde(default)]
    pub deleted: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

pub async fn list(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<AuthenticationPolicyQuery>,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };
    let sso = crate::cookies::get(&headers, crate::cookies::SSO_SESSION_COOKIE).unwrap_or_default();
    let result = state
        .api
        .list_authentication_policies(&correlation.0, &tenant.0, &sso)
        .await;
    let (policies, mut error_key) = match result {
        Ok(response) => (
            response.policies,
            query.error.as_deref().and_then(error_key_for),
        ),
        Err(AdminApiError::Unauthorized) => return redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => (Vec::new(), Some("admin-settings-error-forbidden")),
        Err(_) => (Vec::new(), Some("admin-error-internal")),
    };

    // 編集モード: 一覧から対象を引いてフォームの初期値にする（api への追加の往復は要らない）。
    let editing = query.edit.as_deref().filter(|id| !id.is_empty());
    let (editing_id, values) = match editing {
        Some(id) => match policies.iter().find(|p| p.id == id) {
            Some(policy) => (Some(policy.id.as_str()), values_from(policy)),
            None => {
                // 一覧に無い ID（削除済み・別テナント）。新規作成のフォームへ落として理由を出す。
                error_key = error_key.or(Some("admin-auth-policy-error-not-found"));
                (None, AuthenticationPolicyFormValues::default())
            }
        },
        None => (None, AuthenticationPolicyFormValues::default()),
    };

    let messages = Messages::new(locale(&headers));
    Html(render(&AuthenticationPoliciesConsole {
        messages: &messages,
        tenant: &tenant.prefix(),
        admin: Some(&admin),
        csrf: &csrf_from(&headers, state.config.csrf_secret()),
        default_effect: state.config.auth_policy_default_effect(),
        saved: query.saved.is_some(),
        updated: query.updated.is_some(),
        deleted: query.deleted.is_some(),
        error_key,
        editing: editing_id,
        form_open: editing_id.is_some() || error_key.is_some(),
        effect_options: EFFECT_OPTIONS,
        method_options: AUTHENTICATION_METHOD_CODES,
        values: &values,
        policies: &policies,
    }))
    .into_response()
}

pub async fn create(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<AdminAuthenticationPolicyForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}/admin/authentication-policies", tenant.prefix());
    let body = match validate(&state, &headers, form) {
        Ok(body) => body,
        Err(error) => return found(&format!("{base}?error={error}")),
    };
    let sso = crate::cookies::get(&headers, crate::cookies::SSO_SESSION_COOKIE).unwrap_or_default();
    match state
        .api
        .create_authentication_policy(&correlation.0, &tenant.0, &sso, body)
        .await
    {
        Ok(_) => found(&format!("{base}?saved=1")),
        Err(e) => found(&format!("{base}?error={}", api_error_code(&e))),
    }
}

pub async fn update(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    Path((_tenant_id, policy_id)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<AdminAuthenticationPolicyForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}/admin/authentication-policies", tenant.prefix());
    let body = match validate(&state, &headers, form) {
        // 入力エラーは編集フォームへ戻す（`?edit=` を保つ。新規作成の空フォームへ落とすと
        // 入力し直しになる）。
        Err(error) => return found(&format!("{base}?edit={policy_id}&error={error}")),
        Ok(body) => body,
    };
    let sso = crate::cookies::get(&headers, crate::cookies::SSO_SESSION_COOKIE).unwrap_or_default();
    match state
        .api
        .update_authentication_policy(&correlation.0, &tenant.0, &sso, &policy_id, body)
        .await
    {
        Ok(_) => found(&format!("{base}?updated=1")),
        Err(e) => found(&format!(
            "{base}?edit={policy_id}&error={}",
            api_error_code(&e)
        )),
    }
}

pub async fn delete(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    Path((_tenant_id, policy_id)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<AdminAuthenticationPolicyDeleteForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}/admin/authentication-policies", tenant.prefix());
    if !idp_contracts::csrf::verify(
        &csrf_from(&headers, state.config.csrf_secret()),
        &form.csrf_token,
    ) {
        return found(&format!("{base}?error=csrf"));
    }
    let sso = crate::cookies::get(&headers, crate::cookies::SSO_SESSION_COOKIE).unwrap_or_default();
    match state
        .api
        .delete_authentication_policy(&correlation.0, &tenant.0, &sso, &policy_id)
        .await
    {
        Ok(()) => found(&format!("{base}?deleted=1")),
        Err(e) => found(&format!("{base}?error={}", api_error_code(&e))),
    }
}

/// フォームを api へ送る形へ写す。CSRF と、web 側で判定できる入力の妥当性をここで見る
/// （値そのものの妥当性 —— コードの文字種・CIDR の形・効果と `effect_params` の整合 —— は
/// api が最終判定する。二重に書くと片方だけ緩んだときに気付けない）。
fn validate(
    state: &WebState,
    headers: &HeaderMap,
    form: AdminAuthenticationPolicyForm,
) -> Result<AuthenticationPolicyUpsertRequest, &'static str> {
    if !idp_contracts::csrf::verify(
        &csrf_from(headers, state.config.csrf_secret()),
        &form.csrf_token,
    ) {
        return Err("csrf");
    }
    if form.policy_code.trim().is_empty() || form.policy_name.trim().is_empty() {
        return Err("validation");
    }
    let priority: i32 = form.priority.trim().parse().map_err(|_| "priority")?;
    let time_windows = parse_time_windows(&form.time_windows).map_err(|_| "time-window")?;
    let methods = selected_methods(&form);
    let user_verification = form.user_verification.is_some();
    // `require_specific_method` 以外で要求内容を送ると api が弾く。効果を切り替えたときに
    // チェックが残っていただけ、という取り違えを避けるため、送る側で落とす。
    let effect_params =
        (form.effect == "require_specific_method").then_some(RequiredMethodsPayload {
            methods,
            user_verification,
        });
    Ok(AuthenticationPolicyUpsertRequest {
        policy_code: form.policy_code.trim().to_string(),
        policy_name: form.policy_name.trim().to_string(),
        priority,
        enabled: form.enabled.is_some(),
        effect: form.effect,
        effect_params,
        client_ids: parse_list(&form.client_ids),
        user_ids: parse_list(&form.user_ids),
        ip_cidrs: parse_list(&form.ip_cidrs),
        time_windows,
        requested_acr: parse_list(&form.requested_acr),
    })
}

/// api の応答（`AuthenticationPolicyResponse`）をフォームの初期値へ戻す。
fn values_from(policy: &AuthenticationPolicyResponse) -> AuthenticationPolicyFormValues {
    let (methods, user_verification) = match &policy.effect_params {
        Some(params) => (params.methods.clone(), params.user_verification),
        None => (Vec::new(), false),
    };
    AuthenticationPolicyFormValues {
        policy_code: policy.policy_code.clone(),
        policy_name: policy.policy_name.clone(),
        priority: policy.priority.to_string(),
        enabled: policy.enabled,
        effect: policy.effect.clone(),
        methods,
        user_verification,
        client_ids: format_list(&policy.client_ids),
        user_ids: format_list(&policy.user_ids),
        ip_cidrs: format_list(&policy.ip_cidrs),
        time_windows: format_time_windows(&policy.time_windows),
        requested_acr: format_list(&policy.requested_acr),
    }
}

fn api_error_code(error: &AdminApiError) -> &'static str {
    match error {
        AdminApiError::Unauthorized => "session",
        AdminApiError::Forbidden => "forbidden",
        AdminApiError::Validation(_) => "validation",
        AdminApiError::Conflict(_) => "conflict",
        AdminApiError::NotFound => "not-found",
        AdminApiError::Transport(_) => "internal",
    }
}

fn error_key_for(code: &str) -> Option<&'static str> {
    match code {
        "csrf" => Some("login-error-csrf-retry"),
        "validation" => Some("admin-auth-policy-error-validation"),
        "priority" => Some("admin-auth-policy-error-priority"),
        "time-window" => Some("admin-auth-policy-error-time-window"),
        "conflict" => Some("admin-auth-policy-error-conflict"),
        "not-found" => Some("admin-auth-policy-error-not-found"),
        "forbidden" => Some("admin-settings-error-forbidden"),
        "session" => Some("admin-error-session"),
        _ => Some("admin-error-internal"),
    }
}

fn csrf_from(headers: &HeaderMap, secret: &[u8; 32]) -> String {
    let sso = crate::cookies::get(headers, crate::cookies::SSO_SESSION_COOKIE).unwrap_or_default();
    console_csrf_token(&sso, secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use idp_contracts::admin::TimeWindowPayload;

    fn policy() -> AuthenticationPolicyResponse {
        AuthenticationPolicyResponse {
            id: "p1".to_string(),
            policy_code: "office-hours".to_string(),
            policy_name: "Office hours".to_string(),
            priority: 10,
            enabled: true,
            effect: "require_specific_method".to_string(),
            effect_params: Some(RequiredMethodsPayload {
                methods: vec!["webauthn".to_string()],
                user_verification: true,
            }),
            client_ids: vec!["app-a".to_string(), "app-b".to_string()],
            user_ids: Vec::new(),
            ip_cidrs: vec!["10.0.0.0/8".to_string()],
            time_windows: vec![TimeWindowPayload {
                days: vec![1, 2, 3, 4, 5],
                start_minute: 540,
                end_minute: 1080,
                utc_offset_minutes: 540,
            }],
            requested_acr: Vec::new(),
            created_at: "2026-08-10T00:00:00Z".to_string(),
            updated_at: "2026-08-10T00:00:00Z".to_string(),
        }
    }

    /// 編集フォームは**全項目**を出す。出せない項目があると、全項目置換の保存でその条件が消える。
    #[test]
    fn edit_values_carry_every_condition_back_into_the_form() {
        let values = values_from(&policy());
        assert_eq!(values.policy_code, "office-hours");
        assert_eq!(values.priority, "10");
        assert!(values.enabled);
        assert_eq!(values.effect, "require_specific_method");
        assert!(values.has_method("webauthn"));
        assert!(values.user_verification);
        assert_eq!(values.client_ids, "app-a\napp-b");
        assert_eq!(values.ip_cidrs, "10.0.0.0/8");
        assert_eq!(
            values.time_windows,
            "mon,tue,wed,thu,fri 09:00-18:00 +09:00"
        );
    }

    #[test]
    fn unknown_effects_are_labelled_instead_of_being_shown_untranslated() {
        let messages = Messages::new(crate::i18n::Locale::Ja);
        let console = AuthenticationPoliciesConsole {
            messages: &messages,
            tenant: "/t",
            admin: Some("admin-1"),
            csrf: "csrf",
            default_effect: "allow",
            saved: false,
            updated: false,
            deleted: false,
            error_key: None,
            editing: None,
            form_open: false,
            effect_options: EFFECT_OPTIONS,
            method_options: AUTHENTICATION_METHOD_CODES,
            values: &AuthenticationPolicyFormValues::default(),
            policies: &[],
        };
        assert_eq!(
            console.effect_label("something_new"),
            "admin-auth-policy-effect-unknown"
        );
        assert_eq!(
            console.effect_label("deny"),
            "admin-auth-policy-effect-deny"
        );
    }

    /// 条件が 1 つも無いポリシーは**全員に当たる**。空欄で出すと「設定されていない」と読めるため、
    /// 明示の文言を出す。
    #[test]
    fn a_policy_without_conditions_says_it_matches_everyone() {
        let messages = Messages::new(crate::i18n::Locale::Ja);
        let console = AuthenticationPoliciesConsole {
            messages: &messages,
            tenant: "/t",
            admin: Some("admin-1"),
            csrf: "csrf",
            default_effect: "allow",
            saved: false,
            updated: false,
            deleted: false,
            error_key: None,
            editing: None,
            form_open: false,
            effect_options: EFFECT_OPTIONS,
            method_options: AUTHENTICATION_METHOD_CODES,
            values: &AuthenticationPolicyFormValues::default(),
            policies: &[],
        };
        let mut bare = policy();
        bare.client_ids.clear();
        bare.ip_cidrs.clear();
        bare.time_windows.clear();
        assert_eq!(
            console.condition_summary(&bare),
            messages.get("admin-auth-policy-condition-any")
        );
        assert_eq!(
            console.condition_summary(&policy()),
            "client×2 / network×1 / time×1"
        );
    }
}
