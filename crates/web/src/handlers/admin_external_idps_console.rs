//! 外部 IdP 設定の管理コンソール画面（`/{tenant_id}/admin/external-idps`。AP16）。
//!
//! AP10 で外部 IdP（OIDC）の設定 API を入れたが、画面が無く curl でしか触れなかった。
//! 外部 IdP は**利用者の認証元**であり、間違えるとログインできない／できてはいけない相手で
//! ログインできてしまう設定である。curl でしか確認・切り戻しができない状態は運用に向かない。
//!
//! データ操作は api の `/admin/external-idps` へ SSO Cookie 転送で委譲する。HTML フォームは
//! PATCH/DELETE を送れないため、更新・削除は専用の POST パス（`/{id}/update`・`/{id}/delete`）を
//! 経由して api の PATCH/DELETE へ変換する（認証ポリシー画面と同じ方式）。
//!
//! # クライアントシークレットの扱い
//!
//! api はシークレットを**返さない**（保存は暗号化、復号は外部 IdP へトークン要求を出す瞬間だけ）。
//! したがって編集フォームに現在値を出せない。空欄は「変更しない」を意味させ、リクエストから
//! `client_secret` を落とす。空欄を「削除」と解釈すると、表示名を直しただけで連携が壊れる。

use super::locale;
use crate::admin_dto::ExternalIdpView;
use crate::api_client::AdminApiError;
use crate::correlation::CorrelationId;
use crate::csrf::console_csrf_token;
use crate::handlers::admin_console::{redirect_to_login, resolve_admin, AdminResolution};
use crate::handlers::found;
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, ExternalIdpFormValues, ExternalIdpsConsole};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;
use serde_json::{json, Value};

const SEGMENT: &str = "/admin/external-idps";

#[derive(Debug, Default, Deserialize)]
pub struct ViewQuery {
    /// 編集対象の外部 IdP id（指定時はフォームが編集モードで開く）。
    #[serde(default)]
    pub edit: Option<String>,
    #[serde(default)]
    pub saved: Option<String>,
    #[serde(default)]
    pub deleted: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

/// 登録・更新フォーム。チェックボックスは「チェック時のみ送られる」ため `Option<String>` で受ける。
#[derive(Debug, Deserialize)]
pub struct ExternalIdpForm {
    #[serde(default)]
    pub provider_code: String,
    pub display_name: String,
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    #[serde(default)]
    pub scopes: String,
    #[serde(default)]
    pub enabled: Option<String>,
    #[serde(default)]
    pub allow_auto_link: Option<String>,
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
    Query(query): Query<ViewQuery>,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };
    let sso = sso(&headers);
    let (providers, mut error_key) = match state
        .api
        .list_external_idps(&correlation.0, &tenant.0, &sso)
        .await
    {
        Ok(v) => (v, query.error.as_deref().and_then(error_key_for)),
        Err(AdminApiError::Unauthorized) => return redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => (Vec::new(), Some("admin-settings-error-forbidden")),
        Err(e) => {
            tracing::error!(error = %e, "failed to load external idps");
            (Vec::new(), Some("admin-error-internal"))
        }
    };

    // 編集モード: 一覧から対象を引いてフォームの初期値にする（api への追加の往復は要らない）。
    let editing = query.edit.as_deref().filter(|id| !id.is_empty());
    let (editing_id, values) = match editing {
        Some(id) => match providers.iter().find(|p| p.id == id) {
            Some(provider) => (Some(provider.id.as_str()), values_from(provider)),
            None => {
                // 一覧に無い id（削除済み・別テナント）。新規登録のフォームへ落として理由を出す。
                error_key = error_key.or(Some("admin-external-idps-error-not-found"));
                (None, ExternalIdpFormValues::default())
            }
        },
        None => (None, ExternalIdpFormValues::default()),
    };

    let messages = Messages::new(locale(&headers));
    Html(render(&ExternalIdpsConsole {
        messages: &messages,
        tenant: &tenant.prefix(),
        admin: Some(&admin),
        csrf: &console_csrf_token(&sso, state.config.csrf_secret()),
        providers: &providers,
        editing: editing_id,
        values: &values,
        saved: query.saved.is_some(),
        deleted: query.deleted.is_some(),
        error_key,
    }))
    .into_response()
}

pub async fn create(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<ExternalIdpForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}{SEGMENT}", tenant.prefix());
    let sso = sso(&headers);
    if !csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
    }
    let mut body = common_fields(&form);
    body["provider_code"] = json!(form.provider_code.trim());
    // 新規登録の空欄は「シークレット無し（public クライアント）」。編集時と意味が違うので分ける。
    if !form.client_secret.is_empty() {
        body["client_secret"] = json!(form.client_secret);
    }

    match state
        .api
        .create_external_idp(&correlation.0, &tenant.0, &sso, body)
        .await
    {
        Ok(_) => found(&format!("{base}?saved=1")),
        Err(e) => found(&format!("{base}?error={}", error_code(&e))),
    }
}

pub async fn update(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_tenant_id, id)): Path<(String, String)>,
    Form(form): Form<ExternalIdpForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}{SEGMENT}", tenant.prefix());
    let sso = sso(&headers);
    if !csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf&edit={id}"));
    }
    let mut body = common_fields(&form);
    // 編集時の空欄は「変更しない」。api の部分更新は未指定の項目に触れないので、キーごと落とす。
    if !form.client_secret.is_empty() {
        body["client_secret"] = json!(form.client_secret);
    }

    match state
        .api
        .update_external_idp(&correlation.0, &tenant.0, &sso, &id, body)
        .await
    {
        Ok(_) => found(&format!("{base}?saved=1")),
        Err(e) => found(&format!("{base}?error={}&edit={id}", error_code(&e))),
    }
}

pub async fn delete(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_tenant_id, id)): Path<(String, String)>,
    Form(form): Form<DeleteForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}{SEGMENT}", tenant.prefix());
    let sso = sso(&headers);
    if !csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
    }
    match state
        .api
        .delete_external_idp(&correlation.0, &tenant.0, &sso, &id)
        .await
    {
        Ok(()) => found(&format!("{base}?deleted=1")),
        Err(e) => found(&format!("{base}?error={}", error_code(&e))),
    }
}

/// 作成・更新で共通の項目。`provider_code`（作成時のみ）と `client_secret`（有無で分岐）は呼び出し側で足す。
fn common_fields(form: &ExternalIdpForm) -> Value {
    json!({
        "display_name": form.display_name.trim(),
        "issuer": form.issuer.trim(),
        "authorization_endpoint": form.authorization_endpoint.trim(),
        "token_endpoint": form.token_endpoint.trim(),
        "jwks_uri": form.jwks_uri.trim(),
        "client_id": form.client_id.trim(),
        "scopes": parse_scopes(&form.scopes),
        "enabled": form.enabled.is_some(),
        "allow_auto_link": form.allow_auto_link.is_some(),
    })
}

/// 空白区切りの scope 文字列を配列へ。空要素は落とす（`"openid  email "` を許す）。
fn parse_scopes(raw: &str) -> Vec<String> {
    raw.split_whitespace().map(str::to_string).collect()
}

fn values_from(provider: &ExternalIdpView) -> ExternalIdpFormValues {
    ExternalIdpFormValues {
        provider_code: provider.provider_code.clone(),
        display_name: provider.display_name.clone(),
        issuer: provider.issuer.clone(),
        authorization_endpoint: provider.authorization_endpoint.clone(),
        token_endpoint: provider.token_endpoint.clone(),
        jwks_uri: provider.jwks_uri.clone(),
        client_id: provider.client_id.clone(),
        has_client_secret: provider.has_client_secret,
        scopes: provider.scopes.join(" "),
        enabled: provider.enabled,
        allow_auto_link: provider.allow_auto_link,
    }
}

/// api のエラーをクエリ文字列のコードへ落とす（Post/Redirect/Get で理由を持ち回る）。
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
        "validation" => Some("admin-external-idps-error-validation"),
        "conflict" => Some("admin-external-idps-error-conflict"),
        "notfound" => Some("admin-external-idps-error-not-found"),
        "internal" => Some("admin-error-internal"),
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

    fn form(secret: &str) -> ExternalIdpForm {
        ExternalIdpForm {
            provider_code: "corp".into(),
            display_name: "Corp IdP".into(),
            issuer: "https://idp.example.com".into(),
            authorization_endpoint: "https://idp.example.com/authorize".into(),
            token_endpoint: "https://idp.example.com/token".into(),
            jwks_uri: "https://idp.example.com/jwks".into(),
            client_id: "abc".into(),
            client_secret: secret.into(),
            scopes: "openid  email ".into(),
            enabled: Some("1".into()),
            allow_auto_link: None,
            csrf_token: "t".into(),
        }
    }

    /// 空白区切りの scope は配列になり、空要素は落ちる。
    #[test]
    fn scopes_are_split_on_whitespace() {
        assert_eq!(parse_scopes("openid  email "), vec!["openid", "email"]);
        assert!(parse_scopes("   ").is_empty());
    }

    /// チェックの無いチェックボックスは送られてこない。`false` として送る（未指定にすると
    /// api の部分更新が「変更しない」と解釈し、チェックを外しても無効化できない）。
    #[test]
    fn unchecked_boxes_are_sent_as_false_not_omitted() {
        let body = common_fields(&form(""));
        assert_eq!(body["enabled"], serde_json::json!(true));
        assert_eq!(body["allow_auto_link"], serde_json::json!(false));
    }

    /// シークレットはフォームの共通項目に含めない。編集時の空欄を「変更しない」と扱うため、
    /// 有無の判断を呼び出し側に残す（ここで常に載せると、空欄が削除の意味になってしまう）。
    #[test]
    fn the_client_secret_is_never_part_of_the_common_fields() {
        assert!(common_fields(&form("s3cret"))
            .get("client_secret")
            .is_none());
        assert!(common_fields(&form("")).get("client_secret").is_none());
    }
}
