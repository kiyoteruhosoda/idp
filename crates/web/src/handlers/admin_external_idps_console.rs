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
//!
//! # プロトコル（OIDC / SAML）の出し分け（AP12）
//!
//! 外部 IdP は OIDC と SAML の 2 種類あり（ADR-0027）、必要な項目がまったく違う。画面は 1 枚の
//! フォームで両方を扱い、**選んだプロトコルの欄だけ**を api へ送る。両方の欄を常に送ると、api が
//! 「片方だけ埋まった半端な設定」を作れてしまい、誤りがログイン時まで表に出ない。
//!
//! 登録済みプロバイダの**プロトコルは変更できない**（api が拒否する。同じ `provider_code` のまま
//! 切り替えると、既存の連携が別プロトコルの識別子を指したまま残る）。編集時は選択を固定する。
//!
//! `protocol` は更新でも必ず送る。api の部分更新はプロトコル固有の設定を**まとめて**差し替える
//! 作りで、`protocol` を省くとエンドポイントの変更が黙って無視される。

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
use axum::extract::{Extension, Multipart, Path, Query, State};
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
///
/// プロトコル固有の項目はすべて `#[serde(default)]` にする。片方のプロトコルの欄しか出ていない
/// 画面からの送信でも受け取れる必要があり、**必須かどうかを決めるのは api** だからである
/// （ここで必須にすると、判断が 2 か所に散る）。
#[derive(Debug, Deserialize)]
pub struct ExternalIdpForm {
    #[serde(default)]
    pub provider_code: String,
    pub display_name: String,
    /// `oidc` / `saml`。未指定は `oidc`（既存のフォームからの送信を壊さない）。
    #[serde(default)]
    pub protocol: String,
    pub issuer: String,
    #[serde(default)]
    pub authorization_endpoint: String,
    #[serde(default)]
    pub token_endpoint: String,
    #[serde(default)]
    pub jwks_uri: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    #[serde(default)]
    pub scopes: String,
    #[serde(default)]
    pub saml_sso_url: String,
    #[serde(default)]
    pub saml_certificates: String,
    #[serde(default)]
    pub saml_name_id_format: String,
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
        imported: false,
        error_key,
    }))
    .into_response()
}

/// 外部 IdP のメタデータを取り込み、登録フォームに初期値を反映して再描画する（AP12）。
///
/// 取り込みは**登録ではない**ので PRG は挟まない（管理者が値を確認してから登録する）。取り込み元は
/// ファイルアップロード（`metadata_file`）または貼り付け（`metadata_xml`）で、ファイルを優先する
/// （SP メタデータ取り込みと同じ操作にする。画面ごとに操作が違うと迷う）。
pub async fn import_metadata(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    multipart: Multipart,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };
    let base = format!("{}{SEGMENT}", tenant.prefix());
    let sso = sso(&headers);
    let upload = read_metadata_upload(multipart).await;
    if !csrf_valid(&sso, &upload.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
    }

    let (values, imported, error_key) = match upload.metadata_xml() {
        None => (
            saml_defaults(),
            false,
            Some("admin-external-idps-error-import"),
        ),
        Some(xml) => match state
            .api
            .import_external_idp_metadata(&correlation.0, &tenant.0, &sso, &xml)
            .await
        {
            Ok(parsed) => (
                ExternalIdpFormValues {
                    display_name: parsed.display_name,
                    // entityID がそのまま `issuer`（アサーションの `<Issuer>` と完全一致で照合する値）。
                    issuer: parsed.entity_id,
                    saml_sso_url: parsed.sso_url,
                    saml_certificates: parsed.certificates.join("\n\n"),
                    saml_name_id_format: parsed.name_id_format,
                    ..saml_defaults()
                },
                true,
                None,
            ),
            Err(AdminApiError::Unauthorized) => return redirect_to_login(&tenant),
            Err(AdminApiError::Forbidden) => (
                saml_defaults(),
                false,
                Some("admin-settings-error-forbidden"),
            ),
            // 解析できない XML（SP のメタデータを貼った・SSO が無い等）は利用者の入力誤り。
            Err(AdminApiError::Validation(_) | AdminApiError::NotFound) => (
                saml_defaults(),
                false,
                Some("admin-external-idps-error-import"),
            ),
            Err(e) => {
                tracing::error!(error = %e, "failed to import external idp metadata");
                (saml_defaults(), false, Some("admin-error-internal"))
            }
        },
    };

    let providers = state
        .api
        .list_external_idps(&correlation.0, &tenant.0, &sso)
        .await
        .unwrap_or_default();

    let messages = Messages::new(locale(&headers));
    Html(render(&ExternalIdpsConsole {
        messages: &messages,
        tenant: &tenant.prefix(),
        admin: Some(&admin),
        csrf: &console_csrf_token(&sso, state.config.csrf_secret()),
        providers: &providers,
        editing: None,
        values: &values,
        saved: false,
        deleted: false,
        imported,
        error_key,
    }))
    .into_response()
}

/// 取り込み後のフォームは SAML で開く（IdP メタデータを読んだ直後なので）。
fn saml_defaults() -> ExternalIdpFormValues {
    ExternalIdpFormValues {
        protocol: "saml".to_string(),
        ..ExternalIdpFormValues::default()
    }
}

/// multipart から読み取った取り込み入力。
struct MetadataUpload {
    csrf_token: String,
    pasted: String,
    uploaded: Option<String>,
    /// 読み取りに失敗した（サイズ超過・非 UTF-8・壊れた multipart）。
    read_failed: bool,
}

impl MetadataUpload {
    /// 取り込みに使う XML。ファイルがあればそちらを優先し、無ければ貼り付けを使う。
    fn metadata_xml(&self) -> Option<String> {
        if self.read_failed {
            return None;
        }
        self.uploaded
            .clone()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| Some(self.pasted.clone()))
            .filter(|s| !s.trim().is_empty())
    }
}

/// アップロードされたメタデータは通常数 KB。リクエスト全体は `DefaultBodyLimit` でも制限されるが、
/// 念のため上限を設ける（SP メタデータ取り込みと同じ値）。
const MAX_METADATA_BYTES: usize = 1024 * 1024;

async fn read_metadata_upload(mut multipart: Multipart) -> MetadataUpload {
    let mut upload = MetadataUpload {
        csrf_token: String::new(),
        pasted: String::new(),
        uploaded: None,
        read_failed: false,
    };
    loop {
        match multipart.next_field().await {
            Ok(Some(field)) => match field.name() {
                Some("csrf_token") => upload.csrf_token = field.text().await.unwrap_or_default(),
                Some("metadata_xml") => upload.pasted = field.text().await.unwrap_or_default(),
                Some("metadata_file") => match field.bytes().await {
                    Ok(bytes) if bytes.is_empty() => {}
                    Ok(bytes) if bytes.len() > MAX_METADATA_BYTES => upload.read_failed = true,
                    Ok(bytes) => match String::from_utf8(bytes.to_vec()) {
                        Ok(text) => upload.uploaded = Some(text),
                        Err(_) => upload.read_failed = true,
                    },
                    Err(_) => upload.read_failed = true,
                },
                _ => {
                    let _ = field.bytes().await;
                }
            },
            Ok(None) => break,
            Err(_) => {
                upload.read_failed = true;
                break;
            }
        }
    }
    upload
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
///
/// プロトコル固有の欄は**選んだ側だけ**を載せる。`protocol` は更新でも必ず送る（api はこれが
/// 無いとプロトコル固有の設定を差し替えない）。
fn common_fields(form: &ExternalIdpForm) -> Value {
    let protocol = protocol_of(form);
    let mut body = json!({
        "display_name": form.display_name.trim(),
        "protocol": protocol,
        "issuer": form.issuer.trim(),
        "enabled": form.enabled.is_some(),
        "allow_auto_link": form.allow_auto_link.is_some(),
    });
    if protocol == "saml" {
        body["saml_sso_url"] = json!(form.saml_sso_url.trim());
        body["saml_certificates"] = json!(parse_certificates(&form.saml_certificates));
        body["saml_name_id_format"] = json!(form.saml_name_id_format.trim());
    } else {
        body["authorization_endpoint"] = json!(form.authorization_endpoint.trim());
        body["token_endpoint"] = json!(form.token_endpoint.trim());
        body["jwks_uri"] = json!(form.jwks_uri.trim());
        body["client_id"] = json!(form.client_id.trim());
        body["scopes"] = json!(parse_scopes(&form.scopes));
    }
    body
}

/// フォームのプロトコル。未知の値は `oidc` に丸めず**そのまま api へ渡す**——丸めると、SAML の
/// つもりで送った設定が OIDC として登録される。空欄だけは既定（`oidc`）に落とす。
fn protocol_of(form: &ExternalIdpForm) -> &str {
    match form.protocol.trim() {
        "" => "oidc",
        other => other,
    }
}

/// 空白区切りの scope 文字列を配列へ。空要素は落とす（`"openid  email "` を許す）。
fn parse_scopes(raw: &str) -> Vec<String> {
    raw.split_whitespace().map(str::to_string).collect()
}

/// 証明書欄を配列へ。**空行で区切る**——PEM の本文は行で折り返されるため、行区切りにすると
/// 1 枚の証明書が複数枚に割れる。各証明書内の改行・空白は api 側で除去される。
fn parse_certificates(raw: &str) -> Vec<String> {
    raw.split("\n\n")
        .map(|block| block.split_whitespace().collect::<String>())
        .filter(|block| !block.is_empty())
        .collect()
}

fn values_from(provider: &ExternalIdpView) -> ExternalIdpFormValues {
    ExternalIdpFormValues {
        provider_code: provider.provider_code.clone(),
        display_name: provider.display_name.clone(),
        protocol: provider.protocol.clone(),
        issuer: provider.issuer.clone(),
        authorization_endpoint: provider.authorization_endpoint.clone().unwrap_or_default(),
        token_endpoint: provider.token_endpoint.clone().unwrap_or_default(),
        jwks_uri: provider.jwks_uri.clone().unwrap_or_default(),
        client_id: provider.client_id.clone().unwrap_or_default(),
        has_client_secret: provider.has_client_secret,
        scopes: provider.scopes.join(" "),
        saml_sso_url: provider.saml_sso_url.clone().unwrap_or_default(),
        // 保存済みの証明書は空行区切りで戻す（入力と同じ形。編集で追記・差し替えができる）。
        saml_certificates: provider.saml_certificates.join("\n\n"),
        saml_name_id_format: provider.saml_name_id_format.clone().unwrap_or_default(),
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
        "import" => Some("admin-external-idps-error-import"),
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
            protocol: "oidc".into(),
            issuer: "https://idp.example.com".into(),
            authorization_endpoint: "https://idp.example.com/authorize".into(),
            token_endpoint: "https://idp.example.com/token".into(),
            jwks_uri: "https://idp.example.com/jwks".into(),
            client_id: "abc".into(),
            client_secret: secret.into(),
            scopes: "openid  email ".into(),
            saml_sso_url: String::new(),
            saml_certificates: String::new(),
            saml_name_id_format: String::new(),
            enabled: Some("1".into()),
            allow_auto_link: None,
            csrf_token: "t".into(),
        }
    }

    fn saml_form() -> ExternalIdpForm {
        ExternalIdpForm {
            protocol: "saml".into(),
            issuer: "urn:idp:corp".into(),
            saml_sso_url: "https://idp.example.com/sso".into(),
            saml_certificates: "MIIB\nAAAA==\n\nMIIC\nBBBB==".into(),
            saml_name_id_format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".into(),
            ..form("")
        }
    }

    /// 空白区切りの scope は配列になり、空要素は落ちる。
    #[test]
    fn scopes_are_split_on_whitespace() {
        assert_eq!(parse_scopes("openid  email "), vec!["openid", "email"]);
        assert!(parse_scopes("   ").is_empty());
    }

    /// 証明書は**空行**で区切る。行区切りにすると、折り返された 1 枚の PEM 本文が
    /// 複数枚の証明書に割れて、どれも読めなくなる。
    #[test]
    fn certificates_are_split_on_blank_lines_not_line_breaks() {
        assert_eq!(
            parse_certificates("MIIB\nAAAA==\n\nMIIC\nBBBB=="),
            vec!["MIIBAAAA==", "MIICBBBB=="]
        );
        assert_eq!(parse_certificates("MIIB\nAAAA=="), vec!["MIIBAAAA=="]);
        assert!(parse_certificates("  \n\n  ").is_empty());
    }

    /// **選んだプロトコルの欄だけ**を送る。両方送ると api が半端な設定を作れてしまい、
    /// 誤りがログイン時まで表に出ない。
    #[test]
    fn only_the_selected_protocols_fields_are_sent() {
        let oidc = common_fields(&form(""));
        assert_eq!(oidc["protocol"], json!("oidc"));
        assert_eq!(
            oidc["authorization_endpoint"],
            json!("https://idp.example.com/authorize")
        );
        assert!(oidc.get("saml_sso_url").is_none());

        let saml = common_fields(&saml_form());
        assert_eq!(saml["protocol"], json!("saml"));
        assert_eq!(saml["saml_sso_url"], json!("https://idp.example.com/sso"));
        assert_eq!(
            saml["saml_certificates"],
            json!(["MIIBAAAA==", "MIICBBBB=="])
        );
        assert!(saml.get("authorization_endpoint").is_none());
        assert!(saml.get("scopes").is_none());
    }

    /// `protocol` は更新でも必ず送る。api はこれが無いとプロトコル固有の設定を差し替えないため、
    /// 省くとエンドポイントの変更が黙って無視される。
    #[test]
    fn the_protocol_is_always_sent_so_endpoint_edits_are_not_ignored() {
        assert_eq!(common_fields(&form("s3cret"))["protocol"], json!("oidc"));
        // 未知の値は既定へ丸めない（丸めると SAML のつもりの設定が OIDC として登録される）。
        let unknown = ExternalIdpForm {
            protocol: "ws-fed".into(),
            ..form("")
        };
        assert_eq!(common_fields(&unknown)["protocol"], json!("ws-fed"));
        // 空欄だけは既定（oidc）に落とす。
        let blank = ExternalIdpForm {
            protocol: String::new(),
            ..form("")
        };
        assert_eq!(common_fields(&blank)["protocol"], json!("oidc"));
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
