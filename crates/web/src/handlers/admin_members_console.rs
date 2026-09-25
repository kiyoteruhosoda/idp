//! テナントメンバー（HOME/GUEST）管理画面（web。ADR-0009 §3・§6・MT13）。
//!
//! メンバー管理の起点となるハブ画面。api の JSON 管理 API を管理者の SSO Cookie 転送で呼ぶ。
//! ゲストはメンバーシップの解除のみでき（HOME は api 側が 403 を返す）、所属元（HOME）の利用者には
//! 無効化・有効化・パスワード再発行・削除を提供する（対象が所属元でない場合は api 側が 404 を返す）。
//!
//! 一覧の**絞り込み・ページングは api（DB）側**が行う（MT22）。web は検索語とページ位置をクエリで
//! 引き継ぎ、応答の `total` からページャの前後リンクを組み立てるだけで、全件を受け取らない。

use super::locale;
use crate::api_client::AdminApiError;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::console_csrf_token;
use crate::dto::{MemberActionForm, MemberNoteForm, MemberStatusForm};
use crate::handlers::admin_accounts_console::{self, AccountTarget};
use crate::handlers::admin_console::{
    forbidden_response, redirect_to_login, resolve_admin, AdminContext, AdminResolution,
};
use crate::handlers::found;
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, ConsoleNotice, MemberDetail, PasswordResetResult};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

/// 一覧（アカウントの一覧を人に絞ったもの。ADR-0065）。操作の後の戻り先。
const MEMBERS_LIST: &str = "/admin/accounts?kind=user";

#[derive(Debug, Default, Deserialize)]
pub struct ViewQuery {
    #[serde(default)]
    pub error: Option<String>,
    /// 完了通知（Post/Redirect/Get で操作結果を伝える。MT21 の MFA 解除など）。
    #[serde(default)]
    pub notice: Option<String>,
    /// メンバー一覧の絞り込み語（メールアドレス・氏名の部分一致。大文字小文字を無視）。
    /// 絞り込みは api（DB）側で行う。
    #[serde(default)]
    pub q: Option<String>,
    /// ページャの読み飛ばし件数。未指定は 0。
    #[serde(default)]
    pub offset: Option<i64>,
}

/// メンバー 1 人の画面（`GET /{tenant_id}/admin/members/{user_id}`）。
///
/// ⚠ **一覧は探す場所、ここは操作する場所**と分ける。一覧の 1 セルへ 7 つのボタンを並べて
/// いた頃は、操作列 168px にボタンが縦 7 段に積まれ、幅の広いものは右端で切れていた。
pub async fn detail(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    // ⚠ **経路には `{tenant_id}` と `{user_id}` の 2 つがある。** 1 つだけで受けると
    //   `WrongNumberOfParameters` で弾かれ、ハンドラへ入る前に 500 になる
    //   （同じファイルの他のハンドラも 2 つで受けている）。
    Path((_, user_id)): Path<(String, String)>,
    Query(query): Query<ViewQuery>,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };
    // ⚠ `Messages` は `Send` ではないので、`await` をまたいで持たない（api 呼び出しの後に作る）。
    let sso = sso(&headers);
    let result = state
        .api
        .get_member(&correlation.0, &tenant.0, &sso, &user_id)
        .await;
    // 使えるアプリは `idp.applications:read` が要る。持たない管理者にはメンバーの画面ごと
    // 断らず、アプリの欄だけを出さない（メモや復旧の操作はアプリの権限と関係が無い）。
    let applications = match &result {
        Ok(_) => state
            .api
            .list_member_applications(&correlation.0, &tenant.0, &sso, &user_id)
            .await
            .ok(),
        Err(_) => None,
    };
    let messages = Messages::new(locale(&headers));
    match result {
        Ok(member) => Html(render(&MemberDetail {
            messages: &messages,
            tenant: &tenant.prefix(),
            admin: Some(admin.chrome()),
            member: &member,
            applications: applications.as_ref(),
            csrf: &csrf_from(&headers, state.config.csrf_secret()),
            error_key: query.error.as_deref().and_then(error_key_for),
            notice_key: query.notice.as_deref().and_then(notice_key_for),
        }))
        .into_response(),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => forbidden_response(&headers),
        // 他テナントのメンバーの存在を推測させないため、不存在も 404 のまま一覧へ戻す。
        Err(AdminApiError::NotFound) => {
            found(&format!("{}{MEMBERS_LIST}&error=notfound", tenant.prefix()))
        }
        Err(_) => internal_error(&messages, &tenant, &admin),
    }
}

/// 管理者メモを書く（`POST /{tenant_id}/admin/members/{user_id}/note`。ADR-0063）。
///
/// 書き方はサービスアカウントと同じ（[`admin_accounts_console::write_note`]。ADR-0065）。
pub async fn update_note(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, user_id)): Path<(String, String)>,
    Form(form): Form<MemberNoteForm>,
) -> Response {
    admin_accounts_console::write_note(
        &state,
        &correlation,
        &tenant,
        &headers,
        AccountTarget::User(&user_id),
        &form,
    )
    .await
}

/// このメンバーをアプリへ割り当てる
/// （`POST /{tenant_id}/admin/members/{user_id}/applications/{application_id}/assign`）。
pub async fn assign_application(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, user_id, application_id)): Path<(String, String, String)>,
    Form(form): Form<MemberActionForm>,
) -> Response {
    admin_accounts_console::change_assignment(
        &state,
        &correlation,
        &tenant,
        &headers,
        AccountTarget::User(&user_id),
        &application_id,
        &form,
        true,
    )
    .await
}

/// このメンバーの割り当てを外す
/// （`POST /{tenant_id}/admin/members/{user_id}/applications/{application_id}/unassign`）。
pub async fn unassign_application(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, user_id, application_id)): Path<(String, String, String)>,
    Form(form): Form<MemberActionForm>,
) -> Response {
    admin_accounts_console::change_assignment(
        &state,
        &correlation,
        &tenant,
        &headers,
        AccountTarget::User(&user_id),
        &application_id,
        &form,
        false,
    )
    .await
}

#[derive(Debug, Deserialize)]
pub struct RevokeForm {
    pub csrf_token: String,
}

/// ゲストメンバーシップの解除（`POST /{tenant_id}/admin/members/{user_id}/revoke`）。
pub async fn revoke(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, user_id)): Path<(String, String)>,
    Form(form): Form<RevokeForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}{MEMBERS_LIST}", tenant.prefix());
    if !csrf_valid(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}&error=csrf"));
    }
    let result = state
        .api
        .revoke_member(&correlation.0, &tenant.0, &sso(&headers), &user_id)
        .await;
    match result {
        Ok(()) => found(&base),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => found(&format!("{base}&error=forbidden")),
        Err(AdminApiError::NotFound) => found(&format!("{base}&error=notfound")),
        Err(_) => found(&format!("{base}&error=internal")),
    }
}

/// 利用者の無効化・有効化（`POST /{tenant_id}/admin/members/{user_id}/status`）。
/// 所属元（HOME）が当該テナントの利用者のみ。自分自身は変更できない（api 側が 403 を返す）。
pub async fn set_status(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, user_id)): Path<(String, String)>,
    Form(form): Form<MemberStatusForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}{MEMBERS_LIST}", tenant.prefix());
    if !csrf_valid(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}&error=csrf"));
    }
    let result = state
        .api
        .update_user_status(
            &correlation.0,
            &tenant.0,
            &sso(&headers),
            &user_id,
            form.status.trim(),
        )
        .await;
    match result {
        Ok(_) => found(&base),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => found(&format!("{base}&error=self")),
        Err(AdminApiError::NotFound) => found(&format!("{base}&error=user-notfound")),
        Err(AdminApiError::Validation(_)) => found(&format!("{base}&error=internal")),
        Err(_) => found(&format!("{base}&error=internal")),
    }
}

/// 利用者のパスワード再発行（`POST /{tenant_id}/admin/members/{user_id}/reset-password`）。
/// 成功時は生成パスワードを一度だけ表示する。
pub async fn reset_password(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, user_id)): Path<(String, String)>,
    Form(form): Form<MemberActionForm>,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };
    let base = format!("{}{MEMBERS_LIST}", tenant.prefix());
    if !csrf_valid(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}&error=csrf"));
    }
    let reset = match state
        .api
        .reset_user_password(&correlation.0, &tenant.0, &sso(&headers), &user_id)
        .await
    {
        Ok(v) => v,
        Err(AdminApiError::Unauthorized) => return redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => return found(&format!("{base}&error=self")),
        Err(AdminApiError::NotFound) => return found(&format!("{base}&error=user-notfound")),
        Err(_) => return found(&format!("{base}&error=internal")),
    };
    let messages = Messages::new(locale(&headers));
    let subject = if form.email.trim().is_empty() {
        user_id.clone()
    } else {
        form.email.trim().to_string()
    };
    Html(render(&PasswordResetResult {
        messages: &messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        subject: &subject,
        setup_url: &reset.setup_url,
        setup_expires_at: &reset.setup_expires_at,
        back_href: &base,
        back_label_key: "admin-members-back",
    }))
    .into_response()
}

/// ゲストメンバーシップの一時停止（`POST /{tenant_id}/admin/members/{user_id}/suspend`。MT24）。
/// 解除（削除）と違い、メンバーシップと権限を残したままアクセスだけを止める。
pub async fn suspend(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, user_id)): Path<(String, String)>,
    Form(form): Form<MemberActionForm>,
) -> Response {
    set_member_status(
        &state,
        &correlation,
        &tenant,
        &headers,
        &user_id,
        &form,
        "SUSPENDED",
    )
    .await
}

/// 一時停止したゲストメンバーシップの再開（`POST /{tenant_id}/admin/members/{user_id}/resume`。MT24）。
pub async fn resume(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, user_id)): Path<(String, String)>,
    Form(form): Form<MemberActionForm>,
) -> Response {
    set_member_status(
        &state,
        &correlation,
        &tenant,
        &headers,
        &user_id,
        &form,
        "ACTIVE",
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn set_member_status(
    state: &WebState,
    correlation: &CorrelationId,
    tenant: &WebTenant,
    headers: &HeaderMap,
    user_id: &str,
    form: &MemberActionForm,
    status: &str,
) -> Response {
    match resolve_admin(state, correlation, tenant, headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}{MEMBERS_LIST}", tenant.prefix());
    if !csrf_valid(headers, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}&error=csrf"));
    }
    let notice = if status == "SUSPENDED" {
        "member-suspended"
    } else {
        "member-resumed"
    };
    match state
        .api
        .update_member_status(&correlation.0, &tenant.0, &sso(headers), user_id, status)
        .await
    {
        Ok(()) => found(&format!("{base}&notice={notice}")),
        Err(AdminApiError::Unauthorized) => redirect_to_login(tenant),
        // HOME・遷移できない状態（既に停止済み等）は api が 403 を返す。
        Err(AdminApiError::Forbidden) => found(&format!("{base}&error=forbidden")),
        Err(AdminApiError::NotFound) => found(&format!("{base}&error=notfound")),
        Err(_) => found(&format!("{base}&error=internal")),
    }
}

/// 利用者の MFA 解除（`POST /{tenant_id}/admin/members/{user_id}/reset-mfa`。MT21）。
/// 端末を失って本人では解除できない状態からの復旧手段。TOTP と Passkey をまとめて外す。
/// 秘密情報を伴わないため結果画面は出さず、一覧へ戻して完了通知を出す（Post/Redirect/Get）。
pub async fn reset_mfa(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, user_id)): Path<(String, String)>,
    Form(form): Form<MemberActionForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}{MEMBERS_LIST}", tenant.prefix());
    if !csrf_valid(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}&error=csrf"));
    }
    match state
        .api
        .reset_user_mfa(&correlation.0, &tenant.0, &sso(&headers), &user_id)
        .await
    {
        // 何も設定されていなかった場合も成功だが、管理者には区別して伝える（「効いていない」と
        // 誤解して操作を繰り返すのを防ぐ）。
        Ok(reset) if !reset.totp_removed && reset.passkeys_removed == 0 => {
            found(&format!("{base}&notice=mfa-none"))
        }
        Ok(_) => found(&format!("{base}&notice=mfa-reset")),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => found(&format!("{base}&error=self")),
        Err(AdminApiError::NotFound) => found(&format!("{base}&error=user-notfound")),
        Err(_) => found(&format!("{base}&error=internal")),
    }
}

/// 利用者のトークン再発行（`POST /{tenant_id}/admin/members/{user_id}/reissue-tokens`。ADR-0047）。
///
/// 発行済みの refresh token をまとめて失効させ、アプリに取り直させる。落とすのはトークンだけで、
/// 無効化（業務が止まる）やパスワード再発行（本人に再設定を強いる）まで持ち出さずに済む一段。
/// 秘密情報を伴わないため結果画面は出さず、一覧へ戻して完了通知を出す（Post/Redirect/Get）。
pub async fn reissue_tokens(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, user_id)): Path<(String, String)>,
    Form(form): Form<MemberActionForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}{MEMBERS_LIST}", tenant.prefix());
    if !csrf_valid(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}&error=csrf"));
    }
    match state
        .api
        .reissue_user_tokens(&correlation.0, &tenant.0, &sso(&headers), &user_id)
        .await
    {
        // 落とすものが無かった場合も成功だが、管理者には区別して伝える（「効いていない」と
        // 誤解して操作を繰り返すのを防ぐ。MFA 解除・ロック解除と同じ扱い）。
        Ok(result) if result.revoked == 0 => found(&format!("{base}&notice=tokens-none")),
        Ok(_) => found(&format!("{base}&notice=tokens-reissued")),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => found(&format!("{base}&error=forbidden")),
        Err(AdminApiError::NotFound) => found(&format!("{base}&error=user-notfound")),
        Err(_) => found(&format!("{base}&error=internal")),
    }
}

/// アカウントロックの解除（`POST /{tenant_id}/admin/members/{user_id}/unlock`。AP6）。
/// 段階的ロックでロック時間が伸びた利用者を、期限を待たずに戻す。秘密情報を伴わないため
/// 一覧へ戻して完了通知を出す（Post/Redirect/Get）。
pub async fn unlock(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, user_id)): Path<(String, String)>,
    Form(form): Form<MemberActionForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}{MEMBERS_LIST}", tenant.prefix());
    if !csrf_valid(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}&error=csrf"));
    }
    match state
        .api
        .unlock_user(&correlation.0, &tenant.0, &sso(&headers), &user_id)
        .await
    {
        // 元からロックされていなかった場合も成功だが、管理者には区別して伝える
        //（「効いていない」と誤解して操作を繰り返すのを防ぐ。MFA 解除と同じ扱い）。
        Ok(result) if !result.was_locked => found(&format!("{base}&notice=unlock-none")),
        Ok(_) => found(&format!("{base}&notice=unlocked")),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => found(&format!("{base}&error=forbidden")),
        Err(AdminApiError::NotFound) => found(&format!("{base}&error=user-notfound")),
        Err(_) => found(&format!("{base}&error=internal")),
    }
}

/// 利用者の削除（`POST /{tenant_id}/admin/members/{user_id}/delete`）。
/// 所属元（HOME）が当該テナントの利用者のみ。自分自身は削除できない。
pub async fn delete(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, user_id)): Path<(String, String)>,
    Form(form): Form<MemberActionForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}{MEMBERS_LIST}", tenant.prefix());
    if !csrf_valid(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}&error=csrf"));
    }
    let result = state
        .api
        .delete_user(&correlation.0, &tenant.0, &sso(&headers), &user_id)
        .await;
    match result {
        Ok(()) => found(&base),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => found(&format!("{base}&error=self")),
        Err(AdminApiError::NotFound) => found(&format!("{base}&error=user-notfound")),
        Err(_) => found(&format!("{base}&error=internal")),
    }
}

/// Post/Redirect/Get で戻ったときに出す完了通知の翻訳キー。
pub(crate) fn notice_key_for(notice: &str) -> Option<&'static str> {
    match notice {
        "mfa-reset" => Some("admin-members-mfa-reset-done"),
        "mfa-none" => Some("admin-members-mfa-reset-none"),
        "tokens-reissued" => Some("admin-members-token-reissue-done"),
        "tokens-none" => Some("admin-members-token-reissue-none"),
        "unlocked" => Some("admin-members-unlock-done"),
        "unlock-none" => Some("admin-members-unlock-none"),
        "member-suspended" => Some("admin-members-suspend-done"),
        "member-resumed" => Some("admin-members-resume-done"),
        "note-saved" => Some("admin-member-note-saved"),
        "note-cleared" => Some("admin-member-note-cleared"),
        "application-assigned" => Some("admin-member-applications-assigned"),
        "application-unassigned" => Some("admin-member-applications-unassigned"),
        _ => None,
    }
}

pub(crate) fn error_key_for(error: &str) -> Option<&'static str> {
    match error {
        "csrf" => Some("admin-error-csrf"),
        "forbidden" => Some("admin-members-error-home"),
        "notfound" => Some("admin-members-error-notfound"),
        "self" => Some("admin-members-error-self"),
        "user-notfound" => Some("admin-members-error-user-notfound"),
        "forbidden-write" => Some("admin-member-error-forbidden-write"),
        "note-too-long" => Some("admin-member-note-too-long"),
        "application-notfound" => Some("admin-member-applications-error-notfound"),
        "internal" => Some("admin-error-internal"),
        _ => None,
    }
}

fn sso(headers: &HeaderMap) -> String {
    cookies::get(headers, cookies::SSO_SESSION_COOKIE).unwrap_or_default()
}

fn csrf_from(headers: &HeaderMap, key: &[u8]) -> String {
    cookies::get(headers, cookies::SSO_SESSION_COOKIE)
        .map(|s| console_csrf_token(&s, key))
        .unwrap_or_default()
}

fn csrf_valid(headers: &HeaderMap, submitted: &str, key: &[u8]) -> bool {
    cookies::get(headers, cookies::SSO_SESSION_COOKIE)
        .map(|s| console_csrf_token(&s, key) == submitted)
        .unwrap_or(false)
}

fn internal_error(messages: &Messages, tenant: &WebTenant, admin: &AdminContext) -> Response {
    let body = render(&ConsoleNotice {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        heading: None,
        message: &messages.get("admin-error-internal"),
        is_error: true,
        back_href: None,
        back_label: "",
    });
    (StatusCode::INTERNAL_SERVER_ERROR, Html(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin_dto::MemberView;
    use crate::i18n::Locale;

    fn tenant() -> WebTenant {
        WebTenant("00000000-0000-7000-8000-000000000000".to_string())
    }

    fn member(membership_type: &str) -> MemberView {
        MemberView {
            user_id: "11111111-1111-1111-1111-111111111111".into(),
            email: Some("u@example.com".into()),
            preferred_username: Some("u".into()),
            name: None,
            membership_type: membership_type.into(),
            status: "ACTIVE".into(),
            user_status: Some("ACTIVE".into()),
            locked: false,
            pending_setup: false,
            note: None,
        }
    }

    /// 人だけのアカウント一覧を描く（一覧はアカウントの画面が持つ。ADR-0065）。
    fn render_page(members: &[MemberView], notice_key: Option<&str>) -> String {
        crate::handlers::admin_accounts_console::tests::render_accounts(
            members
                .iter()
                .cloned()
                .map(crate::handlers::admin_accounts_console::tests::user_account)
                .collect(),
            notice_key,
        )
    }

    /// 1 人の画面を描く。⚠ **操作の有無を確かめる場所は一覧ではなくこちら**
    /// （一覧は探す場所になったため）。
    fn render_detail(m: &MemberView) -> String {
        render_detail_in(Locale::Ja, m)
    }

    fn render_detail_in(locale: Locale, m: &MemberView) -> String {
        let messages = Messages::new(locale);
        render(&crate::templates::MemberDetail {
            messages: &messages,
            tenant: &tenant().prefix(),
            admin: Some(AdminContext::for_test("admin-1", Some("Acme")).chrome()),
            member: m,
            applications: None,
            csrf: "csrf123",
            error_key: None,
            notice_key: None,
        })
    }

    fn render_detail_with_applications(
        m: &MemberView,
        applications: &crate::admin_dto::AccountApplicationListView,
    ) -> String {
        let messages = Messages::new(Locale::Ja);
        render(&crate::templates::MemberDetail {
            messages: &messages,
            tenant: &tenant().prefix(),
            admin: Some(AdminContext::for_test("admin-1", Some("Acme")).chrome()),
            member: m,
            applications: Some(applications),
            csrf: "csrf123",
            error_key: None,
            notice_key: None,
        })
    }

    fn app(
        id: &str,
        mode: &str,
        access: &str,
        assigned_at: Option<&str>,
    ) -> crate::admin_dto::AccountApplicationView {
        crate::admin_dto::AccountApplicationView {
            application_id: id.into(),
            display_name: format!("app-{id}"),
            status: "ACTIVE".into(),
            assignment_mode: mode.into(),
            access: access.into(),
            assigned_at: assigned_at.map(Into::into),
        }
    }

    /// ⚠ **一覧に操作を戻さない。** 7 つのボタンを 1 セルへ並べていた頃は、操作列 168px に
    /// ボタンが縦 7 段に積まれ、幅の広いものは右端で切れていた。一覧に出てよいのは
    /// 1 人の画面への導線だけで、破壊的な口（削除・解除）は決して並べない。
    #[test]
    fn the_list_carries_no_actions_only_a_way_into_each_member() {
        let html = render_page(&[member("HOME"), member("GUEST")], None);
        // ⚠ 部分一致で見ない ——`/status` はサイドバーの `/admin/status`（クライアント状況）にも
        //   当たる。メンバー配下の口だけを数える。
        let uid = member("HOME").user_id;
        for action in [
            "reset-mfa",
            "reset-password",
            "reissue-tokens",
            "unlock",
            "delete",
            "revoke",
            "suspend",
            "resume",
            "status",
        ] {
            let path = format!("/admin/members/{uid}/{action}");
            assert!(!html.contains(&path), "一覧に {path} が残っている: {html}");
        }
        // 一覧にも検索フォームとログアウト（レイアウト）は在ってよい。禁じるのは
        // **メンバー宛の送信口**だけ。
        assert!(
            !html.contains("action=\"/00000000-0000-7000-8000-000000000000/admin/members/"),
            "一覧にメンバー宛の送信口が残っている: {html}"
        );
        assert!(
            html.contains("/admin/members/11111111-1111-1111-1111-111111111111"),
            "1 人の画面への導線が要る: {html}"
        );
    }

    /// MT21: 所属元（HOME）の利用者にだけ MFA 解除ボタンを出す。ゲストは所属元テナントの管理者が
    /// 操作する対象で、こちらからは（api も 404 を返すため）出してはいけない。
    #[test]
    fn mfa_reset_button_is_shown_for_home_members_only() {
        let home = render_detail(&member("HOME"));
        assert!(home.contains("/reset-mfa"), "{home}");
        assert!(home.contains("name=\"csrf_token\" value=\"csrf123\""));

        let guest = render_detail(&member("GUEST"));
        assert!(!guest.contains("/reset-mfa"), "{guest}");
    }

    /// ADR-0047: トークン再発行も所属元（HOME）の利用者にだけ出す（api は他テナントの利用者へ
    /// 404 を返すため、ゲストに出すと押せないボタンになる）。
    #[test]
    fn token_reissue_button_is_shown_for_home_members_only() {
        let home = render_detail(&member("HOME"));
        assert!(home.contains("/reissue-tokens"), "{home}");

        let guest = render_detail(&member("GUEST"));
        assert!(!guest.contains("/reissue-tokens"), "{guest}");
    }

    /// 確認ダイアログの文言は `data-confirm` 属性で渡す（インライン JS の文字列へ埋め込まない）。
    ///
    /// `onsubmit="return confirm('…')"` へ埋め込むと、Askama が `'` を `&#39;` にしてもブラウザが
    /// 属性値の解釈時に `'` へ戻すため、英語の "user's" のようなアポストロフィが JS 文字列を
    /// 終端させてハンドラごと構文エラーになり、**確認なしで破壊的操作が送信される**。
    /// 属性値として渡せば HTML エスケープがそのまま正しい防御になる。
    #[test]
    fn confirmation_text_is_passed_as_an_attribute_not_inline_javascript() {
        let html = render_detail(&member("HOME"));
        assert!(!html.contains("onsubmit="), "no inline handlers: {html}");
        assert!(html.contains("data-confirm="));

        // アポストロフィを含む文言（英語ロケール）でも属性として正しくエスケープされ、
        // 生の `'` が属性値を終端しない。
        let english = render_detail_in(Locale::En, &member("HOME"));
        let messages = Messages::new(Locale::En);
        let confirm = messages.get("admin-members-reset-mfa-confirm");
        assert!(confirm.contains('\''), "fixture must contain an apostrophe");
        assert!(english.contains("&#39;"), "apostrophe must be escaped");
        assert!(!english.contains(&format!("data-confirm=\"{confirm}\"")));
    }

    /// MT24: ゲストの行だけに停止・再開ボタンを出し、状態に応じて片方だけ出す
    /// （停止中に「一時停止」を出すと押しても 403 になるだけで、操作できるように見えてしまう）。
    #[test]
    fn suspend_and_resume_buttons_follow_the_membership_state() {
        let active_guest = render_detail(&member("GUEST"));
        assert!(active_guest.contains("/suspend"), "{active_guest}");
        assert!(!active_guest.contains("/resume"));

        let mut suspended = member("GUEST");
        suspended.status = "SUSPENDED".into();
        let html = render_detail(&suspended);
        assert!(html.contains("/resume"), "{html}");
        assert!(!html.contains("/suspend"));

        // 停止中であることは**一覧で**分かる（探す場所に状態が要る）。
        let listed = render_page(&[suspended], None);
        assert!(listed.contains(&Messages::new(Locale::Ja).get("admin-members-status-suspended")));

        // HOME は停止できない（api も 403 を返す）ので導線を出さない。
        let home = render_detail(&member("HOME"));
        assert!(!home.contains("/suspend"));
        assert!(!home.contains("/resume"));

        // 招待中（未承諾）はまだアクセスが無いため停止対象にならない。
        let mut invited = member("GUEST");
        invited.status = "INVITED".into();
        let html = render_detail(&invited);
        assert!(!html.contains("/suspend"), "{html}");
        assert!(!html.contains("/resume"));
    }

    /// ロック解除の導線は**ロック中の HOME 利用者にだけ**出す。常時出すと、押しても何も
    /// 変わらない操作が並び、ロックされている利用者を見分けられなくなる（AP6）。
    #[test]
    fn the_unlock_action_appears_only_for_a_locked_home_member() {
        let unlocked = render_detail(&member("HOME"));
        assert!(!unlocked.contains("/unlock"), "{unlocked}");

        let mut locked = member("HOME");
        locked.locked = true;
        let html = render_detail(&locked);
        assert!(html.contains("/unlock"), "{html}");
        assert!(html.contains(&Messages::new(Locale::Ja).get("admin-members-unlock-button")));

        // ロック中であることは**一覧でも**分かる（誰が入れないのかを探す場所）。
        let listed = render_page(&[locked], None);
        assert!(listed.contains(&Messages::new(Locale::Ja).get("admin-members-user-status-locked")));

        // ゲストの `users` レコードは所属元テナントの管理者だけが操作できる（ADR-0009 §3）。
        let mut guest = member("GUEST");
        guest.locked = true;
        let guest_html = render_detail(&guest);
        assert!(!guest_html.contains("/unlock"), "{guest_html}");
    }

    /// 一覧はユーザー名（主たるログイン識別子）を出す。
    ///
    /// メールアドレスと表示名だけでは、**利用者が「入れない」と言ってきたときに何を打って
    /// もらえばよいのかが分からない**。見出し（メール）の下に添える。
    #[test]
    fn the_list_shows_the_login_identifier_under_the_email() {
        let mut m = member("HOME");
        m.preferred_username = Some("kyon".into());
        m.name = Some("Kyon".into());
        let html = render_page(&[m], None);
        assert!(html.contains(">u@example.com</a>"), "{html}");
        assert!(html.contains("kyon · Kyon"), "{html}");
    }

    /// 見出しと同じ値は添えない（メールをユーザー名にしている人は同じ文字列が 2 段並ぶ）。
    #[test]
    fn the_list_does_not_repeat_the_headline() {
        let mut m = member("HOME");
        m.preferred_username = Some("u@example.com".into());
        assert!(m.secondary_names().is_empty());
        m.email = None;
        m.name = Some("U".into());
        assert_eq!(m.headline(), "u@example.com");
        assert_eq!(m.secondary_names(), vec!["U"]);
    }

    /// ⚠ **普通の人に札を並べない。** 全員に「HOME」「ACTIVE」が並ぶと、止まっている人が埋もれる。
    #[test]
    fn the_list_badges_only_what_is_unusual() {
        let html = render_page(&[member("HOME")], None);
        assert!(!html.contains(">HOME<"), "{html}");
        assert!(!html.contains(">ACTIVE<"), "{html}");

        let mut disabled = member("GUEST");
        disabled.user_status = Some("DISABLED".into());
        let html = render_page(&[disabled], None);
        let messages = Messages::new(Locale::Ja);
        assert!(
            html.contains(&messages.get("admin-members-type-guest")),
            "{html}"
        );
        assert!(
            html.contains(&messages.get("admin-members-user-status-disabled")),
            "{html}"
        );
    }

    /// ADR-0064: 仮登録の人は「有効」ではなく「仮登録」と出す。
    #[test]
    fn a_pending_member_is_shown_as_pending_not_active() {
        let messages = Messages::new(Locale::Ja);
        let mut m = member("HOME");
        m.pending_setup = true;
        let html = render_page(&[m.clone()], None);
        assert!(
            html.contains(&messages.get("admin-members-user-status-pending")),
            "{html}"
        );
        assert!(
            !html.contains(&format!(
                ">{}<",
                messages.get("admin-members-user-status-active")
            )),
            "{html}"
        );
        let detail = render_detail(&m);
        assert!(detail.contains(&messages.get("admin-members-user-status-pending-help")));
    }

    /// ADR-0063: 一覧にはメモの 1 行目だけを出す（全文は 1 人の画面で読む）。
    #[test]
    fn the_list_shows_the_first_line_of_the_note() {
        let mut m = member("HOME");
        m.note = Some(crate::admin_dto::AccountNoteView {
            text: "家族として招待\n2 行目は出さない".into(),
            updated_at: "2026-09-24T12:00:00Z".into(),
        });
        let html = render_page(&[m.clone()], None);
        assert!(html.contains("家族として招待…"), "{html}");
        assert!(!html.contains("2 行目は出さない"), "{html}");

        m.note.as_mut().unwrap().text = "あ".repeat(100);
        let excerpt = m.note.as_ref().unwrap().excerpt().unwrap();
        assert_eq!(excerpt.chars().count(), 61, "60 文字 ＋ 省略記号");
    }

    /// ADR-0063: メモの欄は HOME にもゲストにも出し、書かれていれば中身と日時を出す。
    #[test]
    fn the_detail_has_a_note_form_for_every_member() {
        for kind in ["HOME", "GUEST"] {
            let html = render_detail(&member(kind));
            assert!(
                html.contains("/admin/members/11111111-1111-1111-1111-111111111111/note"),
                "{kind}: {html}"
            );
            assert!(html.contains("maxlength=\"2000\""), "{html}");
        }
        let mut m = member("HOME");
        m.note = Some(crate::admin_dto::AccountNoteView {
            text: "<b>経緯</b>".into(),
            updated_at: "2026-09-24T12:00:00Z".into(),
        });
        let html = render_detail(&m);
        assert!(
            !html.contains("<b>経緯</b>"),
            "メモは必ずエスケープする: {html}"
        );
        assert!(html.contains("経緯"), "{html}");
        assert!(html.contains("datetime=\"2026-09-24T12:00:00Z\""), "{html}");
    }

    /// ADR-0063: アプリの欄は引けたときだけ出す（`idp.applications:read` の無い管理者には無い）。
    #[test]
    fn the_applications_card_is_hidden_without_the_permission() {
        let html = render_detail(&member("HOME"));
        let title = Messages::new(Locale::Ja).get("admin-member-applications-title");
        assert!(!html.contains(&title), "{html}");
    }

    /// ADR-0063: 割り当ての出し入れは「個別」のアプリだけ。「全員」のアプリで外しても入れてしまう。
    #[test]
    fn assignment_buttons_appear_only_for_individual_applications() {
        let apps = crate::admin_dto::AccountApplicationListView {
            applications: vec![
                app("everyone", "EVERYONE", "allowed", None),
                app(
                    "assigned",
                    "INDIVIDUAL",
                    "allowed",
                    Some("2026-09-01T00:00:00Z"),
                ),
                app("missing", "INDIVIDUAL", "not_assigned", None),
            ],
            enforcement: "enforce".into(),
        };
        let html = render_detail_with_applications(&member("HOME"), &apps);
        let base = "/admin/members/11111111-1111-1111-1111-111111111111/applications";
        assert!(!html.contains(&format!("{base}/everyone/")), "{html}");
        assert!(
            html.contains(&format!("{base}/assigned/unassign")),
            "{html}"
        );
        assert!(
            !html.contains(&format!("{base}/assigned/assign\"")),
            "{html}"
        );
        assert!(html.contains(&format!("{base}/missing/assign")), "{html}");
        let messages = Messages::new(Locale::Ja);
        assert!(html.contains(&messages.get("admin-member-applications-not-assigned")));
        assert!(!html.contains(&messages.get("admin-member-applications-record-only")));
    }

    /// 「使えるアプリ」はその場で絞り込める。行は名前と可否を持ち、札には件数が付く。
    #[test]
    fn the_applications_card_can_be_filtered_in_place() {
        let apps = crate::admin_dto::AccountApplicationListView {
            applications: vec![
                app("a1", "EVERYONE", "allowed", None),
                app("a2", "INDIVIDUAL", "not_assigned", None),
                app("a3", "INDIVIDUAL", "not_assigned", None),
            ],
            enforcement: "enforce".into(),
        };
        let html = render_detail_with_applications(&member("HOME"), &apps);
        assert!(html.contains("data-list-filter-input"), "{html}");
        assert!(html.contains("/assets/list-filter.js?v="), "{html}");
        assert!(
            html.contains("data-filter-state=\"not_assigned\" data-filter-text=\"app-a2\""),
            "{html}"
        );
        assert_eq!(apps.count("not_assigned"), 2);
        // 停止中のアプリが無ければ、その札は出さない（押しても 0 件になるだけ）。
        assert!(!html.contains("data-list-filter-state=\"application_disabled\""));
    }

    /// 記録だけの間は、割り当てがまだ効いていないことを添える。
    #[test]
    fn record_only_is_mentioned_on_the_applications_card() {
        let apps = crate::admin_dto::AccountApplicationListView {
            applications: vec![],
            enforcement: "record_only".into(),
        };
        let html = render_detail_with_applications(&member("HOME"), &apps);
        let messages = Messages::new(Locale::Ja);
        assert!(html.contains(&messages.get("admin-member-applications-record-only")));
        assert!(html.contains(&messages.get("admin-member-applications-none")));
    }

    /// 解除後の完了通知は「外した」「元から無かった」を区別して出す。
    #[test]
    fn mfa_reset_notices_distinguish_removed_from_absent() {
        let removed = render_page(&[member("HOME")], notice_key_for("mfa-reset"));
        assert!(removed.contains(&Messages::new(Locale::Ja).get("admin-members-mfa-reset-done")));

        let absent = render_page(&[member("HOME")], notice_key_for("mfa-none"));
        assert!(absent.contains(&Messages::new(Locale::Ja).get("admin-members-mfa-reset-none")));

        // 未知の通知値は無視する（クエリ経由で任意文字列が来るため）。
        assert!(notice_key_for("../../etc/passwd").is_none());
    }
}
