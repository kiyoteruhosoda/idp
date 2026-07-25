//! テナントメンバー（HOME/GUEST）管理画面（web。ADR-0009 §3・§6・MT13）。
//!
//! メンバー管理の起点となるハブ画面。api の JSON 管理 API を管理者の SSO Cookie 転送で呼ぶ。
//! ゲストはメンバーシップの解除のみでき（HOME は api 側が 403 を返す）、所属元（HOME）の利用者には
//! 無効化・有効化・パスワード再発行・削除を提供する（対象が所属元でない場合は api 側が 404 を返す）。
//!
//! 一覧の**絞り込み・ページングは api（DB）側**が行う（MT22）。web は検索語とページ位置をクエリで
//! 引き継ぎ、応答の `total` からページャの前後リンクを組み立てるだけで、全件を受け取らない。

use super::locale;
use crate::admin_dto::MemberListView;
use crate::api_client::AdminApiError;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::console_csrf_token;
use crate::dto::{MemberActionForm, MemberStatusForm};
use crate::handlers::admin_console::{
    forbidden_response, redirect_to_login, resolve_admin, AdminResolution,
};
use crate::handlers::found;
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, ConsoleNotice, MembersList, PasswordResetResult};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

const MEMBERS_SEGMENT: &str = "/admin/members";

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

/// メンバー一覧（`GET /{tenant_id}/admin/members`）。
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
    let term = query.q.clone().unwrap_or_default();
    let offset = query.offset.unwrap_or(0).max(0);
    // 絞り込み・ページングは api（DB）側で行う。web 側で全件を受けてから絞る方式は、
    // テナントの規模に比例して応答が膨らむため採らない（MT22）。
    let mut params: Vec<(&str, String)> = vec![("offset", offset.to_string())];
    if !term.trim().is_empty() {
        params.push(("q", term.trim().to_string()));
    }
    let result = state
        .api
        .list_members(&correlation.0, &tenant.0, &sso(&headers), &params)
        .await;
    let messages = Messages::new(locale(&headers));
    let csrf = csrf_from(&headers, state.config.csrf_secret());
    let error_key = query.error.as_deref().and_then(error_key_for);
    let notice_key = query.notice.as_deref().and_then(notice_key_for);
    match result {
        Ok(page) => Html(render_list(
            &messages,
            &tenant,
            &admin,
            &csrf,
            &page,
            term.trim(),
            offset,
            error_key,
            notice_key,
        ))
        .into_response(),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => forbidden_response(&headers),
        Err(_) => internal_error(&messages, &tenant, &admin),
    }
}

/// メンバー一覧の描画（ページャのリンク組み立てを含む）。
#[allow(clippy::too_many_arguments)]
fn render_list(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &str,
    csrf: &str,
    page: &MemberListView,
    term: &str,
    offset: i64,
    error_key: Option<&str>,
    notice_key: Option<&str>,
) -> String {
    let (prev_href, next_href) = pager_links(tenant, term, offset, page);
    render(&MembersList {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin),
        members: &page.members,
        total: page.total,
        query: term,
        csrf,
        error_key,
        notice_key,
        prev_href,
        next_href,
    })
}

/// ページャの前後リンク。次ページの有無は**総件数**で判定する（1 ページに満たない件数かどうかで
/// 判定すると、最後のページがちょうど埋まったときに空ページへのリンクが出る）。
fn pager_links(
    tenant: &WebTenant,
    term: &str,
    offset: i64,
    page: &MemberListView,
) -> (Option<String>, Option<String>) {
    // limit は api が実際に適用した値。0 以下が返ることは無いが、割り算・加算の安全側として弾く。
    let limit = page.limit.max(1);
    let prev = (offset > 0).then(|| members_href(tenant, term, (offset - limit).max(0)));
    let next = (offset + limit < page.total).then(|| members_href(tenant, term, offset + limit));
    (prev, next)
}

fn members_href(tenant: &WebTenant, term: &str, offset: i64) -> String {
    let mut query = format!("offset={offset}");
    if !term.is_empty() {
        query.push_str(&format!("&q={}", urlencode(term)));
    }
    format!("{}{MEMBERS_SEGMENT}?{query}", tenant.prefix())
}

/// クエリ文字列へ載せる値のパーセントエンコード（RFC 3986 の unreserved 以外を変換する）。
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
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
    let base = format!("{}{MEMBERS_SEGMENT}", tenant.prefix());
    if !csrf_valid(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
    }
    let result = state
        .api
        .revoke_member(&correlation.0, &tenant.0, &sso(&headers), &user_id)
        .await;
    match result {
        Ok(()) => found(&base),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => found(&format!("{base}?error=forbidden")),
        Err(AdminApiError::NotFound) => found(&format!("{base}?error=notfound")),
        Err(_) => found(&format!("{base}?error=internal")),
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
    let base = format!("{}{MEMBERS_SEGMENT}", tenant.prefix());
    if !csrf_valid(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
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
        Err(AdminApiError::Forbidden) => found(&format!("{base}?error=self")),
        Err(AdminApiError::NotFound) => found(&format!("{base}?error=user-notfound")),
        Err(AdminApiError::Validation(_)) => found(&format!("{base}?error=internal")),
        Err(_) => found(&format!("{base}?error=internal")),
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
    let base = format!("{}{MEMBERS_SEGMENT}", tenant.prefix());
    if !csrf_valid(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
    }
    let reset = match state
        .api
        .reset_user_password(&correlation.0, &tenant.0, &sso(&headers), &user_id)
        .await
    {
        Ok(v) => v,
        Err(AdminApiError::Unauthorized) => return redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => return found(&format!("{base}?error=self")),
        Err(AdminApiError::NotFound) => return found(&format!("{base}?error=user-notfound")),
        Err(_) => return found(&format!("{base}?error=internal")),
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
        admin: Some(&admin),
        subject: &subject,
        generated_password: &reset.generated_password,
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
    let base = format!("{}{MEMBERS_SEGMENT}", tenant.prefix());
    if !csrf_valid(headers, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
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
        Ok(()) => found(&format!("{base}?notice={notice}")),
        Err(AdminApiError::Unauthorized) => redirect_to_login(tenant),
        // HOME・遷移できない状態（既に停止済み等）は api が 403 を返す。
        Err(AdminApiError::Forbidden) => found(&format!("{base}?error=forbidden")),
        Err(AdminApiError::NotFound) => found(&format!("{base}?error=notfound")),
        Err(_) => found(&format!("{base}?error=internal")),
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
    let base = format!("{}{MEMBERS_SEGMENT}", tenant.prefix());
    if !csrf_valid(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
    }
    match state
        .api
        .reset_user_mfa(&correlation.0, &tenant.0, &sso(&headers), &user_id)
        .await
    {
        // 何も設定されていなかった場合も成功だが、管理者には区別して伝える（「効いていない」と
        // 誤解して操作を繰り返すのを防ぐ）。
        Ok(reset) if !reset.totp_removed && reset.passkeys_removed == 0 => {
            found(&format!("{base}?notice=mfa-none"))
        }
        Ok(_) => found(&format!("{base}?notice=mfa-reset")),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => found(&format!("{base}?error=self")),
        Err(AdminApiError::NotFound) => found(&format!("{base}?error=user-notfound")),
        Err(_) => found(&format!("{base}?error=internal")),
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
    let base = format!("{}{MEMBERS_SEGMENT}", tenant.prefix());
    if !csrf_valid(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
    }
    let result = state
        .api
        .delete_user(&correlation.0, &tenant.0, &sso(&headers), &user_id)
        .await;
    match result {
        Ok(()) => found(&base),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => found(&format!("{base}?error=self")),
        Err(AdminApiError::NotFound) => found(&format!("{base}?error=user-notfound")),
        Err(_) => found(&format!("{base}?error=internal")),
    }
}

/// メンバー一覧を絞り込み語で部分一致フィルタする（メールアドレス・氏名。大文字小文字を無視）。
/// 空語のときは全件返す。一覧は api が全件返すため、絞り込みは web 側で行う（api 変更は不要）。
fn notice_key_for(notice: &str) -> Option<&'static str> {
    match notice {
        "mfa-reset" => Some("admin-members-mfa-reset-done"),
        "mfa-none" => Some("admin-members-mfa-reset-none"),
        "member-suspended" => Some("admin-members-suspend-done"),
        "member-resumed" => Some("admin-members-resume-done"),
        _ => None,
    }
}

fn error_key_for(error: &str) -> Option<&'static str> {
    match error {
        "csrf" => Some("admin-error-csrf"),
        "forbidden" => Some("admin-members-error-home"),
        "notfound" => Some("admin-members-error-notfound"),
        "self" => Some("admin-members-error-self"),
        "user-notfound" => Some("admin-members-error-user-notfound"),
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

fn internal_error(messages: &Messages, tenant: &WebTenant, admin: &str) -> Response {
    let body = render(&ConsoleNotice {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin),
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
            name: None,
            membership_type: membership_type.into(),
            status: "ACTIVE".into(),
            user_status: Some("ACTIVE".into()),
        }
    }

    /// 1 ページ分の応答（総件数はページの件数と同じ = 1 ページで収まる状態）。
    fn page(members: Vec<MemberView>) -> MemberListView {
        let total = members.len() as i64;
        MemberListView {
            members,
            total,
            limit: 50,
            offset: 0,
        }
    }

    fn render_page(members: &[MemberView], notice_key: Option<&str>) -> String {
        let messages = Messages::new(Locale::Ja);
        super::render_list(
            &messages,
            &tenant(),
            "admin-1",
            "csrf123",
            &page(members.to_vec()),
            "",
            0,
            None,
            notice_key,
        )
    }

    /// MT21: 所属元（HOME）の利用者にだけ MFA 解除ボタンを出す。ゲストは所属元テナントの管理者が
    /// 操作する対象で、こちらからは（api も 404 を返すため）出してはいけない。
    #[test]
    fn mfa_reset_button_is_shown_for_home_members_only() {
        let home = render_page(&[member("HOME")], None);
        assert!(home.contains("/reset-mfa"), "{home}");
        assert!(home.contains("name=\"csrf_token\" value=\"csrf123\""));

        let guest = render_page(&[member("GUEST")], None);
        assert!(!guest.contains("/reset-mfa"), "{guest}");
    }

    /// 確認ダイアログの文言は `data-confirm` 属性で渡す（インライン JS の文字列へ埋め込まない）。
    ///
    /// `onsubmit="return confirm('…')"` へ埋め込むと、Askama が `'` を `&#39;` にしてもブラウザが
    /// 属性値の解釈時に `'` へ戻すため、英語の "user's" のようなアポストロフィが JS 文字列を
    /// 終端させてハンドラごと構文エラーになり、**確認なしで破壊的操作が送信される**。
    /// 属性値として渡せば HTML エスケープがそのまま正しい防御になる。
    #[test]
    fn confirmation_text_is_passed_as_an_attribute_not_inline_javascript() {
        let html = render_page(&[member("HOME")], None);
        assert!(!html.contains("onsubmit="), "no inline handlers: {html}");
        assert!(html.contains("data-confirm="));

        // アポストロフィを含む文言（英語ロケール）でも属性として正しくエスケープされ、
        // 生の `'` が属性値を終端しない。
        let messages = Messages::new(Locale::En);
        let english = super::render_list(
            &messages,
            &tenant(),
            "admin-1",
            "csrf123",
            &page(vec![member("HOME")]),
            "",
            0,
            None,
            None,
        );
        let confirm = messages.get("admin-members-reset-mfa-confirm");
        assert!(confirm.contains('\''), "fixture must contain an apostrophe");
        assert!(english.contains("&#39;"), "apostrophe must be escaped");
        assert!(!english.contains(&format!("data-confirm=\"{confirm}\"")));
    }

    /// MT24: ゲストの行だけに停止・再開ボタンを出し、状態に応じて片方だけ出す
    /// （停止中に「一時停止」を出すと押しても 403 になるだけで、操作できるように見えてしまう）。
    #[test]
    fn suspend_and_resume_buttons_follow_the_membership_state() {
        let active_guest = render_page(&[member("GUEST")], None);
        assert!(active_guest.contains("/suspend"), "{active_guest}");
        assert!(!active_guest.contains("/resume"));

        let mut suspended = member("GUEST");
        suspended.status = "SUSPENDED".into();
        let html = render_page(&[suspended], None);
        assert!(html.contains("/resume"), "{html}");
        assert!(!html.contains("/suspend"));
        // 停止中であることが一覧で分かる。
        assert!(html.contains(&Messages::new(Locale::Ja).get("admin-members-status-suspended")));

        // HOME は停止できない（api も 403 を返す）ので導線を出さない。
        let home = render_page(&[member("HOME")], None);
        assert!(!home.contains("/suspend"));
        assert!(!home.contains("/resume"));

        // 招待中（未承諾）はまだアクセスが無いため停止対象にならない。
        let mut invited = member("GUEST");
        invited.status = "INVITED".into();
        let html = render_page(&[invited], None);
        assert!(!html.contains("/suspend"), "{html}");
        assert!(!html.contains("/resume"));
    }

    /// MT22: ページャは**総件数**で次ページの有無を決める。ページがちょうど埋まったかどうかで
    /// 判定すると、最後のページが満杯のときに空ページへのリンクが出る。
    #[test]
    fn next_link_appears_only_while_rows_remain() {
        let full = MemberListView {
            members: vec![member("HOME")],
            total: 2,
            limit: 1,
            offset: 0,
        };
        let (prev, next) = pager_links(&tenant(), "", 0, &full);
        assert_eq!(prev, None, "先頭ページに「前へ」は出さない");
        assert!(next.expect("next").ends_with("/admin/members?offset=1"));

        // 最終ページ（offset + limit == total）では次ページを出さない。
        let last = MemberListView {
            members: vec![member("HOME")],
            total: 2,
            limit: 1,
            offset: 1,
        };
        let (prev, next) = pager_links(&tenant(), "", 1, &last);
        assert!(prev.expect("prev").ends_with("/admin/members?offset=0"));
        assert_eq!(next, None);
    }

    /// 絞り込み語はページ送りのリンクへ引き継ぐ（次ページで条件が消えると別の集合になる）。
    /// クエリ文字列に載せるためパーセントエンコードする。
    #[test]
    fn pager_links_keep_the_search_term_encoded() {
        let page = MemberListView {
            members: vec![member("HOME")],
            total: 100,
            limit: 50,
            offset: 0,
        };
        let (_, next) = pager_links(&tenant(), "a b&c", 0, &page);
        let next = next.expect("next");
        assert!(next.contains("offset=50"), "{next}");
        assert!(next.contains("q=a%20b%26c"), "{next}");
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
