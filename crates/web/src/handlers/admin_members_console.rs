//! Tenant member (HOME/GUEST) management screen (web. ADR-0009 §3, §6, MT13).
//!
//! The hub screen where member management starts. Calls the api's JSON admin APIs by forwarding the admin's SSO cookie.
//! Guests can only have their membership removed (the api returns 403 for HOME); users whose home is this tenant
//! get disable, enable, password reissue and deletion (the api returns 404 when the target's home is not this tenant).
//!
//! **Filtering and paging of the list are done by the api (DB)** (MT22). web carries over the search term and page position
//! in the query and only builds the pager's prev/next links from the response's `total`, never receiving all rows.

use super::locale;
use crate::api_client::AdminApiError;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::{console_csrf_from, console_csrf_valid_in};
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

/// The list (the account list filtered to people. ADR-0065). Where to return after an operation.
const MEMBERS_LIST: &str = "/admin/accounts?kind=user";

#[derive(Debug, Default, Deserialize)]
pub struct ViewQuery {
    #[serde(default)]
    pub error: Option<String>,
    /// Completion notice (conveys the operation result via Post/Redirect/Get; e.g. MFA removal in MT21).
    #[serde(default)]
    pub notice: Option<String>,
    /// Filter term for the member list (substring match on email address and name, case-insensitive).
    /// Filtering is done by the api (DB).
    #[serde(default)]
    pub q: Option<String>,
    /// Number of items the pager skips. Unspecified is 0.
    #[serde(default)]
    pub offset: Option<i64>,
}

/// Screen for one member (`GET /{tenant_id}/admin/members/{user_id}`).
///
/// ⚠ **Keep the list as the place to find and this as the place to operate.** Back when 7 buttons sat in one list cell,
/// they were stacked 7 high in the 168px operations column, and wide ones were cut off at the right edge.
pub async fn detail(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    // ⚠ **The path has two parameters, `{tenant_id}` and `{user_id}`.** Receiving only one gets rejected with
    //   `WrongNumberOfParameters`, a 500 before entering the handler
    //   (the other handlers in this file also receive two).
    Path((_, user_id)): Path<(String, String)>,
    Query(query): Query<ViewQuery>,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };
    // ⚠ `Messages` is not `Send`, so do not hold it across an `await` (create it after the api calls).
    let sso = sso(&headers);
    let result = state
        .api
        .get_member(&correlation.0, &tenant.0, &sso, &user_id)
        .await;
    // Available apps need `idp.applications:read`. Admins without it are not refused the whole member screen;
    // only the apps section is hidden (notes and recovery operations are unrelated to app permissions).
    let applications = match &result {
        Ok(_) => state
            .api
            .list_member_applications(&correlation.0, &tenant.0, &sso, &user_id)
            .await
            .ok(),
        Err(_) => None,
    };
    // Number of currently valid tokens (task #83). Shows whether there is anything before pressing reissue. Only users
    // whose home is this tenant can be counted (the api returns 404 for users of other tenants), so guests are
    // not asked. If it cannot be fetched, the section is hidden and the screen itself is not refused (the operation works
    // without knowing the count. ADR-0047).
    let active_tokens = match &result {
        Ok(member) if member.membership_type == "HOME" => state
            .api
            .count_user_active_tokens(&correlation.0, &tenant.0, &sso, &user_id)
            .await
            .ok(),
        _ => None,
    };
    let messages = Messages::new(locale(&headers));
    match result {
        Ok(member) => Html(render(&MemberDetail {
            messages: &messages,
            tenant: &tenant.prefix(),
            admin: Some(admin.chrome()),
            member: &member,
            applications: applications.as_ref(),
            active_tokens: active_tokens.as_ref(),
            csrf: &console_csrf_from(&headers, state.config.csrf_secret()),
            error_key: query.error.as_deref().and_then(error_key_for),
            notice_key: query.notice.as_deref().and_then(notice_key_for),
        }))
        .into_response(),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => forbidden_response(&headers),
        // So as not to reveal the existence of other tenants' members, nonexistence also stays a 404 and returns to the list.
        Err(AdminApiError::NotFound) => {
            found(&format!("{}{MEMBERS_LIST}&error=notfound", tenant.prefix()))
        }
        Err(_) => internal_error(&messages, &tenant, &admin),
    }
}

/// Writes an admin note (`POST /{tenant_id}/admin/members/{user_id}/note`. ADR-0063).
///
/// Written the same way as for service accounts ([`admin_accounts_console::write_note`]. ADR-0065).
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

/// Assigns this member to an app
/// (`POST /{tenant_id}/admin/members/{user_id}/applications/{application_id}/assign`).
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

/// Removes this member's assignment
/// (`POST /{tenant_id}/admin/members/{user_id}/applications/{application_id}/unassign`).
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

/// Removes a guest membership (`POST /{tenant_id}/admin/members/{user_id}/revoke`).
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
    if !console_csrf_valid_in(&headers, &form.csrf_token, state.config.csrf_secret()) {
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

/// Disables/enables a user (`POST /{tenant_id}/admin/members/{user_id}/status`).
/// Only users whose home (HOME) is this tenant. One cannot change oneself (the api returns 403).
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
    if !console_csrf_valid_in(&headers, &form.csrf_token, state.config.csrf_secret()) {
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

/// Reissues a user's password (`POST /{tenant_id}/admin/members/{user_id}/reset-password`).
/// On success the generated password is shown only once.
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
    if !console_csrf_valid_in(&headers, &form.csrf_token, state.config.csrf_secret()) {
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

/// Suspends a guest membership (`POST /{tenant_id}/admin/members/{user_id}/suspend`. MT24).
/// Unlike removal (deletion), it stops only access while keeping the membership and permissions.
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

/// Resumes a suspended guest membership (`POST /{tenant_id}/admin/members/{user_id}/resume`. MT24).
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
    if !console_csrf_valid_in(headers, &form.csrf_token, state.config.csrf_secret()) {
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
        // HOME or states that cannot transition (already suspended etc.) get a 403 from the api.
        Err(AdminApiError::Forbidden) => found(&format!("{base}&error=forbidden")),
        Err(AdminApiError::NotFound) => found(&format!("{base}&error=notfound")),
        Err(_) => found(&format!("{base}&error=internal")),
    }
}

/// Removes a user's MFA (`POST /{tenant_id}/admin/members/{user_id}/reset-mfa`. MT21).
/// Recovery for users who lost their device and cannot remove it themselves. Removes TOTP and passkeys together.
/// No secrets are involved, so no result screen; return to the list with a completion notice (Post/Redirect/Get).
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
    if !console_csrf_valid_in(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}&error=csrf"));
    }
    match state
        .api
        .reset_user_mfa(&correlation.0, &tenant.0, &sso(&headers), &user_id)
        .await
    {
        // Nothing configured is also success, but tell the admin the difference (prevents repeating the operation
        // thinking "it did not work").
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

/// Reissues a user's tokens (`POST /{tenant_id}/admin/members/{user_id}/reissue-tokens`. ADR-0047).
///
/// Revokes all issued refresh tokens and makes apps re-acquire them. Only tokens are dropped — one step that avoids going as far as
/// disabling (stops their work) or password reissue (forces the user to reset).
/// No secrets are involved, so no result screen; return to the list with a completion notice (Post/Redirect/Get).
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
    if !console_csrf_valid_in(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}&error=csrf"));
    }
    match state
        .api
        .reissue_user_tokens(&correlation.0, &tenant.0, &sso(&headers), &user_id)
        .await
    {
        // Nothing to drop is also success, but tell the admin the difference (prevents repeating the operation
        // thinking "it did not work"; same as MFA removal and unlock).
        Ok(result) if result.revoked == 0 => found(&format!("{base}&notice=tokens-none")),
        Ok(_) => found(&format!("{base}&notice=tokens-reissued")),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => found(&format!("{base}&error=forbidden")),
        Err(AdminApiError::NotFound) => found(&format!("{base}&error=user-notfound")),
        Err(_) => found(&format!("{base}&error=internal")),
    }
}

/// Unlocks an account (`POST /{tenant_id}/admin/members/{user_id}/unlock`. AP6).
/// Restores a user whose lock time grew under progressive locking, without waiting for expiry. No secrets are involved,
/// so return to the list with a completion notice (Post/Redirect/Get).
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
    if !console_csrf_valid_in(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}&error=csrf"));
    }
    match state
        .api
        .unlock_user(&correlation.0, &tenant.0, &sso(&headers), &user_id)
        .await
    {
        // Not locked in the first place is also success, but tell the admin the difference
        //(prevents repeating the operation thinking "it did not work"; same as MFA removal).
        Ok(result) if !result.was_locked => found(&format!("{base}&notice=unlock-none")),
        Ok(_) => found(&format!("{base}&notice=unlocked")),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => found(&format!("{base}&error=forbidden")),
        Err(AdminApiError::NotFound) => found(&format!("{base}&error=user-notfound")),
        Err(_) => found(&format!("{base}&error=internal")),
    }
}

/// Deletes a user (`POST /{tenant_id}/admin/members/{user_id}/delete`).
/// Only users whose home (HOME) is this tenant. One cannot delete oneself.
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
    if !console_csrf_valid_in(&headers, &form.csrf_token, state.config.csrf_secret()) {
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

/// Translation key of the completion notice shown when returning via Post/Redirect/Get.
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
            setup_link_expires_at: None,
            setup_link_expired: false,
            note: None,
        }
    }

    /// Renders the people-only account list (the list belongs to the accounts screen. ADR-0065).
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

    /// Renders the single-person screen. ⚠ **This is where to check for the presence of operations, not the list**
    /// (the list became the place to find).
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
            active_tokens: None,
            csrf: "csrf123",
            error_key: None,
            notice_key: None,
        })
    }

    fn render_detail_with_tokens(
        locale: Locale,
        m: &MemberView,
        tokens: &crate::admin_dto::UserActiveTokensView,
    ) -> String {
        let messages = Messages::new(locale);
        render(&crate::templates::MemberDetail {
            messages: &messages,
            tenant: &tenant().prefix(),
            admin: Some(AdminContext::for_test("admin-1", Some("Acme")).chrome()),
            member: m,
            applications: None,
            active_tokens: Some(tokens),
            csrf: "csrf123",
            error_key: None,
            notice_key: None,
        })
    }

    /// task #83: the single-person screen shows the number of currently valid refresh tokens **together with what was counted**.
    /// Showing only the number reads as "access tokens are counted too" or "0 means nothing is alive"
    /// (access tokens have no DB rows and cannot be counted).
    #[test]
    fn active_token_count_is_shown_with_what_was_counted() {
        let tokens = crate::admin_dto::UserActiveTokensView {
            user_id: member("HOME").user_id,
            active_refresh_tokens: 3,
        };
        let ja = render_detail_with_tokens(Locale::Ja, &member("HOME"), &tokens);
        assert!(ja.contains("data-active-refresh-tokens=\"3\""), "{ja}");
        assert!(ja.contains("3 本"), "{ja}");
        assert!(ja.contains("アプリに渡している有効なトークン"), "{ja}");
        assert!(ja.contains("アクセストークンは数えられないため"), "{ja}");

        let en = render_detail_with_tokens(Locale::En, &member("HOME"), &tokens);
        assert!(en.contains("Active app tokens"), "{en}");
        assert!(en.contains("access tokens cannot be counted"), "{en}");
    }

    /// When the count could not be fetched (`None`), the section is hidden. Do not let it be mistaken for 0.
    #[test]
    fn active_token_count_is_hidden_when_unknown() {
        let html = render_detail(&member("HOME"));
        assert!(!html.contains("data-active-refresh-tokens"), "{html}");
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
            active_tokens: None,
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

    /// ⚠ **Do not put operations back in the list.** Back when 7 buttons sat in one cell, they were stacked
    /// 7 high in the 168px operations column, and wide ones were cut off at the right edge. The list may only have
    /// the link to the single-person screen, never destructive endpoints (delete, remove).
    #[test]
    fn the_list_carries_no_actions_only_a_way_into_each_member() {
        let html = render_page(&[member("HOME"), member("GUEST")], None);
        // ⚠ Do not use substring matching — `/status` also hits the sidebar's `/admin/status` (client status).
        //   Count only the endpoints under members.
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
            assert!(!html.contains(&path), "{path} remains in the list: {html}");
        }
        // The list may have the search form and logout (layout). What is forbidden is
        // **submission endpoints targeting members** only.
        assert!(
            !html.contains("action=\"/00000000-0000-7000-8000-000000000000/admin/members/"),
            "submission endpoints targeting members remain in the list: {html}"
        );
        assert!(
            html.contains("/admin/members/11111111-1111-1111-1111-111111111111"),
            "a link to the single-person screen is required: {html}"
        );
    }

    /// MT21: the MFA removal button is shown only for users whose home (HOME) is this tenant. Guests are handled by
    /// their home tenant's admin and must not get it from here (the api returns 404 too).
    #[test]
    fn mfa_reset_button_is_shown_for_home_members_only() {
        let home = render_detail(&member("HOME"));
        assert!(home.contains("/reset-mfa"), "{home}");
        assert!(home.contains("name=\"csrf_token\" value=\"csrf123\""));

        let guest = render_detail(&member("GUEST"));
        assert!(!guest.contains("/reset-mfa"), "{guest}");
    }

    /// ADR-0047: token reissue is also shown only for users whose home (HOME) is this tenant (the api returns 404 for
    /// users of other tenants, so for guests it would be a button that cannot be pressed).
    #[test]
    fn token_reissue_button_is_shown_for_home_members_only() {
        let home = render_detail(&member("HOME"));
        assert!(home.contains("/reissue-tokens"), "{home}");

        let guest = render_detail(&member("GUEST"));
        assert!(!guest.contains("/reissue-tokens"), "{guest}");
    }

    /// The confirm dialog wording is passed via the `data-confirm` attribute (not embedded in inline JS strings).
    ///
    /// Embedded in `onsubmit="return confirm('…')"`, even though Askama turns `'` into `&#39;`, the browser turns it
    /// back into `'` when interpreting the attribute value, so an apostrophe like English "user's" terminates the JS string,
    /// the whole handler becomes a syntax error, and **the destructive operation is submitted without confirmation**.
    /// Passed as an attribute value, HTML escaping as is is the correct defense.
    #[test]
    fn confirmation_text_is_passed_as_an_attribute_not_inline_javascript() {
        let html = render_detail(&member("HOME"));
        assert!(!html.contains("onsubmit="), "no inline handlers: {html}");
        assert!(html.contains("data-confirm="));

        // Even wording containing an apostrophe (English locale) is correctly escaped as an attribute,
        // and a raw `'` does not terminate the attribute value.
        let english = render_detail_in(Locale::En, &member("HOME"));
        let messages = Messages::new(Locale::En);
        let confirm = messages.get("admin-members-reset-mfa-confirm");
        assert!(confirm.contains('\''), "fixture must contain an apostrophe");
        assert!(english.contains("&#39;"), "apostrophe must be escaped");
        assert!(!english.contains(&format!("data-confirm=\"{confirm}\"")));
    }

    /// MT24: suspend/resume buttons only on guest rows, showing only one depending on state
    /// (showing "suspend" while suspended would just give a 403 when pressed, while looking operable).
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

        // Being suspended is visible **in the list** (the place to find needs the state).
        let listed = render_page(&[suspended], None);
        assert!(listed.contains(&Messages::new(Locale::Ja).get("admin-members-status-suspended")));

        // HOME cannot be suspended (the api returns 403 too), so no entry is shown.
        let home = render_detail(&member("HOME"));
        assert!(!home.contains("/suspend"));
        assert!(!home.contains("/resume"));

        // Invited (not accepted) has no access yet, so it is not a suspension target.
        let mut invited = member("GUEST");
        invited.status = "INVITED".into();
        let html = render_detail(&invited);
        assert!(!html.contains("/suspend"), "{html}");
        assert!(!html.contains("/resume"));
    }

    /// The unlock entry is shown **only for locked HOME users**. Showing it always would line up operations
    /// that change nothing when pressed, and locked users could not be told apart (AP6).
    #[test]
    fn the_unlock_action_appears_only_for_a_locked_home_member() {
        let unlocked = render_detail(&member("HOME"));
        assert!(!unlocked.contains("/unlock"), "{unlocked}");

        let mut locked = member("HOME");
        locked.locked = true;
        let html = render_detail(&locked);
        assert!(html.contains("/unlock"), "{html}");
        assert!(html.contains(&Messages::new(Locale::Ja).get("admin-members-unlock-button")));

        // Being locked is visible **in the list too** (the place to find who cannot get in).
        let listed = render_page(&[locked], None);
        assert!(listed.contains(&Messages::new(Locale::Ja).get("admin-members-user-status-locked")));

        // A guest's `users` record can only be operated by their home tenant's admin (ADR-0009 §3).
        let mut guest = member("GUEST");
        guest.locked = true;
        let guest_html = render_detail(&guest);
        assert!(!guest_html.contains("/unlock"), "{guest_html}");
    }

    /// The list shows the username (the primary login identifier).
    ///
    /// With only the email address and display name, **when a user says "I can't get in", you cannot tell what
    /// to have them type**. It is attached under the heading (email).
    #[test]
    fn the_list_shows_the_login_identifier_under_the_email() {
        let mut m = member("HOME");
        m.preferred_username = Some("kyon".into());
        m.name = Some("Kyon".into());
        let html = render_page(&[m], None);
        assert!(html.contains(">u@example.com</a>"), "{html}");
        assert!(html.contains("kyon · Kyon"), "{html}");
    }

    /// A value identical to the heading is not attached (people using their email as username would get the same string twice).
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

    /// ⚠ **Do not put badges on ordinary people.** If everyone shows "HOME" and "ACTIVE", the stopped ones get buried.
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

    /// ADR-0064: provisionally registered people are shown as "provisional", not "active".
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

    /// Provisionally registered people show the setup link expiry, and the badge changes once expired. The button is "reissue setup link".
    #[test]
    fn a_pending_member_shows_the_setup_link_deadline_and_its_expiry() {
        let messages = Messages::new(Locale::Ja);
        let mut m = member("HOME");
        m.pending_setup = true;
        m.setup_link_expires_at = Some("2026-09-25T14:39:45Z".into());
        let list = render_page(&[m.clone()], None);
        assert!(
            list.contains(&messages.get("admin-members-setup-link-until")),
            "{list}"
        );
        assert!(list.contains("datetime=\"2026-09-25T14:39:45Z\""), "{list}");
        let detail = render_detail(&m);
        assert!(
            detail.contains(&messages.get("admin-members-reissue-setup-link-button")),
            "{detail}"
        );
        assert!(
            !detail.contains(&messages.get("admin-members-reset-password-button")),
            "do not offer \"password reissue\" to provisionally registered people: {detail}"
        );

        m.setup_link_expired = true;
        let list = render_page(&[m.clone()], None);
        assert!(
            list.contains(&messages.get("admin-members-user-status-setup-expired")),
            "{list}"
        );
        assert!(
            !list.contains(&format!(
                ">{}<",
                messages.get("admin-members-user-status-pending")
            )),
            "an expired one must not get the same badge as an ordinary provisional one: {list}"
        );
        let detail = render_detail(&m);
        assert!(detail.contains(&messages.get("admin-members-user-status-setup-expired-help")));
    }

    /// ADR-0063: the list shows only the first line of the note (the full text is read on the single-person screen).
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
        assert_eq!(excerpt.chars().count(), 61, "60 chars + ellipsis");
    }

    /// ADR-0063: the note section is shown for both HOME and guests, with content and date when written.
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
            "the note must always be escaped: {html}"
        );
        assert!(html.contains("経緯"), "{html}");
        assert!(html.contains("datetime=\"2026-09-24T12:00:00Z\""), "{html}");
    }

    /// ADR-0063: the apps section is shown only when fetched (absent for admins without `idp.applications:read`).
    #[test]
    fn the_applications_card_is_hidden_without_the_permission() {
        let html = render_detail(&member("HOME"));
        let title = Messages::new(Locale::Ja).get("admin-member-applications-title");
        assert!(!html.contains(&title), "{html}");
    }

    /// ADR-0063: adding/removing assignments only for "individual" apps. Removing from an "everyone" app would still let them in.
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

    /// "Available apps" can be filtered in place. Rows hold the name and availability; badges carry counts.
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
        // If there are no suspended apps, that badge is not shown (pressing it would just give 0 rows).
        assert!(!html.contains("data-list-filter-state=\"application_disabled\""));
    }

    /// While record-only, it notes that assignments do not take effect yet.
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

    /// The completion notice after removal distinguishes "removed" from "was not there".
    #[test]
    fn mfa_reset_notices_distinguish_removed_from_absent() {
        let removed = render_page(&[member("HOME")], notice_key_for("mfa-reset"));
        assert!(removed.contains(&Messages::new(Locale::Ja).get("admin-members-mfa-reset-done")));

        let absent = render_page(&[member("HOME")], notice_key_for("mfa-none"));
        assert!(absent.contains(&Messages::new(Locale::Ja).get("admin-members-mfa-reset-none")));

        // Unknown notice values are ignored (arbitrary strings arrive via the query).
        assert!(notice_key_for("../../etc/passwd").is_none());
    }
}
