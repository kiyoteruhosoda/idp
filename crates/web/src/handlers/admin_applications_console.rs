//! Admin console screen for apps (`/{tenant_id}/admin/applications`. ADR-0054).
//!
//! Provides list, registration, settings changes, deletion, attaching/detaching and moving bindings, and assigning
//! the principals that use it (people, service accounts). Binding targets are picked from a candidate list, not typed IDs (ADR-0067).
//! The actual operations are delegated to the api's `/admin/applications/*` by forwarding the SSO cookie (web does not touch sqlx. ADR-0007).
//!
//! ⚠ **This screen is the recovery path for lockouts** (step 4 of decision 4 in ADR-0054). Before switching, confirm that
//! adding an assignment takes seconds — open one from the list, paste the user ID and submit.

use super::locale;
use crate::admin_dto::{
    group_binding_candidates, parse_binding_choice, ApplicationBindingCandidateView,
    ApplicationCurrentUserView, ApplicationDetailView,
};
use crate::api_client::AdminApiError;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::{console_csrf_from, console_csrf_valid_in};
use crate::handlers::admin_console::{
    forbidden_response, redirect_to_login, resolve_admin, AdminContext, AdminResolution,
};
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, ApplicationDetail, ApplicationsList, ConsoleNotice};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

const APPLICATIONS_SEGMENT: &str = "/admin/applications";

macro_rules! admin_or_return {
    ($state:expr, $correlation:expr, $tenant:expr, $headers:expr) => {
        match resolve_admin($state, $correlation, $tenant, $headers).await {
            AdminResolution::Ok(uid) => uid,
            AdminResolution::Reject(resp) => return resp,
        }
    };
}

/// App list (`GET /{tenant_id}/admin/applications`).
pub async fn list(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let sso = sso(&headers);
    let result = state
        .api
        .list_applications(&correlation.0, &tenant.0, &sso)
        .await;
    let messages = Messages::new(locale(&headers));
    let csrf = console_csrf_from(&headers, state.config.csrf_secret());
    match result {
        Ok(list) => Html(render(&ApplicationsList {
            messages: &messages,
            tenant: &tenant.prefix(),
            admin: Some(admin.chrome()),
            applications: &list.applications,
            record_only: list.is_record_only(),
            csrf: &csrf,
            error: None,
        }))
        .into_response(),
        Err(e) => map_error(&messages, &tenant, &admin, &headers, e),
    }
}

/// Screen for one app (`GET /{tenant_id}/admin/applications/{application_id}`).
pub async fn detail(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_tenant_id, application_id)): Path<(String, String)>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    render_detail(
        &state,
        &correlation,
        &tenant,
        &admin,
        &headers,
        &application_id,
        None,
    )
    .await
}

#[derive(Deserialize)]
pub struct CreateApplicationForm {
    pub display_name: String,
    pub assignment_mode: String,
    /// A checkbox is sent **only when checked**. Unspecified = do not assign.
    #[serde(default)]
    pub assign_creator: Option<String>,
    pub csrf_token: String,
}

/// Registers an app (`POST /{tenant_id}/admin/applications/create`).
pub async fn create(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<CreateApplicationForm>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let sso = sso(&headers);
    if !console_csrf_valid_in(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return reload_list_with_error(
            &state,
            &correlation,
            &tenant,
            &admin,
            &headers,
            &sso,
            "admin-error-csrf",
        )
        .await;
    }
    let result = state
        .api
        .for_locale(locale(&headers))
        .create_application(
            &correlation.0,
            &tenant.0,
            &sso,
            form.display_name.trim(),
            form.assignment_mode.trim(),
            form.assign_creator.is_some(),
        )
        .await;
    match result {
        // Go to the screen of the newly created app. ⚠ **Do not return to the list** — right after creating as "individual",
        // both the roster and authentication methods are empty and must be configured next.
        Ok(application) => redirect_detail(&tenant, &application.id),
        Err(AdminApiError::Validation(m) | AdminApiError::Conflict(m)) => {
            reload_list_with_error(&state, &correlation, &tenant, &admin, &headers, &sso, &m).await
        }
        Err(e) => {
            let messages = Messages::new(locale(&headers));
            map_error(&messages, &tenant, &admin, &headers, e)
        }
    }
}

#[derive(Deserialize)]
pub struct UpdateApplicationForm {
    pub display_name: String,
    pub status: String,
    pub assignment_mode: String,
    pub csrf_token: String,
}

/// Changes an app's settings (`POST /{tenant_id}/admin/applications/{id}/update`).
pub async fn update(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_tenant_id, application_id)): Path<(String, String)>,
    Form(form): Form<UpdateApplicationForm>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let sso = sso(&headers);
    if !console_csrf_valid_in(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return render_detail(
            &state,
            &correlation,
            &tenant,
            &admin,
            &headers,
            &application_id,
            Some("admin-error-csrf"),
        )
        .await;
    }
    let result = state
        .api
        .for_locale(locale(&headers))
        .update_application(
            &correlation.0,
            &tenant.0,
            &sso,
            &application_id,
            form.display_name.trim(),
            form.status.trim(),
            form.assignment_mode.trim(),
        )
        .await;
    finish(
        &state,
        &correlation,
        &tenant,
        &admin,
        &headers,
        &application_id,
        result.map(|_| ()),
    )
    .await
}

#[derive(Deserialize)]
pub struct BindForm {
    /// The target chosen from the candidate list (`<kind>:<target>`. [`ApplicationBindingCandidateView::choice_value`]).
    #[serde(default)]
    pub candidate: String,
    /// The current owner's app ID, attached only when "move from X" was confirmed (ADR-0067).
    #[serde(default)]
    pub move_from: Option<String>,
    pub csrf_token: String,
}

/// Adds a binding (`POST /{tenant_id}/admin/applications/{id}/bind`. ADR-0059 / ADR-0067).
///
/// If the chosen target is another app's binding, it is not sent right away; a "move from X" confirmation is shown. Only when
/// resent from the confirmation (with `move_from`) is the api asked to move it — the api does detach + bind in one go.
pub async fn bind(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_tenant_id, application_id)): Path<(String, String)>,
    Form(form): Form<BindForm>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let sso = sso(&headers);
    if !console_csrf_valid_in(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return render_detail(
            &state,
            &correlation,
            &tenant,
            &admin,
            &headers,
            &application_id,
            Some("admin-error-csrf"),
        )
        .await;
    }
    let Some((kind, reference)) = parse_binding_choice(&form.candidate) else {
        return render_detail(
            &state,
            &correlation,
            &tenant,
            &admin,
            &headers,
            &application_id,
            Some("admin-applications-bind-invalid"),
        )
        .await;
    };
    let move_from = form
        .move_from
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if move_from.is_none() {
        // Re-fetch the chosen target's current owner (do not trust the value from when the screen was shown). If it is another
        // app's binding, show the confirmation. ⚠ If candidates could not be read, skip the confirmation and send — if there is an
        // owner, the api returns 409 with that app's name, so nothing is silently taken.
        let candidates = state
            .api
            .application_binding_candidates(&correlation.0, &tenant.0, &sso, &application_id)
            .await
            .map(|list| list.candidates)
            .unwrap_or_default();
        if let Some(owned) = candidates.into_iter().find(|c| {
            c.kind == kind
                && c.reference == reference
                && c.application_id
                    .as_deref()
                    .is_some_and(|a| a != application_id)
        }) {
            return render_detail_with(
                &state,
                &correlation,
                &tenant,
                &admin,
                &headers,
                &application_id,
                None,
                Some(owned),
            )
            .await;
        }
    }
    // The kind is validated by the api (copying it here would put the rule in two places).
    let result = state
        .api
        .for_locale(locale(&headers))
        .add_application_binding(
            &correlation.0,
            &tenant.0,
            &sso,
            &application_id,
            kind,
            reference,
            move_from,
        )
        .await;
    finish(
        &state,
        &correlation,
        &tenant,
        &admin,
        &headers,
        &application_id,
        result.map(|_| ()),
    )
    .await
}

#[derive(Deserialize)]
pub struct DeleteApplicationForm {
    pub csrf_token: String,
}

/// Deletes an app (`POST /{tenant_id}/admin/applications/{id}/delete`).
///
/// Like the api's deletion, removes bindings and principals and deletes (the targets' registrations remain). The screen shows
/// what will be removed first, with a confirmation before sending. After deletion return to the list (the deleted app's screen is 404).
pub async fn delete(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_tenant_id, application_id)): Path<(String, String)>,
    Form(form): Form<DeleteApplicationForm>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let sso = sso(&headers);
    if !console_csrf_valid_in(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return render_detail(
            &state,
            &correlation,
            &tenant,
            &admin,
            &headers,
            &application_id,
            Some("admin-error-csrf"),
        )
        .await;
    }
    let result = state
        .api
        .for_locale(locale(&headers))
        .delete_application(&correlation.0, &tenant.0, &sso, &application_id)
        .await;
    match result {
        Ok(()) => {
            axum::response::Redirect::to(&format!("{}{APPLICATIONS_SEGMENT}", tenant.prefix()))
                .into_response()
        }
        Err(e) => {
            finish(
                &state,
                &correlation,
                &tenant,
                &admin,
                &headers,
                &application_id,
                Err(e),
            )
            .await
        }
    }
}

#[derive(Deserialize)]
pub struct BindingIdForm {
    pub binding_id: String,
    pub csrf_token: String,
}

/// Removes a binding (`POST /{tenant_id}/admin/applications/{id}/unbind`).
pub async fn unbind(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_tenant_id, application_id)): Path<(String, String)>,
    Form(form): Form<BindingIdForm>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let sso = sso(&headers);
    if !console_csrf_valid_in(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return render_detail(
            &state,
            &correlation,
            &tenant,
            &admin,
            &headers,
            &application_id,
            Some("admin-error-csrf"),
        )
        .await;
    }
    let result = state
        .api
        .for_locale(locale(&headers))
        .remove_application_binding(
            &correlation.0,
            &tenant.0,
            &sso,
            &application_id,
            form.binding_id.trim(),
        )
        .await;
    finish(
        &state,
        &correlation,
        &tenant,
        &admin,
        &headers,
        &application_id,
        result,
    )
    .await
}

#[derive(Deserialize)]
pub struct AssignForm {
    /// `user` / `service_account`. When copying from "people currently in", `user` is sent.
    #[serde(default = "user_kind")]
    pub kind: String,
    /// User ID for a person, client ID for a service account.
    pub target: String,
    pub csrf_token: String,
}

fn user_kind() -> String {
    "user".to_string()
}

/// Adds a principal (`POST /{tenant_id}/admin/applications/{id}/assign`. ADR-0059).
///
/// One entry point; "person / service account" is chosen after pressing it. The kind is validated by the api.
pub async fn assign(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_tenant_id, application_id)): Path<(String, String)>,
    Form(form): Form<AssignForm>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let sso = sso(&headers);
    if !console_csrf_valid_in(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return render_detail(
            &state,
            &correlation,
            &tenant,
            &admin,
            &headers,
            &application_id,
            Some("admin-error-csrf"),
        )
        .await;
    }
    let result = state
        .api
        .for_locale(locale(&headers))
        .assign_application_principal(
            &correlation.0,
            &tenant.0,
            &sso,
            &application_id,
            form.kind.trim(),
            form.target.trim(),
        )
        .await;
    finish(
        &state,
        &correlation,
        &tenant,
        &admin,
        &headers,
        &application_id,
        result.map(|_| ()),
    )
    .await
}

#[derive(Deserialize)]
pub struct UnassignForm {
    /// `user` / `service_account` (each row has a fixed kind).
    pub kind: String,
    /// User ID for a person, client ID for a service account.
    pub target: String,
    pub csrf_token: String,
}

/// Removes a principal (`POST /{tenant_id}/admin/applications/{id}/unassign`). Sent to the api matching the row's kind.
pub async fn unassign(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_tenant_id, application_id)): Path<(String, String)>,
    Form(form): Form<UnassignForm>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let sso = sso(&headers);
    if !console_csrf_valid_in(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return render_detail(
            &state,
            &correlation,
            &tenant,
            &admin,
            &headers,
            &application_id,
            Some("admin-error-csrf"),
        )
        .await;
    }
    let api = state.api.for_locale(locale(&headers));
    let result = match form.kind.trim() {
        "service_account" => {
            api.unassign_application_service_account(
                &correlation.0,
                &tenant.0,
                &sso,
                &application_id,
                form.target.trim(),
            )
            .await
        }
        _ => {
            api.unassign_application_user(
                &correlation.0,
                &tenant.0,
                &sso,
                &application_id,
                form.target.trim(),
            )
            .await
        }
    };
    finish(
        &state,
        &correlation,
        &tenant,
        &admin,
        &headers,
        &application_id,
        result,
    )
    .await
}

// ── Helpers ─────────────────────────────────────────────────────────────────

async fn finish(
    state: &WebState,
    correlation: &CorrelationId,
    tenant: &WebTenant,
    admin: &AdminContext,
    headers: &HeaderMap,
    application_id: &str,
    result: Result<(), AdminApiError>,
) -> Response {
    match result {
        // PRG. The details are re-fetched for rendering, so a reload does not repeat the operation.
        Ok(()) => redirect_detail(tenant, application_id),
        Err(AdminApiError::NotFound) => {
            let messages = Messages::new(locale(headers));
            not_found(&messages, tenant, admin)
        }
        // Input errors (400 / 409) show the api's message as is. Copying the checks into web would
        // split the rules into two places and one would go stale.
        Err(AdminApiError::Validation(m) | AdminApiError::Conflict(m)) => {
            render_detail(
                state,
                correlation,
                tenant,
                admin,
                headers,
                application_id,
                Some(&m),
            )
            .await
        }
        Err(e) => {
            let messages = Messages::new(locale(headers));
            map_error(&messages, tenant, admin, headers, e)
        }
    }
}

/// Re-fetches the details and renders (with an error if needed).
async fn render_detail(
    state: &WebState,
    correlation: &CorrelationId,
    tenant: &WebTenant,
    admin: &AdminContext,
    headers: &HeaderMap,
    application_id: &str,
    error: Option<&str>,
) -> Response {
    render_detail_with(
        state,
        correlation,
        tenant,
        admin,
        headers,
        application_id,
        error,
        None,
    )
    .await
}

/// Re-fetches the details and renders. If there is a `pending_move`, attaches the "move from X" confirmation (ADR-0067).
#[allow(clippy::too_many_arguments)]
async fn render_detail_with(
    state: &WebState,
    correlation: &CorrelationId,
    tenant: &WebTenant,
    admin: &AdminContext,
    headers: &HeaderMap,
    application_id: &str,
    error: Option<&str>,
    pending_move: Option<ApplicationBindingCandidateView>,
) -> Response {
    let sso = sso(headers);
    let detail = match state
        .api
        .get_application(&correlation.0, &tenant.0, &sso, application_id)
        .await
    {
        Ok(detail) => detail,
        Err(AdminApiError::NotFound) => {
            let messages = Messages::new(locale(headers));
            return not_found(&messages, tenant, admin);
        }
        Err(e) => {
            let messages = Messages::new(locale(headers));
            return map_error(&messages, tenant, admin, headers, e);
        }
    };
    // Only for "everyone", fetch the people currently in (the copy source. Decision 3 of ADR-0054).
    // ⚠ Even if this fails, show the screen — being unable to fix the settings would be worse.
    let current = if detail.application.is_individual() {
        None
    } else {
        state
            .api
            .application_current_users(&correlation.0, &tenant.0, &sso, application_id)
            .await
            .ok()
    };
    // Binding candidates (ADR-0067). ⚠ Even if this fails, show the screen (the screen says the candidates could not be read).
    let candidates = state
        .api
        .application_binding_candidates(&correlation.0, &tenant.0, &sso, application_id)
        .await
        .ok();
    let candidates_unavailable = candidates.is_none();
    let candidate_groups =
        group_binding_candidates(candidates.map(|c| c.candidates).unwrap_or_default());
    // Build Messages after the await (it is non-Send, so it must not live across an await).
    let messages = Messages::new(locale(headers));
    let csrf = console_csrf_from(headers, state.config.csrf_secret());
    let delete_summary = delete_summary(&messages, &detail);
    // "Individual" apps need no copy source, so render it empty (the screen decides what to show).
    let no_users: Vec<ApplicationCurrentUserView> = Vec::new();
    let body = render(&ApplicationDetail {
        messages: &messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        application: &detail.application,
        assigned: &detail.assigned,
        assigned_service_accounts: &detail.assigned_service_accounts,
        current_users: current
            .as_ref()
            .map(|c| c.users.as_slice())
            .unwrap_or(&no_users),
        current_users_truncated: current.as_ref().map(|c| c.truncated).unwrap_or(false),
        current_users_total: current.as_ref().map(|c| c.total).unwrap_or(0),
        candidate_groups: &candidate_groups,
        candidates_unavailable,
        pending_move: pending_move.as_ref(),
        delete_summary: &delete_summary,
        record_only: detail.is_record_only(),
        csrf: &csrf,
        error,
    });
    match error {
        Some(_) => (StatusCode::BAD_REQUEST, Html(body)).into_response(),
        None => Html(body).into_response(),
    }
}

/// Summary of what "delete this app" removes. ⚠ The api's deletion (`delete_application`) **removes bindings and
/// principals and deletes** (does not refuse), so the counts are phrased as "things to remove".
fn delete_summary(messages: &Messages, detail: &ApplicationDetailView) -> String {
    let bindings = detail.application.bindings.len();
    let principals = detail.assigned.len() + detail.assigned_service_accounts.len();
    if bindings == 0 && principals == 0 {
        return messages.get("admin-applications-delete-empty");
    }
    messages.get_args(
        "admin-applications-delete-summary",
        &[
            ("bindings", &bindings.to_string()),
            ("principals", &principals.to_string()),
        ],
    )
}

/// Re-fetches the list and re-renders with an error (not PRG, so the reason can be shown).
async fn reload_list_with_error(
    state: &WebState,
    correlation: &CorrelationId,
    tenant: &WebTenant,
    admin: &AdminContext,
    headers: &HeaderMap,
    sso: &str,
    error: &str,
) -> Response {
    let list = state
        .api
        .list_applications(&correlation.0, &tenant.0, sso)
        .await;
    let (applications, record_only) = match list {
        Ok(list) => {
            let record_only = list.is_record_only();
            (list.applications, record_only)
        }
        Err(_) => (Vec::new(), true),
    };
    let messages = Messages::new(locale(headers));
    let csrf = console_csrf_from(headers, state.config.csrf_secret());
    (
        StatusCode::BAD_REQUEST,
        Html(render(&ApplicationsList {
            messages: &messages,
            tenant: &tenant.prefix(),
            admin: Some(admin.chrome()),
            applications: &applications,
            record_only,
            csrf: &csrf,
            error: Some(error),
        })),
    )
        .into_response()
}

fn redirect_detail(tenant: &WebTenant, application_id: &str) -> Response {
    axum::response::Redirect::to(&format!(
        "{}{APPLICATIONS_SEGMENT}/{application_id}",
        tenant.prefix()
    ))
    .into_response()
}

fn sso(headers: &HeaderMap) -> String {
    cookies::get(headers, cookies::SSO_SESSION_COOKIE).unwrap_or_default()
}

fn not_found(messages: &Messages, tenant: &WebTenant, admin: &AdminContext) -> Response {
    (
        StatusCode::NOT_FOUND,
        Html(render(&ConsoleNotice {
            messages,
            tenant: &tenant.prefix(),
            admin: Some(admin.chrome()),
            heading: None,
            message: "api-application-not-found",
            is_error: true,
            back_href: Some(&format!("{}{APPLICATIONS_SEGMENT}", tenant.prefix())),
            back_label: "admin-applications-back",
        })),
    )
        .into_response()
}

fn map_error(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &AdminContext,
    headers: &HeaderMap,
    e: AdminApiError,
) -> Response {
    match e {
        AdminApiError::Unauthorized => redirect_to_login(tenant),
        AdminApiError::Forbidden => forbidden_response(headers),
        _ => internal_error(messages, tenant, admin),
    }
}

fn internal_error(messages: &Messages, tenant: &WebTenant, admin: &AdminContext) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Html(render(&ConsoleNotice {
            messages,
            tenant: &tenant.prefix(),
            admin: Some(admin.chrome()),
            heading: None,
            message: "admin-error-internal",
            is_error: true,
            back_href: Some(&format!("{}{APPLICATIONS_SEGMENT}", tenant.prefix())),
            back_label: "admin-applications-back",
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::delete_summary;
    use crate::admin_dto::{
        group_binding_candidates, ApplicationAssignmentView, ApplicationBindingCandidateView,
        ApplicationBindingView, ApplicationDetailView, ApplicationServiceAccountAssignmentView,
        ApplicationView,
    };
    use crate::handlers::admin_console::AdminContext;
    use crate::i18n::{Locale, Messages};
    use crate::templates::{render, ApplicationDetail};

    fn application() -> ApplicationView {
        ApplicationView {
            id: "app-1".into(),
            display_name: "wiki".into(),
            status: "ACTIVE".into(),
            assignment_mode: "INDIVIDUAL".into(),
            bindings: Vec::new(),
            assigned_count: 1,
            created_at: "2026-09-16T00:00:00Z".into(),
            updated_at: "2026-09-16T00:00:00Z".into(),
        }
    }

    /// "Principals using this app" lists people and service accounts in one list, and ⚠ **never icon-only:
    /// the kind text is always attached** (distinguishable with screen readers too. ADR-0048 / ADR-0059).
    /// The remove operation sends the value matching the row's kind.
    #[test]
    fn people_and_service_accounts_share_one_list_with_their_kind_spelled_out() {
        let messages = Messages::new(Locale::Ja);
        let admin = AdminContext::for_test("admin", Some("Root"));
        let assigned = vec![ApplicationAssignmentView {
            user_id: "user-1".into(),
            sub: "sub-1".into(),
            email: "alice@example.com".into(),
            name: None,
            status: "ACTIVE".into(),
            assigned_at: "2026-09-16T00:00:00Z".into(),
        }];
        let accounts = vec![ApplicationServiceAccountAssignmentView {
            client_id: "wiki-machine".into(),
            app_name: "wiki machine".into(),
            status: "ACTIVE".into(),
            assigned_at: "2026-09-16T00:00:00Z".into(),
        }];
        let html = render(&ApplicationDetail {
            messages: &messages,
            tenant: "/t",
            admin: Some(admin.chrome()),
            application: &application(),
            assigned: &assigned,
            assigned_service_accounts: &accounts,
            current_users: &[],
            current_users_truncated: false,
            current_users_total: 0,
            candidate_groups: &[],
            candidates_unavailable: false,
            pending_move: None,
            delete_summary: "",
            record_only: false,
            csrf: "csrf",
            error: None,
        });

        assert!(html.contains("このアプリを使う主体"));
        assert!(html.contains(r#"<i class="fa-solid fa-user me-1" aria-hidden="true"></i>人"#));
        assert!(
            html.contains(r#"<i class="fa-solid fa-server me-1" aria-hidden="true"></i>サービス"#)
        );
        assert!(html.contains("alice@example.com"));
        assert!(html.contains("wiki-machine"));
        assert!(html.contains(r#"name="kind" value="service_account""#));
        assert!(html.contains(r#"name="target" value="wiki-machine""#));
        assert!(html.contains("「全員」に含まれるのは人だけです"));
    }

    fn candidate(
        kind: &str,
        reference: &str,
        owner: Option<(&str, &str)>,
    ) -> ApplicationBindingCandidateView {
        ApplicationBindingCandidateView {
            kind: kind.into(),
            reference: reference.into(),
            identifier: reference.into(),
            display_name: format!("{reference} の登録名"),
            application_id: owner.map(|(id, _)| id.to_string()),
            application_name: owner.map(|(_, name)| name.to_string()),
        }
    }

    /// Binding targets are chosen from per-kind candidates, not typed IDs (ADR-0067). Another app's binding has
    /// its owner attached, and there is no free-input field.
    #[test]
    fn binding_targets_are_chosen_from_candidates_that_name_their_owner() {
        let messages = Messages::new(Locale::Ja);
        let admin = AdminContext::for_test("admin", Some("Root"));
        let groups = group_binding_candidates(vec![
            candidate("resource", "api://wiki", None),
            candidate("oidc", "wiki-login", Some(("app-auto", "wiki（自動）"))),
            candidate("service_account", "wiki-machine", None),
        ]);
        let html = render(&ApplicationDetail {
            messages: &messages,
            tenant: "/t",
            admin: Some(admin.chrome()),
            application: &application(),
            assigned: &[],
            assigned_service_accounts: &[],
            current_users: &[],
            current_users_truncated: false,
            current_users_total: 0,
            candidate_groups: &groups,
            candidates_unavailable: false,
            pending_move: None,
            delete_summary: "",
            record_only: false,
            csrf: "csrf",
            error: None,
        });

        assert!(
            html.contains(
                r#"<select class="form-select" id="bind-candidate" name="candidate" required>"#
            ),
            "{html}"
        );
        assert!(
            !html.contains(r#"id="bind-target""#),
            "the free-text target is gone: {html}"
        );
        // Grouped in kind order (login → service account → audience).
        let login = html
            .find(r#"<optgroup label="ログイン（OIDC）">"#)
            .expect("login group");
        let machine = html
            .find(r#"<optgroup label="サービスアカウント">"#)
            .expect("service account group");
        let resource = html
            .find(r#"<optgroup label="API の宛名（aud）">"#)
            .expect("resource group");
        assert!(login < machine && machine < resource, "{html}");
        assert!(html.contains(r#"value="oidc:wiki-login""#), "{html}");
        assert!(html.contains(r#"value="resource:api://wiki""#), "{html}");
        assert!(
            html.contains("いま「wiki（自動）」の名乗り"),
            "the owner is named: {html}"
        );
    }

    /// On the English screen the owner note is attached in ASCII parentheses, and counts are phrased in a plural-safe form.
    #[test]
    fn english_owner_note_and_delete_summary_read_naturally() {
        let messages = Messages::new(Locale::En);
        assert_eq!(
            messages.get_arg("admin-applications-candidate-owned", "application", "wiki"),
            r#" (currently on "wiki")"#
        );
        assert_eq!(
            messages.get_args(
                "admin-applications-delete-summary",
                &[("bindings", "1"), ("principals", "0")],
            ),
            "Deleting removes these from this application: identities: 1, assigned principals: 0."
        );
    }

    /// If the chosen target is another app's binding, a "move from X" confirmation is shown. The resend names the source.
    #[test]
    fn a_target_owned_elsewhere_asks_to_move_it_from_that_application() {
        let messages = Messages::new(Locale::Ja);
        let admin = AdminContext::for_test("admin", Some("Root"));
        let owned = candidate("oidc", "wiki-login", Some(("app-auto", "wiki（自動）")));
        let html = render(&ApplicationDetail {
            messages: &messages,
            tenant: "/t",
            admin: Some(admin.chrome()),
            application: &application(),
            assigned: &[],
            assigned_service_accounts: &[],
            current_users: &[],
            current_users_truncated: false,
            current_users_total: 0,
            candidate_groups: &[],
            candidates_unavailable: false,
            pending_move: Some(&owned),
            delete_summary: "",
            record_only: false,
            csrf: "csrf",
            error: None,
        });

        assert!(html.contains("「wiki（自動）」から移しますか？"), "{html}");
        assert!(
            html.contains(r#"name="candidate" value="oidc:wiki-login""#),
            "{html}"
        );
        assert!(
            html.contains(r#"name="move_from" value="app-auto""#),
            "{html}"
        );
        assert!(html.contains("「wiki（自動）」から移す</button>"), "{html}");
    }

    /// Before deleting, the screen says what will be removed. If there is a login binding, it also says it leaves the check.
    #[test]
    fn deleting_says_what_comes_off_before_asking() {
        let messages = Messages::new(Locale::Ja);
        let admin = AdminContext::for_test("admin", Some("Root"));
        let mut app = application();
        app.bindings = vec![ApplicationBindingView {
            id: "b-1".into(),
            kind: "oidc".into(),
            identifier: Some("wiki-login".into()),
            display_name: Some("wiki".into()),
        }];
        let detail = ApplicationDetailView {
            application: app.clone(),
            assigned: Vec::new(),
            assigned_service_accounts: Vec::new(),
            enforcement: "enforce".into(),
        };
        let summary = delete_summary(&messages, &detail);
        assert_eq!(
            summary,
            "名乗り 1 件と、使う主体 0 件を外して、このアプリを消します。"
        );
        let html = render(&ApplicationDetail {
            messages: &messages,
            tenant: "/t",
            admin: Some(admin.chrome()),
            application: &app,
            assigned: &[],
            assigned_service_accounts: &[],
            current_users: &[],
            current_users_truncated: false,
            current_users_total: 0,
            candidate_groups: &[],
            candidates_unavailable: false,
            pending_move: None,
            delete_summary: &summary,
            record_only: false,
            csrf: "csrf",
            error: None,
        });
        assert!(html.contains(&summary), "{html}");
        assert!(
            html.contains(r#"action="/t/admin/applications/app-1/delete""#),
            "{html}"
        );
        assert!(
            html.contains(r#"data-confirm="「wiki」を消します。元に戻せません。よろしいですか？""#),
            "{html}"
        );
        assert!(
            html.contains("このテナントの誰でもログインできるようになります"),
            "{html}"
        );

        let empty = ApplicationDetailView {
            application: application(),
            assigned: Vec::new(),
            assigned_service_accounts: Vec::new(),
            enforcement: "enforce".into(),
        };
        assert_eq!(
            delete_summary(&messages, &empty),
            "このアプリには名乗りも使う主体もありません。"
        );
    }
}
