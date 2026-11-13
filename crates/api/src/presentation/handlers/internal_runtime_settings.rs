//! Shared runtime settings API (`GET /internal/runtime-settings`, MT26 / ADR-0013).
//!
//! web has no DB (sqlx), so it cannot resolve on its own the DB-managed settings **consumed by both** api and web
//! (`COOKIE_SECURE`, `HSTS_MAX_AGE`, `AUTH_SESSION_TTL_SECS`). With the api as the single
//! source, web fetches the DB override values from this endpoint at startup.
//!
//! **What is returned is "the DB override values the running api applied at startup", not the current values of
//! `system_settings`** (ADR-0013 §1-a). Re-reading the DB every time would, when a setting has been saved but the api not yet restarted,
//! let only web (e.g. after an auto-restart following a crash) pick up the new value, creating the very mismatch
//! this endpoint exists to prevent. By handing out the api's startup snapshot, **the values web can receive are
//! always the values the running api uses**. Publishing new values is done by restarting the api.
//!
//! Returns **only DB-sourced values**, not the api's effective values (resolved through ENV and defaults). Unset keys are
//! omitted, and web falls back to its own ENV -> its own default (the default of `COOKIE_SECURE` is
//! derived by each service from its own public origin's scheme, ADR-0012 §2).
//!
//! Protected by the service auth token shared by `/internal/*` (`X-Internal-Auth-Token`). The values contain
//! no secrets (`shared_with_web` is non-secret keys only, guaranteed by `domain::system_setting`).

use crate::config::SettingSource;
use crate::domain::system_setting::is_shared_with_web;
use crate::presentation::state::AppState;
use assay_contracts::runtime_settings::SharedRuntimeSettingsResponse;
use axum::extract::State;
use axum::Json;

/// Of the runtime settings shared with web, returns the values the running api applied from the DB at startup.
pub async fn shared_runtime_settings(
    State(state): State<AppState>,
) -> Json<SharedRuntimeSettingsResponse> {
    let settings = state
        .config
        .resolved_settings()
        .iter()
        // Only DB-sourced values = what the api actually applied as DB overrides. ENV and defaults are
        // resolved by web itself, so they are not passed.
        .filter(|setting| setting.source == SettingSource::Db && is_shared_with_web(&setting.key))
        .filter_map(|setting| {
            setting
                .value
                .clone()
                .map(|value| (setting.key.clone(), value))
        })
        .collect();
    Json(SharedRuntimeSettingsResponse { settings })
}
