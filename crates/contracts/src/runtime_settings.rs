//! Contract for runtime settings shared by api and web (MT26 / ADR-0013).
//!
//! Some settings, like `COOKIE_SECURE`, `HSTS_MAX_AGE` and `AUTH_SESSION_TTL_SECS`, are **consumed by
//! both api and web and break when they diverge** (mismatched cookie attributes cause a login loop,
//! mismatched HSTS leaves one domain unprotected). web has no DB, so api is the only source of these DB
//! overrides, and web receives them from this endpoint at startup and resolves them.
//!
//! Only **overrides stored in the DB** are returned, not the effective values. Unset keys are omitted,
//! and web falls back to its own ENV, then its own default (the `COOKIE_SECURE` default derives from each
//! service's public origin scheme, so api's default must not be imposed as is; ADR-0012 §2).
//!
//! Secrets are never included. The bootstrap secrets web needs (`INTERNAL_SERVICE_TOKEN`,
//! `CSRF_SECRET`) are `EnvLocked` and read from web's own environment variables.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Path of the internal endpoint that returns the shared runtime settings (api exposes it, web calls it).
pub const SHARED_RUNTIME_SETTINGS_PATH: &str = "/internal/runtime-settings";

/// DB overrides of the shared runtime settings. Keys are the key names of `RUNTIME_SETTING_DEFINITIONS`
/// (`COOKIE_SECURE` etc.); values are the string representation stored in the DB.
///
/// A `BTreeMap` keeps the key order stable (so response diffs and logs are easier to read).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedRuntimeSettingsResponse {
    pub settings: BTreeMap<String, String>,
}
