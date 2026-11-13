//! Reading and writing the `authentication_methods` column (JSON string array).
//!
//! Four tables have the same column (`sso_sessions` / `auth_sessions` / `authorization_codes` /
//! `refresh_tokens`). Writing it per table would make the handling of unknown values and the meaning of NULL drift per table.
//!
//! **The meaning of NULL differs by table.** In `sso_sessions`, "a session established before AP4" =
//! no record, which may be treated as an empty array, but `authorization_codes` must distinguish no record from
//! "authenticated with a single factor" (otherwise something unknown would be asserted as
//! `single_factor` in `acr`). The former is [`from_json`], the latter [`from_json_opt`].

use crate::domain::values::AuthenticationMethod;

/// Serializes an array of authentication methods to a JSON string (stored as an array of allowed-value strings).
pub(crate) fn to_json(methods: &[AuthenticationMethod]) -> String {
    let values: Vec<&str> = methods.iter().map(|m| m.as_str()).collect();
    serde_json::to_string(&values).unwrap_or_else(|_| "[]".to_string())
}

/// Restores an array of authentication methods from stored JSON (NULL or broken values become an empty array).
///
/// Unknown values are ignored (so an old-version process reading a row with methods added in a newer version
/// doesn't break).
pub(crate) fn from_json(raw: Option<Vec<u8>>) -> Vec<AuthenticationMethod> {
    from_json_opt(raw).unwrap_or_default()
}

/// Restores from stored JSON. **NULL is `None`** (preserves the absence of a record).
pub(crate) fn from_json_opt(raw: Option<Vec<u8>>) -> Option<Vec<AuthenticationMethod>> {
    let bytes = raw?;
    let values: Vec<String> = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "invalid JSON in authentication_methods");
            return None;
        }
    };
    Some(
        values
            .iter()
            .filter_map(|v| AuthenticationMethod::parse(v).ok())
            .collect(),
    )
}
