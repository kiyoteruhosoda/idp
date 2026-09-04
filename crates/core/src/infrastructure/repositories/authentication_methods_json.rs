//! `authentication_methods` 列（JSON の文字列配列）の読み書き。
//!
//! 同じ列を 4 つの表が持つ（`sso_sessions` / `auth_sessions` / `authorization_codes` /
//! `refresh_tokens`）。表ごとに書くと、未知の値の扱いや NULL の意味が表ごとにずれる。
//!
//! **NULL の意味は表によって違う。** `sso_sessions` では「AP4 導入前に確立したセッション」＝
//! 記録なしとして空配列で扱ってよいが、`authorization_codes` では記録なしと「単一要素で
//! 認証した」を区別しなければならない（区別しないと、分からないものを `acr` で
//! `single_factor` と名乗ってしまう）。前者は [`from_json`]、後者は [`from_json_opt`]。

use crate::domain::values::AuthenticationMethod;

/// 認証方式の配列を JSON 文字列へ落とす（保存形式は許可値の文字列配列）。
pub(crate) fn to_json(methods: &[AuthenticationMethod]) -> String {
    let values: Vec<&str> = methods.iter().map(|m| m.as_str()).collect();
    serde_json::to_string(&values).unwrap_or_else(|_| "[]".to_string())
}

/// 保存済み JSON から認証方式の配列を復元する（NULL・壊れた値は空配列）。
///
/// 未知の値は無視する（将来の版で追加された方式を持つ行を、古い版のプロセスが読んでも
/// 壊れないようにする）。
pub(crate) fn from_json(raw: Option<Vec<u8>>) -> Vec<AuthenticationMethod> {
    from_json_opt(raw).unwrap_or_default()
}

/// 保存済み JSON から復元する。**NULL は `None`**（記録が無いことを保つ）。
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
