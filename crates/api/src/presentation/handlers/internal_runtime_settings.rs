//! 共有ランタイム設定 API（`GET /internal/runtime-settings`。MT26 / ADR-0013）。
//!
//! web は DB（sqlx）を持たないため、api と web の**両方が消費する** DB 管理設定
//! （`COOKIE_SECURE`・`HSTS_MAX_AGE`・`AUTH_SESSION_TTL_SECS`）を自力で解決できない。api を唯一の
//! 出所として、web が起動時に本エンドポイントから DB 上書き値を取得する。
//!
//! 返すのは DB 上書き値だけで、api の有効値ではない（未設定キーは含めない）。web は受け取った値を
//! 最優先とし、無いキーは自分の ENV → 自分の既定値の順に解決する。`COOKIE_SECURE` の既定は
//! 各サービスが自分の公開オリジンのスキームから導くため（ADR-0012 §2）、api の既定を押し付けない。
//!
//! 保護は `/internal/*` 共通のサービス認証トークン（`X-Internal-Auth-Token`）。値に secret は
//! 含まれない（`shared_with_web` は非 secret キーのみ。`domain::system_setting` で保証する）。

use crate::presentation::error::ApiError;
use crate::presentation::state::AppState;
use axum::extract::State;
use axum::Json;
use idp_contracts::runtime_settings::SharedRuntimeSettingsResponse;

/// web と共有するランタイム設定の DB 上書き値を返す。
pub async fn shared_runtime_settings(
    State(state): State<AppState>,
) -> Result<Json<SharedRuntimeSettingsResponse>, ApiError> {
    let overrides = state
        .system_settings
        .shared_web_overrides()
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Json(SharedRuntimeSettingsResponse {
        settings: overrides.into_iter().collect(),
    }))
}
