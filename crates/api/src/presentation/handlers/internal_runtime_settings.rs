//! 共有ランタイム設定 API（`GET /internal/runtime-settings`。MT26 / ADR-0013）。
//!
//! web は DB（sqlx）を持たないため、api と web の**両方が消費する** DB 管理設定
//! （`COOKIE_SECURE`・`HSTS_MAX_AGE`・`AUTH_SESSION_TTL_SECS`）を自力で解決できない。api を唯一の
//! 出所として、web が起動時に本エンドポイントから DB 上書き値を取得する。
//!
//! **返すのは「実行中の api が起動時に適用した DB 上書き値」であり、`system_settings` の現在値では
//! ない**（ADR-0013 §1-a）。毎回 DB を読み直すと、設定を保存したが api をまだ再起動していない状態で
//! web だけが（クラッシュ後の自動再起動などで）新しい値を拾い、このエンドポイントが防ごうとしている
//! 不一致そのものを作ってしまう。api の起動時スナップショットを配ることで、**web が受け取れる値は
//! 必ず実行中の api が使っている値**になる。新しい値の公開は api の再起動が担う。
//!
//! api の有効値（ENV・既定値まで解決した結果）ではなく **DB 由来の値だけ**を返す。未設定キーは
//! 含めず、web は自分の ENV → 自分の既定値の順にフォールバックする（`COOKIE_SECURE` の既定は
//! 各サービスが自分の公開オリジンのスキームから導くため。ADR-0012 §2）。
//!
//! 保護は `/internal/*` 共通のサービス認証トークン（`X-Internal-Auth-Token`）。値に secret は
//! 含まれない（`shared_with_web` は非 secret キーのみ。`domain::system_setting` で保証する）。

use crate::config::SettingSource;
use crate::domain::system_setting::is_shared_with_web;
use crate::presentation::state::AppState;
use axum::extract::State;
use axum::Json;
use idp_contracts::runtime_settings::SharedRuntimeSettingsResponse;

/// web と共有するランタイム設定のうち、実行中の api が起動時に DB から適用した値を返す。
pub async fn shared_runtime_settings(
    State(state): State<AppState>,
) -> Json<SharedRuntimeSettingsResponse> {
    let settings = state
        .config
        .resolved_settings()
        .iter()
        // 出所が DB のものだけ＝ api が実際に DB 上書きとして適用した値。ENV・既定値は web が
        // 自分で解決するため渡さない。
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
