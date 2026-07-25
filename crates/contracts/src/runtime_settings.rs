//! api と web が共有するランタイム設定の契約（MT26 / ADR-0013）。
//!
//! `COOKIE_SECURE`・`HSTS_MAX_AGE`・`AUTH_SESSION_TTL_SECS` のように **api と web の双方が消費し、
//! 値がずれると壊れる**設定がある（Cookie 属性の不一致はログインループ、HSTS の不一致は片方の
//! ドメインだけ保護されない状態になる）。web は DB を持たないため、これらの DB 上書き値は api が
//! 唯一の出所となり、web は起動時に本エンドポイントから受け取って解決する。
//!
//! 返すのは **DB に保存された上書き値だけ**であり、有効値そのものではない。未設定キーは含めず、
//! web は自分の ENV → 自分の既定値の順にフォールバックする（`COOKIE_SECURE` の既定は各サービスの
//! 公開オリジンのスキームから導くため、api の既定をそのまま押し付けてはいけない。ADR-0012 §2）。
//!
//! secret は決して含めない。web が必要とする bootstrap secret（`INTERNAL_SERVICE_TOKEN`・
//! `CSRF_SECRET`）は `EnvLocked` であり、web 自身の環境変数から読む。

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// 共有ランタイム設定を取得する内部エンドポイントのパス（api が公開し web が呼ぶ）。
pub const SHARED_RUNTIME_SETTINGS_PATH: &str = "/internal/runtime-settings";

/// 共有ランタイム設定の DB 上書き値。キーは `RUNTIME_SETTING_DEFINITIONS` のキー名
/// （`COOKIE_SECURE` 等）、値は DB に保存された文字列表現。
///
/// `BTreeMap` にしてキー順を安定させる（応答の差分・ログを読みやすくするため）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedRuntimeSettingsResponse {
    pub settings: BTreeMap<String, String>,
}
