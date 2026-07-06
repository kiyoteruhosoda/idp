//! 管理コンソール（web）が api の JSON 管理 API（`/admin/*`）を呼ぶときに共有する DTO 契約。
//!
//! これらは api の `RequirePerms<IdpAdmin>` で保護される内部認可 API のレスポンス型で、web は
//! 管理者の SSO Cookie を転送して呼ぶ（ADR-0007 §4）。OpenAPI（外部公開 API）とは別系統のため
//! `utoipa` は付けない。

use serde::{Deserialize, Serialize};

/// `GET /admin/whoami` のレスポンス。アクセスできること自体が「有効な SSO ＋ `idp.admin` 保有」を意味する。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoamiResponse {
    /// 認可済み管理利用者の内部 ID（UUID 文字列）。
    pub user_id: String,
}
