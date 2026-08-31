//! web 自身の `/internal/*` を保護するミドルウェア（ADR-0031）。
//!
//! api と同じヘッダ・同じ照合（`assay_contracts::internal_auth`）を使う。web は api を呼ぶ側として
//! 既に同じトークンを持っているため、新しい秘密は増えない。
//!
//! web にも内部面が要るのは、**web 自身の状態は api には分からない**ためである（版数・起動時刻・
//! api への到達性）。api の `/internal/health` を見ても、web が生きているかは答えられない。

use crate::state::WebState;
use assay_contracts::internal_auth::{service_token_matches, SERVICE_TOKEN_HEADER};
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// `/internal/*` を保護する。トークンが一致しなければ 401 で遮断する。
///
/// 応答に理由を書かないのは、トークンが「無い」のか「違う」のかを外へ伝えないため。
pub async fn require_service_token(
    State(state): State<WebState>,
    request: Request,
    next: Next,
) -> Response {
    let presented = request
        .headers()
        .get(SERVICE_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !service_token_matches(presented, state.config.internal_service_token()) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    next.run(request).await
}
