//! プレゼンテーション層（axum ハンドラ・ルータ・DTO）。
//!
//! ルータ集約は `router`、各エンドポイントは `handlers` 配下に置く。DTO・cookie・エラー変換は
//! 以降のフェーズで追加する。

pub mod handlers;
pub mod router;
