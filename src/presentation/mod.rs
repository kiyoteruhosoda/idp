//! プレゼンテーション層（axum ハンドラ・ルータ・DTO）。
//!
//! ルータ集約は `router`、各エンドポイントは `handlers` 配下、共有状態は `state`、
//! 共通 DTO は `dto`、エラー変換は `error`。

pub mod dto;
pub mod error;
pub mod handlers;
pub mod router;
pub mod state;
