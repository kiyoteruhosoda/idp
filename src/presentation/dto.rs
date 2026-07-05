//! presentation 全体で使う共通 DTO（`〇〇Request` / `〇〇Response`）。

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    #[serde(default)]
    pub preferred_username: Option<String>,
    pub password: String,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub sub: String,
    pub status: String,
}
