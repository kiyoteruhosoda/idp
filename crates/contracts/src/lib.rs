//! Inter-service DTO contracts of the OIDC IdP (`assay-contracts`).
//!
//! ADR-0007 (API/Web service split) §6. The JSON DTOs returned by api (server) and the types used by
//! web (client) are shared as **the same serde structs**, guaranteeing contract consistency at compile
//! time. No dependency on DB, axum or sqlx (HTTP uses only `http` basic types; see [`http_trace`]).
//! No code generation from OpenAPI; types are defined once in Rust.
//! OpenAPI via utoipa stays on the api side (DTOs of the publicly exposed API live in api's presentation).

pub mod admin;
pub mod application_log;
pub mod auth;
pub mod cookie_domain;
pub mod cookies;
pub mod csrf;
pub mod deployment;
pub mod forwarded;
pub mod frame_ancestors;
pub mod health;
pub mod http_trace;
pub mod internal_auth;
pub mod runtime_settings;
pub mod session_key;

pub mod version;
