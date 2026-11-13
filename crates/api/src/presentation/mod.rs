//! Presentation layer (axum handlers, routers, DTOs).
//!
//! Routers are aggregated in `router`, endpoints live under `handlers`, shared state in `state`,
//! common DTOs in `dto`, error conversion in `error`.

pub mod admin;
pub mod client_auth;
pub mod client_country;
pub mod client_device;
pub mod cookies;
pub mod correlation;
pub mod cors;
pub mod dto;
pub mod error;
pub mod handlers;
pub mod i18n;
pub mod metrics;
pub mod openapi;
pub mod origin;
pub mod router;
pub mod security_headers;
pub mod state;
pub mod tenant;
pub mod token_endpoint_load;
