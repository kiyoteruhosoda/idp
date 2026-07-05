//! OpenAPI ドキュメント（utoipa による自動生成）。
//!
//! API エンドポイント仕様はここから生成される `/api/openapi.json`・Swagger UI（`/api/docs`）が
//! 唯一の出所（`CLAUDE.md`「ドキュメント運用」）。仕様はハンドラの `#[utoipa::path]` 属性と
//! DTO の `ToSchema` から組み立てられる。

use crate::presentation::dto::{
    OAuthErrorResponse, RegisterRequest, RegisterResponse, TokenRequest, TokenResponse,
    UserInfoResponse,
};
use crate::presentation::handlers;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "OIDC Identity Provider (MVP)",
        description = "OpenID Connect Identity Provider。Authorization Code Flow + PKCE(S256)。",
    ),
    paths(
        handlers::register::register,
        handlers::authorize::authorize,
        handlers::token::token,
        handlers::userinfo::userinfo,
        handlers::discovery::openid_configuration,
        handlers::discovery::jwks,
    ),
    components(schemas(
        RegisterRequest,
        RegisterResponse,
        TokenRequest,
        TokenResponse,
        UserInfoResponse,
        OAuthErrorResponse,
    )),
    modifiers(&BearerToken),
    tags(
        (name = "oidc", description = "OIDC コアエンドポイント"),
        (name = "auth", description = "ユーザー登録・認証"),
    )
)]
pub struct ApiDoc;

/// `/userinfo` の Bearer 認証スキーム定義。
struct BearerToken;

impl Modify for BearerToken {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer_token",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .build(),
            ),
        );
    }
}
