//! CORS ミドルウェア（G1）。
//!
//! 既定トポロジは `domain-split`（api と web が別ホスト名）なので、SPA（public client）が
//! `identity.example.com/{tenant}/token` を呼ぶのは常にクロスオリジンになる。
//! `application/x-www-form-urlencoded` の POST は CORS-safelisted でリクエスト自体は飛ぶが、
//! `Access-Control-Allow-Origin` が無いためブラウザが**レスポンスを読めない**——これが G1 の症状。
//!
//! # 経路の分け方
//!
//! | 経路 | 判定 |
//! |---|---|
//! | `/.well-known/openid-configuration`・`/.well-known/jwks.json`・`/{tenant}/saml/metadata` | 無認証で誰でも取得できる公開メタデータなので `Access-Control-Allow-Origin: *` |
//! | `/{tenant}/token`・`/revoke`・`/introspect`・`/userinfo` | テナントの許可オリジン集合（[`assay_core::application::cors_policy`]）と完全一致したときだけ、そのオリジンを反映 |
//! | それ以外（管理 API・`/internal/*`・`/authorize` のリダイレクト） | CORS ヘッダを付けない（ブラウザ JS から叩く経路ではない） |
//!
//! **`Access-Control-Allow-Credentials` はどの経路にも付けない。** api はブラウザ Cookie を
//! 読まない（ADR-0018）ため、付ける理由が無い。付けないことで、公開メタデータの `*` が
//! セッションの持ち出しにつながらないことも構造的に保証される。
//!
//! # なぜ `tower_http::CorsLayer` ではないのか
//!
//! 許可オリジンがテナントごと・登録クライアントごとに動的に決まるため。`CorsLayer` の
//! `AllowOrigin::predicate` でも書けるが、判定に DB 参照（async）が要る。

use crate::presentation::state::AppState;
use assay_core::domain::tenant::TenantId;
use axum::extract::{Request, State};
use axum::http::header::{
    HeaderValue, ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS,
    ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_MAX_AGE, ACCESS_CONTROL_REQUEST_HEADERS, ORIGIN,
    VARY,
};
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use uuid::Uuid;

/// プリフライト結果のキャッシュ時間（秒）。許可集合は管理画面から変わりうるので短めにする。
const PREFLIGHT_MAX_AGE_SECS: u64 = 600;

/// プリフライトで許可するメソッド（ assay のプロトコル面は GET と POST しか使わない）。
const ALLOWED_METHODS: &str = "GET, POST, OPTIONS";

/// リクエストの CORS 上の扱い。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CorsScope {
    /// 誰でも取得できる公開メタデータ（`*`）。
    PublicMetadata,
    /// テナントの許可オリジンとの照合が要る保護されたプロトコル面。
    TenantScoped(TenantId),
    /// CORS を有効にしない経路。
    None,
}

pub async fn apply_cors(State(state): State<AppState>, request: Request, next: Next) -> Response {
    // `Origin` の無いリクエストはブラウザの越境アクセスではない（curl・サーバ間）。何もしない。
    let Some(origin) = request
        .headers()
        .get(ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
    else {
        return next.run(request).await;
    };
    let scope = classify(request.uri().path());
    if scope == CorsScope::None {
        return next.run(request).await;
    }

    let allow_origin = match scope {
        CorsScope::PublicMetadata => Some("*".to_string()),
        CorsScope::TenantScoped(tenant_id) => state
            .cors_policy
            .allows(tenant_id, &origin)
            .await
            .then_some(origin),
        CorsScope::None => None,
    };

    // プリフライト（OPTIONS）はハンドラまで通さずここで完結させる。ルータは OPTIONS を
    // 持たないため、通すと 405 になり CORS ヘッダも載らない。
    if request.method() == Method::OPTIONS {
        let requested_headers = request
            .headers()
            .get(ACCESS_CONTROL_REQUEST_HEADERS)
            .cloned();
        return preflight_response(allow_origin.as_deref(), requested_headers);
    }

    let mut response = next.run(request).await;
    // 許可しないオリジンにはヘッダを付けない（ブラウザ側で読み取りが失敗する = 期待どおり）。
    if let Some(value) = allow_origin
        .as_deref()
        .and_then(|o| HeaderValue::try_from(o).ok())
    {
        response
            .headers_mut()
            .insert(ACCESS_CONTROL_ALLOW_ORIGIN, value);
    }
    // オリジンごとに応答が変わることをキャッシュへ伝える（共有キャッシュの取り違え防止）。
    append_vary_origin(&mut response);
    response
}

fn preflight_response(
    allow_origin: Option<&str>,
    requested_headers: Option<HeaderValue>,
) -> Response {
    let Some(origin) = allow_origin.and_then(|o| HeaderValue::try_from(o).ok()) else {
        // 許可しないオリジンからのプリフライトは、CORS ヘッダ無しで返す（ブラウザが実リクエストを
        // 送らない）。理由は返さない —— 許可集合を外から列挙させない。
        let mut response = StatusCode::NO_CONTENT.into_response();
        append_vary_origin(&mut response);
        return response;
    };
    let mut response = StatusCode::NO_CONTENT.into_response();
    let headers = response.headers_mut();
    headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    headers.insert(
        ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static(ALLOWED_METHODS),
    );
    // 要求されたヘッダをそのまま許可する。`Allow-Credentials` を付けないため、ここで許すのは
    // 「呼び出し側が自分で載せる値」（`Authorization`・`Content-Type`）だけで、ブラウザが
    // 自動で載せる資格情報（Cookie）は対象外。
    if let Some(requested) = requested_headers {
        headers.insert(ACCESS_CONTROL_ALLOW_HEADERS, requested);
    }
    if let Ok(max_age) = HeaderValue::try_from(PREFLIGHT_MAX_AGE_SECS.to_string()) {
        headers.insert(ACCESS_CONTROL_MAX_AGE, max_age);
    }
    append_vary_origin(&mut response);
    response
}

fn append_vary_origin(response: &mut Response) {
    response
        .headers_mut()
        .append(VARY, HeaderValue::from_name(ORIGIN));
}

/// パスから CORS 上の扱いを決める。
///
/// テナントスコープのパスは `/{tenant_id}/...`（ADR-0009 §6）。`tenant_id` の存在確認までは
/// しない（未知テナントは許可集合が空になり、結果として CORS ヘッダが付かない）。
fn classify(path: &str) -> CorsScope {
    let mut segments = path.trim_start_matches('/').split('/');
    let Some(first) = segments.next() else {
        return CorsScope::None;
    };
    // テナント外の公開メタデータは無い（Discovery はテナントごと）。`/{tenant}` 以外は対象外。
    let Ok(tenant_id) = Uuid::parse_str(first) else {
        return CorsScope::None;
    };
    let rest: Vec<&str> = segments.collect();
    match rest.as_slice() {
        [".well-known", "openid-configuration"] | [".well-known", "jwks.json"] => {
            CorsScope::PublicMetadata
        }
        ["saml", "metadata"] => CorsScope::PublicMetadata,
        ["token"] | ["revoke"] | ["introspect"] | ["userinfo"] => {
            CorsScope::TenantScoped(tenant_id.into())
        }
        _ => CorsScope::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TENANT: &str = "00000000-0000-7000-8000-000000000001";

    #[test]
    fn public_metadata_is_open_to_everyone() {
        assert_eq!(
            classify(&format!("/{TENANT}/.well-known/openid-configuration")),
            CorsScope::PublicMetadata
        );
        assert_eq!(
            classify(&format!("/{TENANT}/.well-known/jwks.json")),
            CorsScope::PublicMetadata
        );
        assert_eq!(
            classify(&format!("/{TENANT}/saml/metadata")),
            CorsScope::PublicMetadata
        );
    }

    #[test]
    fn protocol_endpoints_are_checked_against_the_tenant_allowlist() {
        for path in ["token", "revoke", "introspect", "userinfo"] {
            assert!(
                matches!(
                    classify(&format!("/{TENANT}/{path}")),
                    CorsScope::TenantScoped(_)
                ),
                "{path} must be tenant scoped"
            );
        }
    }

    /// 管理 API・内部 API・ブラウザのリダイレクト経路には CORS を開けない。管理 API は SSO Cookie を
    /// 持つ web からしか呼ばれず、`/internal/*` はそもそも外部公開しない。
    #[test]
    fn everything_else_stays_closed() {
        assert_eq!(
            classify(&format!("/{TENANT}/admin/clients")),
            CorsScope::None
        );
        assert_eq!(classify(&format!("/{TENANT}/authorize")), CorsScope::None);
        assert_eq!(classify("/internal/authenticate"), CorsScope::None);
        assert_eq!(classify("/healthz"), CorsScope::None);
        assert_eq!(classify("/api/openapi.json"), CorsScope::None);
    }

    /// テナント部が UUID でなければテナントスコープとして扱わない（`/api/docs` 等の誤爆防止）。
    #[test]
    fn a_non_uuid_first_segment_is_not_a_tenant() {
        assert_eq!(classify("/not-a-uuid/token"), CorsScope::None);
    }

    /// `Vary: Origin` は上書きではなく追記する（他のミドルウェアが付けた値を消さない）。
    #[test]
    fn vary_origin_is_appended() {
        let mut response = StatusCode::OK.into_response();
        response
            .headers_mut()
            .insert(VARY, HeaderValue::from_static("accept-language"));
        append_vary_origin(&mut response);
        let values: Vec<&str> = response
            .headers()
            .get_all(VARY)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        assert_eq!(values, vec!["accept-language", "origin"]);
    }
}
