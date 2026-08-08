//! 接続元 IP の決定（SEC1）。
//!
//! ADR-0018 以降、ログインの入口は web である。web が組み立てた IP は `/internal/authenticate*` の
//! ボディで api へ渡り、**api のログインレートリミッタと監査ログの IP になる**。したがって
//! `X-Forwarded-For` を web が無条件に信じると、api 側の `TRUST_FORWARDED_HEADERS` ゲート
//! （`crates/api/src/presentation/handlers/mod.rs` の `request_context`）がログイン経路で迂回される:
//!
//! - ヘッダを毎回変える → IP 単位のレート制限（既定 30 回 / 5 分）を素通りできる。
//! - ヘッダを送らない → IP が `None` になり、レート制限の判定自体が行われない。
//! - 任意の値を送る → 監査ログの `ip_address` を汚染できる。
//!
//! そこで api と**同じ設定キー・同じ既定値**（`TRUST_FORWARDED_HEADERS`、既定 `false`）でゲートし、
//! 非信頼時は TCP 接続元アドレス（[`axum::extract::ConnectInfo`]）へフォールバックする。
//! api には `ConnectInfo` 相当が無い（web からのサーバ間呼び出しなので接続元は常に web）ため、
//! フォールバック先を持つのは web だけである。
//!
//! 決定は middleware 1 箇所で行い、結果を `Extension` でハンドラへ渡す。ハンドラごとにヘッダを
//! 読むと、画面が増えたときにゲートの掛け忘れが混ざる。

use axum::extract::{ConnectInfo, Request};
use axum::middleware::Next;
use axum::response::Response;
use std::net::SocketAddr;

/// このリクエストの接続元 IP。ハンドラは `Extension<ClientIp>` で受け取る。
///
/// `None` = 特定できなかった（非信頼構成で `ConnectInfo` も無い場合。テストでルータを直接叩くと
/// こうなる）。監査ログの IP が空になり、IP 単位のレート制限は適用されない。
#[derive(Debug, Clone, Default)]
pub struct ClientIp(pub Option<String>);

/// 接続元 IP を決めて `Extension` へ載せる middleware。
///
/// `trust_forwarded` が `true` のときだけ `X-Forwarded-For` の先頭値を採り、空・非 ASCII なら
/// `ConnectInfo` へ落とす。`false` のときはヘッダを一切見ない。
pub async fn resolve_client_ip(
    trust_forwarded: bool,
    mut request: Request,
    next: Next,
) -> Response {
    let forwarded = trust_forwarded
        .then(|| {
            request
                .headers()
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(',').next())
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        })
        .flatten();
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip().to_string());
    request
        .extensions_mut()
        .insert(ClientIp(forwarded.or(peer)));
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode};
    use axum::routing::get;
    use axum::{Extension, Router};
    use tower::ServiceExt as _;

    async fn echo_ip(Extension(ip): Extension<ClientIp>) -> String {
        ip.0.unwrap_or_else(|| "none".to_string())
    }

    /// `ConnectInfo` を差し込んだうえでルータへ 1 回投げ、決定された IP を返す。
    async fn resolved_ip(trust_forwarded: bool, forwarded_for: Option<&str>) -> String {
        let app = Router::new()
            .route("/", get(echo_ip))
            .layer(axum::middleware::from_fn(move |req, next| {
                resolve_client_ip(trust_forwarded, req, next)
            }));
        let mut builder = HttpRequest::builder().uri("/");
        if let Some(v) = forwarded_for {
            builder = builder.header("x-forwarded-for", v);
        }
        let mut request = builder.body(Body::empty()).unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 7], 40000))));
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 64)
            .await
            .unwrap();
        String::from_utf8(body.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn ignores_the_forwarded_header_when_it_is_not_trusted() {
        // 既定構成。攻撃者が偽装しても採用されず、接続元アドレスが使われる。
        assert_eq!(
            resolved_ip(false, Some("198.51.100.9")).await,
            "203.0.113.7"
        );
        assert_eq!(resolved_ip(false, None).await, "203.0.113.7");
    }

    #[tokio::test]
    async fn takes_the_first_forwarded_value_when_trusted() {
        assert_eq!(
            resolved_ip(true, Some("198.51.100.9, 203.0.113.7")).await,
            "198.51.100.9"
        );
    }

    #[tokio::test]
    async fn falls_back_to_the_peer_address_when_the_trusted_header_is_missing() {
        // プロキシ配下でもヘッダを送らない経路（内部ヘルスチェック等）はある。
        assert_eq!(resolved_ip(true, None).await, "203.0.113.7");
        assert_eq!(resolved_ip(true, Some("   ")).await, "203.0.113.7");
    }
}
