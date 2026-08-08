//! HTTP アクセススパンの組み立て（api ↔ web 共有。SEC9）。
//!
//! `TraceLayer::new_for_http()` の既定スパンは `uri` を**クエリ文字列込み**で記録する。本 IdP の
//! URL には `?auth_session=`（web ハンドオフの単回ハンドル）・`?code_challenge=`・`?code=` といった
//! 資格情報に準じる値が載るため、既定のままだと `RUST_LOG=debug` で秘密が stdout・`log` テーブルへ
//! 落ちる（ADR-0018 の受け入れ条件）。
//!
//! そこで両サービスとも `make_span_with(idp_contracts::http_trace::request_span)` を使い、記録するのは
//! **パスのみ**にする。api と web で別々に組み立てると片方だけ既定へ戻る事故が起きるため、
//! cookie 名・CSRF 導出と同じく本 crate に単一定義する。
//!
//! 注: パス自体にも `/{tenant_id}/...` のような識別子は載るが、これは秘密ではない（テナント UUID は
//! ブラウザのアドレスバーに出る公開値）。

use tracing::Span;

/// アクセスログ用のスパン。`uri` は**クエリ文字列を落として**パスだけを載せる。
///
/// スパン名・フィールド名は `TraceLayer` の既定（`http_request` / `method` / `uri` / `version`）に
/// 揃えてあるため、既存のログ検索・ダッシュボードはそのまま使える。
pub fn request_span<B>(request: &http::Request<B>) -> Span {
    tracing::info_span!(
        "http_request",
        method = %request.method(),
        uri = %request.uri().path(),
        version = ?request.version(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn span_records_the_path_without_the_query_string() {
        let request = http::Request::builder()
            .uri("https://idp.example.com/6f0b/login?auth_session=secret-handle&lang=ja")
            .body(())
            .unwrap();
        let span = request_span(&request);
        // `tracing` のフィールド値は外から読めないため、スパンへ渡す元の値で確認する
        //（`request_span` はこの値をそのまま `uri` に載せる）。
        assert_eq!(request.uri().path(), "/6f0b/login");
        assert!(!request.uri().path().contains("secret-handle"));
        assert_eq!(span.metadata().map(|m| m.name()), Some("http_request"));
    }
}
