//! HTTP エラーページ（403 / 404 / 500）の描画。
//!
//! 未マッチ経路の fallback（404）と、各ハンドラから共通利用するエラーページ描画ヘルパを提供する。
//! テナント文脈を持たない経路でも描画できるよう `Accept-Language`（＋`lang` Cookie）から表示言語を
//! 決めるだけで、テナント ID には依存しない。

use crate::handlers::locale;
use crate::i18n::Messages;
use crate::templates::{render, ErrorPage};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};

/// ステータスコードに対応する翻訳キー（title / message）を引く。未対応コードは 404 の文言を既定にする。
fn message_keys(status: StatusCode) -> (&'static str, &'static str) {
    match status {
        StatusCode::FORBIDDEN => ("error-403-title", "error-403-message"),
        StatusCode::INTERNAL_SERVER_ERROR => ("error-500-title", "error-500-message"),
        _ => ("error-404-title", "error-404-message"),
    }
}

/// 指定ステータスのエラーページ応答を組み立てる（リクエストヘッダから表示言語を決定する）。
pub(crate) fn page(status: StatusCode, headers: &HeaderMap) -> Response {
    let messages = Messages::new(locale(headers));
    let (title_key, message_key) = message_keys(status);
    let html = Html(render(&ErrorPage {
        code: status.as_u16().to_string(),
        title: messages.get(title_key),
        message: messages.get(message_key),
    }));
    (status, html).into_response()
}

/// どのルートにも一致しなかったリクエストへ返す 404 ページ（axum の `Router::fallback`）。
pub(crate) async fn fallback(headers: HeaderMap) -> Response {
    page(StatusCode::NOT_FOUND, &headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_known_status_codes_to_dedicated_keys() {
        assert_eq!(
            message_keys(StatusCode::FORBIDDEN),
            ("error-403-title", "error-403-message")
        );
        assert_eq!(
            message_keys(StatusCode::NOT_FOUND),
            ("error-404-title", "error-404-message")
        );
        assert_eq!(
            message_keys(StatusCode::INTERNAL_SERVER_ERROR),
            ("error-500-title", "error-500-message")
        );
        // 未対応コードは 404 の文言へフォールバックする。
        assert_eq!(
            message_keys(StatusCode::BAD_GATEWAY),
            ("error-404-title", "error-404-message")
        );
    }
}
