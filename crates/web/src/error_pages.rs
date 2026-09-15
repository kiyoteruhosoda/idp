//! HTTP エラーページ（全ステータスコード対応）の描画と、エラー応答の本文を補完するミドルウェア。
//!
//! **エラー応答の HTML 化はこのミドルウェアに集約する。** 個々のハンドラが
//! `StatusCode::X.into_response()` のように本文なしで返した応答も、axum の extractor 拒否
//! （`Form` のデシリアライズ失敗など）や未マッチ経路の 404・メソッド不一致の 405 も、すべて
//! ここで共通のエラーページへ差し替える。ハンドラ側を 1 箇所ずつ書き換える方式は、新しい
//! エラー経路が増えたときに漏れるため採らない。
//!
//! 差し替える条件は「本文が空」または「本文が `text/plain`（axum 既定の拒否メッセージ）」のときだけ。
//! ハンドラが文脈に応じた HTML（例: 管理コンソールの権限不足バナー・戻るリンク付き告知）を
//! 描画済みならそれを尊重して素通しする。`text/plain` を差し替え対象に含めるのは、
//! 「Failed to deserialize form body: ...」のような内部詳細をブラウザへ露出させないためでもある。
//!
//! 文言は `error-<code>-title` / `error-<code>-message` を引き、専用文言を持たないコードは
//! クラス既定（`error-4xx-*` / `error-5xx-*`）へフォールバックする。これにより標準外のコードでも
//! 翻訳キーがそのまま画面に出ることがない。

use crate::i18n::{Locale, Messages};
use crate::templates::{render, ErrorPage};
use axum::body::Body;
use axum::extract::Request;
use axum::http::header::{HeaderValue, CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::Uri;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Response};

/// 専用の文言（`error-<code>-title` / `-message`）を用意しているステータスコード。
/// IANA 登録済みの 4xx / 5xx を網羅する（418 I'm a teapot はジョークコードのため除く）。
/// ここに無いコードはクラス既定（`error-4xx-*` / `error-5xx-*`）へフォールバックする。
const DEDICATED_STATUS_CODES: &[u16] = &[
    400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 421,
    422, 423, 424, 425, 426, 428, 429, 431, 451, 500, 501, 502, 503, 504, 505, 506, 507, 508, 510,
    511,
];

/// エラー応答の本文を差し替え判定のためにバッファする上限。エラー応答は小さいため十分な余裕がある。
/// 上限を超える本文はハンドラが意図して描画したものとみなし、そのまま返す。
const MAX_BUFFERED_ERROR_BODY: usize = 64 * 1024;

/// ステータスコードに対応する翻訳キー（title / message）を返す。
fn message_keys(status: StatusCode) -> (String, String) {
    let code = status.as_u16();
    if DEDICATED_STATUS_CODES.contains(&code) {
        return (
            format!("error-{code}-title"),
            format!("error-{code}-message"),
        );
    }
    let class = if status.is_server_error() {
        "5xx"
    } else {
        "4xx"
    };
    (
        format!("error-{class}-title"),
        format!("error-{class}-message"),
    )
}

/// エラー画面から戻れる先。
///
/// **エラー画面には出口を置く。** 置かないと、リンクを踏んだ先で失敗した利用者は
/// ブラウザの戻る以外に手が無くなる（左上の名乗りもリンクではない）。
struct BackLink {
    href: String,
    label_key: &'static str,
}

/// 要求されたパスから戻り先を決める。
///
/// テナント接頭辞（UUID）が取れたときだけ出す。管理コンソール配下はコンソールのホームへ、
/// それ以外はアカウント設定へ戻す。**今いる場所と同じなら出さない** —— 同じ場所へ戻しても
/// また同じエラーになるだけで、出口には見えて実際は行き止まりになる。
fn back_link(path: &str) -> Option<BackLink> {
    let mut segments = path.split('/').skip(1);
    let tenant = segments.next()?;
    if uuid::Uuid::parse_str(tenant).is_err() {
        return None;
    }
    let (suffix, label_key) = match segments.next() {
        Some("admin") => ("/admin", "error-back-to-console"),
        _ => ("/settings", "error-back-to-settings"),
    };
    let href = format!("/{tenant}{suffix}");
    (href.trim_end_matches('/') != path.trim_end_matches('/'))
        .then_some(BackLink { href, label_key })
}

/// エラーページの HTML を描画する。
fn render_page(status: StatusCode, locale: Locale, back: Option<BackLink>) -> String {
    let messages = Messages::new(locale);
    let (title_key, message_key) = message_keys(status);
    let (back_href, back_label) = match back {
        Some(link) => (link.href, messages.get(link.label_key)),
        None => (String::new(), String::new()),
    };
    render(&ErrorPage {
        code: status.as_u16().to_string(),
        title: messages.get(&title_key),
        message: messages.get(&message_key),
        back_href,
        back_label,
    })
}

/// ハンドラから直接エラーページを返すための応答組み立て（表示言語はリクエストヘッダから決める）。
///
/// 戻り先は呼び出し側が渡す。パスから機械的に導かない —— 「そのテナントが存在しない」ような
/// 404 では、導いた戻り先も同じ理由で開けない。
pub(crate) fn page(status: StatusCode, headers: &HeaderMap, back: Option<&str>) -> Response {
    let back = back.map(|href| BackLink {
        href: href.to_string(),
        label_key: "error-back-to-settings",
    });
    let html = render_page(status, crate::handlers::locale(headers), back);
    (status, Html(html)).into_response()
}

/// どのルートにも一致しなかったリクエストへ返す 404 ページ（`Router::fallback`）。
pub(crate) async fn fallback(uri: Uri, headers: HeaderMap) -> Response {
    let html = render_page(
        StatusCode::NOT_FOUND,
        crate::handlers::locale(&headers),
        back_link(uri.path()),
    );
    (StatusCode::NOT_FOUND, Html(html)).into_response()
}

/// エラー応答（4xx / 5xx）の本文が空・またはプレーンテキストのとき、共通のエラーページへ差し替える。
pub async fn render_error_pages(request: Request, next: Next) -> Response {
    // JSON を送ってくるブラウザ JS 経路（passkey の登録・認証 API）は HTML を返さず素通しする。
    // これらは JS 側で `response.ok` を見てエラー表示するため、本文の補完は不要。
    let is_json_request = request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/json"));
    // HEAD には本文を付けられない。
    let is_head = request.method() == Method::HEAD;
    // `next.run` で request を消費するため、表示言語と戻り先の判定材料は先に取り出しておく。
    let locale = crate::handlers::locale(request.headers());
    let back = back_link(request.uri().path());

    let response = next.run(request).await;

    let status = response.status();
    if is_json_request || is_head || !(status.is_client_error() || status.is_server_error()) {
        return response;
    }
    replace_placeholder_body(response, status, locale, back).await
}

/// 本文が「空」または `text/plain` のときだけエラーページへ差し替える。それ以外（ハンドラが描画した
/// HTML・JSON）は本文をそのまま復元して返す。応答ヘッダ（Set-Cookie 等）は保持する。
async fn replace_placeholder_body(
    response: Response,
    status: StatusCode,
    locale: Locale,
    back: Option<BackLink>,
) -> Response {
    let is_plain_text = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("text/plain"));

    let (mut parts, body) = response.into_parts();
    // 上限超過・読み取り失敗時は本文を復元できないため、エラーページを描画して返す（フェイルソフト）。
    let keep_body = match axum::body::to_bytes(body, MAX_BUFFERED_ERROR_BODY).await {
        Ok(bytes) if !bytes.is_empty() && !is_plain_text => Some(bytes),
        Ok(_) => None,
        Err(error) => {
            tracing::warn!(%error, %status, "failed to buffer error response body");
            None
        }
    };
    if let Some(bytes) = keep_body {
        return Response::from_parts(parts, Body::from(bytes));
    }

    parts.headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    // 本文長が変わるため、元の Content-Length は捨てて再計算させる。
    parts.headers.remove(CONTENT_LENGTH);
    Response::from_parts(parts, Body::from(render_page(status, locale, back)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::{get, post};
    use axum::Router;
    use tower::ServiceExt;

    fn app() -> Router {
        Router::new()
            .route("/ok", get(|| async { "fine" }))
            // 本文なしのエラー（既存ハンドラの `StatusCode::X.into_response()` 相当）。
            .route("/bare", get(|| async { StatusCode::BAD_GATEWAY }))
            // ハンドラが文脈つき HTML を描画したエラー。
            .route(
                "/rendered",
                get(|| async {
                    (
                        StatusCode::FORBIDDEN,
                        Html("<!DOCTYPE html><p>context specific</p>".to_string()),
                    )
                }),
            )
            // 標準外のステータスコード（クラス既定へフォールバックする）。
            .route(
                "/nonstandard",
                get(|| async { StatusCode::from_u16(499).expect("status") }),
            )
            // extractor 拒否（本文なし POST への `Form` 抽出）で text/plain が返る経路。
            .route(
                "/form",
                post(
                    |_: axum::extract::Form<std::collections::HashMap<String, String>>| async {
                        StatusCode::OK
                    },
                ),
            )
            .fallback(fallback)
            .layer(axum::middleware::from_fn(render_error_pages))
    }

    async fn request(method: &str, uri: &str, content_type: Option<&str>) -> (StatusCode, String) {
        let mut builder = axum::http::Request::builder().method(method).uri(uri);
        if let Some(content_type) = content_type {
            builder = builder.header(CONTENT_TYPE, content_type);
        }
        let response = app()
            .oneshot(builder.body(Body::empty()).expect("request"))
            .await
            .expect("response");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    #[test]
    fn dedicated_codes_use_their_own_keys_and_others_fall_back_by_class() {
        assert_eq!(
            message_keys(StatusCode::FORBIDDEN),
            (
                "error-403-title".to_string(),
                "error-403-message".to_string()
            )
        );
        assert_eq!(
            message_keys(StatusCode::INTERNAL_SERVER_ERROR),
            (
                "error-500-title".to_string(),
                "error-500-message".to_string()
            )
        );
        // 専用文言を持たない 4xx / 5xx はクラス既定へ。
        assert_eq!(
            message_keys(StatusCode::from_u16(499).expect("status")),
            (
                "error-4xx-title".to_string(),
                "error-4xx-message".to_string()
            )
        );
        assert_eq!(
            message_keys(StatusCode::from_u16(599).expect("status")),
            (
                "error-5xx-title".to_string(),
                "error-5xx-message".to_string()
            )
        );
    }

    /// 専用文言を宣言したすべてのコードとクラス既定が、ja / en 両方で実際に翻訳されていること
    /// （`Messages::get` は未定義キーをキー名のまま返すため、キー名が返ったら翻訳漏れ）。
    #[test]
    fn every_declared_status_code_has_translations_in_both_locales() {
        for locale in [Locale::Ja, Locale::En] {
            let messages = Messages::new(locale);
            let codes = DEDICATED_STATUS_CODES
                .iter()
                .map(|code| code.to_string())
                .chain(["4xx".to_string(), "5xx".to_string()]);
            for code in codes {
                for key in [
                    format!("error-{code}-title"),
                    format!("error-{code}-message"),
                ] {
                    assert_ne!(
                        messages.get(&key),
                        key,
                        "missing translation for {key} ({})",
                        locale.as_tag()
                    );
                }
            }
        }
    }

    /// 本文なしのエラー応答は共通エラーページへ差し替える。
    #[tokio::test]
    async fn fills_empty_error_bodies_with_the_common_page() {
        let (status, body) = request("GET", "/bare", None).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(body.contains("502"), "must show the status code: {body}");
        assert!(body.contains("<!DOCTYPE html>"));
    }

    /// ハンドラが描画した文脈つき HTML は上書きしない。
    #[tokio::test]
    async fn keeps_handler_rendered_error_pages() {
        let (status, body) = request("GET", "/rendered", None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(body.contains("context specific"));
    }

    /// extractor 拒否のプレーンテキスト（内部詳細）はエラーページへ差し替えて露出させない。
    #[tokio::test]
    async fn replaces_extractor_rejection_text_with_the_common_page() {
        let (status, body) = request("POST", "/form", None).await;
        assert!(status.is_client_error(), "unexpected status {status}");
        assert!(
            !body.contains("Failed to deserialize"),
            "internal rejection message must not leak: {body}"
        );
        assert!(body.contains("<!DOCTYPE html>"));
    }

    /// 未マッチ経路（404）・メソッド不一致（405）もエラーページになる。
    #[tokio::test]
    async fn covers_unmatched_routes_and_method_mismatch() {
        let (status, body) = request("GET", "/no/such/path", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains("404"));

        let (status, body) = request("POST", "/ok", None).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert!(body.contains("405"), "must show the status code: {body}");
    }

    /// 標準外のコードでも翻訳キーを画面に出さず、クラス既定の文言を表示する。
    #[tokio::test]
    async fn nonstandard_status_codes_use_class_defaults() {
        let (status, body) = request("GET", "/nonstandard", None).await;
        assert_eq!(status.as_u16(), 499);
        assert!(body.contains("499"));
        assert!(
            !body.contains("error-4xx-title"),
            "translation key must not leak into the page: {body}"
        );
    }

    /// JSON リクエスト（passkey の JS 経路）へは HTML を返さない。
    #[tokio::test]
    async fn leaves_json_requests_untouched() {
        let (status, body) = request("GET", "/bare", Some("application/json")).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(
            body.is_empty(),
            "JSON callers must not receive HTML: {body}"
        );
    }

    /// HEAD には本文を付けない。
    #[tokio::test]
    async fn does_not_add_a_body_to_head_responses() {
        let (_, body) = request("HEAD", "/bare", None).await;
        assert!(body.is_empty(), "HEAD must not carry a body: {body}");
    }

    /// 正常応答（2xx）は素通しする。
    #[tokio::test]
    async fn leaves_successful_responses_untouched() {
        let (status, body) = request("GET", "/ok", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "fine");
    }

    /// テナントが分かるときは戻り先を出す。分からないときは出さない（行き先が無い）。
    #[test]
    fn the_way_out_is_offered_only_when_the_tenant_is_known() {
        let t = "01a00dfe-bffb-7f23-88b5-8bbef50d23f0";
        let link = back_link(&format!("/{t}/account/mfa/totp/setup")).expect("link");
        assert_eq!(link.href, format!("/{t}/settings"));
        assert_eq!(link.label_key, "error-back-to-settings");

        let link = back_link(&format!("/{t}/admin/clients/new")).expect("link");
        assert_eq!(link.href, format!("/{t}/admin"));
        assert_eq!(link.label_key, "error-back-to-console");

        // テナント接頭辞が無い経路（資産・ルート）には戻り先が無い。
        assert!(back_link("/assets/app.css").is_none());
        assert!(back_link("/").is_none());
        assert!(back_link("/healthz").is_none());
    }

    /// **今いる場所へは戻さない。** 設定画面自身が失敗したときに同じ URL を出すと、
    /// 押してもまた同じエラーになるだけで、出口に見えて行き止まりになる。
    #[test]
    fn it_does_not_offer_a_link_back_to_the_failing_page_itself() {
        let t = "01a00dfe-bffb-7f23-88b5-8bbef50d23f0";
        assert!(back_link(&format!("/{t}/settings")).is_none());
        assert!(back_link(&format!("/{t}/settings/")).is_none());
        assert!(back_link(&format!("/{t}/admin")).is_none());
    }

    /// 本文の無い 500 を差し替えたページに、戻り先のリンクが載ること。
    #[tokio::test]
    async fn a_replaced_error_page_carries_the_way_out() {
        let t = "01a00dfe-bffb-7f23-88b5-8bbef50d23f0";
        let app = Router::new().route(
            &format!("/{t}/account/mfa/totp/setup"),
            get(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
        );
        let app = app.layer(axum::middleware::from_fn(render_error_pages));
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/{t}/account/mfa/totp/setup"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = String::from_utf8_lossy(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .into_owned();
        assert!(
            body.contains(&format!(r#"href="/{t}/settings""#)),
            "戻り先のリンクが無い: {body}"
        );
    }
}
