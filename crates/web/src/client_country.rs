//! 今の要求の「信じてよい国」を、その要求の間だけ持つ（task #895）。
//!
//! 国（`CF-IPCountry`）は `TRUST_FORWARDED_HEADERS` が有効なときだけ信じる（[`crate::device_observation`]
//! と同じ判定）。middleware が要求の間だけここへ置き、api クライアントが内部の呼び出しへ
//! [`assay_contracts::auth::CLIENT_COUNTRY_HEADER`] として添える。api は断ったログインの履歴に国を書く。
//!
//! ハンドラの引数で渡さないのは、ログインの経路（パスワード・確認コード・パスキー・外部 IdP・管理
//! コンソール・パスワード変更）がどれも api を呼ぶだけで、国を必要とするのは api 側の履歴だけだから。
//! 経路ごとに DTO へ欄を足すと、足し忘れた経路だけ国が抜ける。

use crate::device_observation::trusted_country;
use crate::state::WebState;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;

tokio::task_local! {
    static CLIENT_COUNTRY: Option<String>;
}

/// 今の要求の信じてよい国（middleware の外・要求の外では `None`）。
pub fn current() -> Option<String> {
    CLIENT_COUNTRY.try_with(Clone::clone).ok().flatten()
}

/// 要求の間だけ国を置く middleware。
pub async fn scope_client_country(
    State(state): State<WebState>,
    request: Request,
    next: Next,
) -> Response {
    // 見出しに載せるので、国コードの形（英数字 2 文字）以外は置かない（壊れた見出しで api 呼び出しを落とさない）。
    let country = trusted_country(request.headers(), state.config.trust_forwarded_headers())
        .filter(|c| c.len() == 2 && c.bytes().all(|b| b.is_ascii_alphanumeric()));
    CLIENT_COUNTRY.scope(country, next.run(request)).await
}

/// 試験用: 国を置いた状態で `f` を走らせる。
#[cfg(test)]
pub async fn with_country<F: std::future::Future>(country: Option<String>, f: F) -> F::Output {
    CLIENT_COUNTRY.scope(country, f).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_country_is_only_visible_inside_the_request() {
        assert_eq!(current(), None);
        let inside = with_country(Some("JP".to_string()), async { current() }).await;
        assert_eq!(inside.as_deref(), Some("JP"));
        assert_eq!(current(), None);
    }
}
