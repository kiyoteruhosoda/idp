//! トークン系エンドポイント（`/token`・`/introspect`・`/revoke`）の負荷ゲート（SEC10）。
//!
//! この 3 つは RFC 6749 §2.3.1 のクライアント認証を使い、confidential クライアントの
//! `client_secret` を **Argon2id（19 MiB・2 反復）で照合する**。総当たりは非現実的だが、
//! メモリハード関数はそれ自体が増幅器になる: 攻撃者は数百バイトのリクエストで、
//! サーバ側に 19 MiB のメモリ確保と数十ミリ秒の CPU を強制できる。しかも照合は同期関数で
//! tokio のワーカースレッド上を走るため、バーストは**トークン発行だけでなく全エンドポイントの
//! 応答を止める**。
//!
//! # 二段のゲート
//!
//! 1. **同時実行数の上限**（`TOKEN_ENDPOINT_MAX_CONCURRENCY`）。ピーク時のメモリを
//!    「上限 × 19 MiB」に、CPU を「上限個のワーカー」に抑える。**接続元が分からなくても効く**のが
//!    重要で、`TRUST_FORWARDED_HEADERS` が既定の `false` のとき（api が接続元 IP を知らない構成）
//!    でも成立する唯一の防御線がこれである。溢れた要求は待たせずに落とす。待たせると
//!    CPU の飽和が「待ち行列のメモリ」に化けるだけで、状況は悪くなる。
//! 2. **接続元 IP 単位のレート制限**（`TOKEN_ENDPOINT_RATE_LIMIT_*`）。単一の送信元が上限枠を
//!    占有し、正規の RP を締め出すのを防ぐ。IP が分かるとき（`TRUST_FORWARDED_HEADERS = true`）
//!    のみ効く。
//!
//! # 応答
//!
//! RFC 6749 §5.2 のトークンエンドポイントのエラーコードには「混雑」に当たる値が無い。
//! §4.1.2.1 の `temporarily_unavailable`（一時的な過負荷を表す唯一のコード）を用い、
//! HTTP ステータスは実態に合わせる（枠切れ = 503、送信元単位の超過 = 429）。
//! `Retry-After` を添えてクライアントに再試行の間隔を伝える。

use crate::domain::clock::Clock;
use crate::domain::rate_limit::LoginRateLimiter;
use crate::infrastructure::rate_limit::InMemoryLoginRateLimiter;
use crate::presentation::state::AppState;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// 枠切れ・レート超過時に伝える再試行間隔（秒）。ウィンドウ全体を待たせる必要はなく、
/// 「すぐに叩き直さない」ことが伝わればよい。
const RETRY_AFTER_SECS: u32 = 5;

/// ゲートの判定結果。
pub enum Admission {
    /// 通してよい。`_permit` は応答を返し終えるまで保持する（drop で枠が空く）。
    Admitted(Option<OwnedSemaphorePermit>),
    /// 送信元単位のレート制限を超えた。
    RateLimited,
    /// 同時実行の枠が空いていない。
    AtCapacity,
}

/// トークン系エンドポイントの負荷ゲート（SEC10）。
///
/// axum から切り離してあるのは、判定（どの条件でどちらの理由で落とすか）を DB もルータも無しに
/// 検証できるようにするため。ミドルウェアは HTTP への写像だけを担う。
pub struct TokenEndpointLoadGate {
    /// 同時実行の枠。`None` は無制限（`TOKEN_ENDPOINT_MAX_CONCURRENCY = 0`）。
    slots: Option<Arc<Semaphore>>,
    /// 接続元 IP 単位のレート制限。`None` は無効（`..._MAX_REQUESTS = 0`）。
    ///
    /// 実体はログインと同じスライディングウィンドウ実装だが、**制限器は共有しない**
    /// （RP のトークン取得がログイン試行の枠を食い合わないようにする）。
    rate_limiter: Option<Arc<dyn LoginRateLimiter>>,
    clock: Arc<dyn Clock>,
}

impl TokenEndpointLoadGate {
    /// 設定から組み立てる。どちらの上限も `0` なら素通しのゲートになる。
    pub fn from_config(config: &crate::config::Config, clock: Arc<dyn Clock>) -> Self {
        Self {
            slots: config
                .token_endpoint_max_concurrency()
                .map(|permits| Arc::new(Semaphore::new(permits))),
            rate_limiter: config.token_endpoint_rate_limit().map(|(max, window)| {
                Arc::new(InMemoryLoginRateLimiter::new(
                    max,
                    chrono::Duration::from_std(window)
                        .unwrap_or_else(|_| chrono::Duration::seconds(60)),
                )) as Arc<dyn LoginRateLimiter>
            }),
            clock,
        }
    }

    /// テスト用に上限を直接指定して組み立てる。
    pub fn new(
        max_concurrency: Option<usize>,
        rate_limit: Option<(usize, Duration)>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            slots: max_concurrency.map(|permits| Arc::new(Semaphore::new(permits))),
            rate_limiter: rate_limit.map(|(max, window)| {
                Arc::new(InMemoryLoginRateLimiter::new(
                    max,
                    chrono::Duration::from_std(window)
                        .unwrap_or_else(|_| chrono::Duration::seconds(60)),
                )) as Arc<dyn LoginRateLimiter>
            }),
            clock,
        }
    }

    /// 1 リクエストを通してよいか判定する。`client_ip` が `None`（接続元が分からない構成）でも
    /// 同時実行の上限は効く。
    pub fn admit(&self, client_ip: Option<&str>) -> Admission {
        // 送信元単位のレート制限を先に見る。枠（permit）を取ってから弾くと、弾かれる要求が
        // 一瞬でも枠を占有し、攻撃者が枠を空にできてしまう。
        if let (Some(limiter), Some(ip)) = (&self.rate_limiter, client_ip) {
            if !limiter.check_and_record(ip, self.clock.now()) {
                return Admission::RateLimited;
            }
        }
        match &self.slots {
            // 待たずに落とす（待ち行列は CPU の飽和をメモリの飽和に変えるだけで解決にならない）。
            Some(slots) => match slots.clone().try_acquire_owned() {
                Ok(permit) => Admission::Admitted(Some(permit)),
                Err(_) => Admission::AtCapacity,
            },
            None => Admission::Admitted(None),
        }
    }
}

/// トークン系エンドポイントの負荷ゲート。ルータ側で該当ルートにのみ `route_layer` する。
pub async fn limit_token_endpoint_load(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    let ip = client_ip(&headers, state.config.trust_forwarded_headers());
    // permit は応答を返し終えるまで保持する（`_permit` を早く drop しない）。
    let _permit = match state.token_endpoint_load.admit(ip.as_deref()) {
        Admission::Admitted(permit) => permit,
        Admission::RateLimited => {
            tracing::warn!(
                target: "security",
                "token endpoint rate limit exceeded for a single source"
            );
            return too_many_requests();
        }
        Admission::AtCapacity => {
            tracing::warn!(
                target: "security",
                "token endpoint concurrency limit reached; shedding the request"
            );
            return service_overloaded();
        }
    };

    next.run(request).await
}

/// 接続元 IP。`request_context` と同じ導出（最右の `X-Forwarded-For`。SEC1）を使う。
/// 信頼していないときは `None`（＝ IP 単位の制限は行わない）。
fn client_ip(headers: &HeaderMap, trust_forwarded: bool) -> Option<String> {
    if !trust_forwarded {
        return None;
    }
    idp_contracts::forwarded::client_ip(
        headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok()),
    )
}

fn too_many_requests() -> Response {
    oauth_error(
        StatusCode::TOO_MANY_REQUESTS,
        "too many token endpoint requests from this client; retry later",
    )
}

fn service_overloaded() -> Response {
    oauth_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "the token endpoint is at capacity; retry later",
    )
}

/// 文言は**翻訳しない**（`CLAUDE.md`「翻訳の対象外」: OAuth/OIDC のプロトコルエラーは RP 向けの
/// 固定値であり、RP のログ・自動処理が文言に依存し得る）。
fn oauth_error(status: StatusCode, description: &'static str) -> Response {
    (
        status,
        [
            (header::RETRY_AFTER, RETRY_AFTER_SECS.to_string()),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        axum::Json(json!({
            "error": "temporarily_unavailable",
            "error_description": description,
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, TimeZone, Utc};

    struct FixedClock;
    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            Utc.with_ymd_and_hms(2026, 8, 10, 0, 0, 0).unwrap()
        }
    }

    fn gate(
        max_concurrency: Option<usize>,
        rate_limit: Option<(usize, Duration)>,
    ) -> TokenEndpointLoadGate {
        TokenEndpointLoadGate::new(max_concurrency, rate_limit, Arc::new(FixedClock))
    }

    fn admitted(a: &Admission) -> bool {
        matches!(a, Admission::Admitted(_))
    }

    /// 同時実行の上限は**接続元が分からなくても**効く。`TRUST_FORWARDED_HEADERS` が既定の
    /// `false` のとき、Argon2 のメモリ増幅に対する防御線はこれだけになる。
    #[test]
    fn concurrency_is_capped_even_when_the_source_is_unknown() {
        let gate = gate(Some(2), None);
        let first = gate.admit(None);
        let second = gate.admit(None);
        assert!(admitted(&first));
        assert!(admitted(&second));
        assert!(matches!(gate.admit(None), Admission::AtCapacity));

        // permit を離すと枠が空く。
        drop(first);
        assert!(admitted(&gate.admit(None)));
    }

    /// 送信元単位の超過は、枠を取る**前に**判定する。枠を取ってから弾くと、弾かれる要求が
    /// 一瞬でも枠を占有し、攻撃者が同時実行枠を空にできてしまう。
    #[test]
    fn a_rate_limited_source_never_consumes_a_concurrency_slot() {
        let gate = gate(Some(1), Some((1, Duration::from_secs(60))));
        let held = gate.admit(Some("203.0.113.9"));
        assert!(admitted(&held));
        // 同じ送信元の 2 回目はレート制限で落ちる（枠切れではない）。
        assert!(matches!(
            gate.admit(Some("203.0.113.9")),
            Admission::RateLimited
        ));
        // 別の送信元から見ると、枠は 1 つ（held）だけが埋まっている。
        assert!(matches!(
            gate.admit(Some("198.51.100.4")),
            Admission::AtCapacity
        ));
        // 枠が空けば、まだ枠を使っていない送信元は通る。
        drop(held);
        assert!(admitted(&gate.admit(Some("192.0.2.30"))));
    }

    /// 枠切れで落とした要求も、送信元の回数には数える。数えないと、枠が埋まっている間は
    /// いくら叩いてもレート制限に触れず、攻撃者が枠の解放を待って叩き続けられる。
    #[test]
    fn a_request_shed_for_capacity_still_counts_against_its_source() {
        let gate = gate(Some(1), Some((2, Duration::from_secs(60))));
        let held = gate.admit(Some("203.0.113.9"));
        assert!(admitted(&held));
        // 同じ送信元の 2 回目: レート制限（上限 2）は通るが枠が無い。
        assert!(matches!(
            gate.admit(Some("203.0.113.9")),
            Admission::AtCapacity
        ));
        // 3 回目は枠の有無に関係なくレート制限で落ちる。
        drop(held);
        assert!(matches!(
            gate.admit(Some("203.0.113.9")),
            Admission::RateLimited
        ));
    }

    /// 送信元ごとに独立して数える（1 つの RP の集中が他の RP を巻き添えにしない）。
    #[test]
    fn rate_limits_are_counted_per_source() {
        let gate = gate(None, Some((1, Duration::from_secs(60))));
        assert!(admitted(&gate.admit(Some("203.0.113.1"))));
        assert!(matches!(
            gate.admit(Some("203.0.113.1")),
            Admission::RateLimited
        ));
        assert!(admitted(&gate.admit(Some("203.0.113.2"))));
    }

    /// 両方 `0`（無効）なら素通しする。既定値を外した運用でゲートが黙って全拒否にならないこと。
    #[test]
    fn both_limits_disabled_admits_everything() {
        let gate = gate(None, None);
        for _ in 0..1_000 {
            assert!(admitted(&gate.admit(Some("203.0.113.1"))));
        }
    }

    /// 信頼していないヘッダからは IP を採らない（SEC1）。採ると、送信元を名乗り分けるだけで
    /// レート制限を無限に回避できる。
    #[test]
    fn forwarded_headers_are_ignored_unless_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.7".parse().unwrap());
        assert_eq!(client_ip(&headers, false), None);
        assert_eq!(client_ip(&headers, true).as_deref(), Some("203.0.113.7"));
    }
}
