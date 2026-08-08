//! Back-channel logout の送信（OpenID Connect Back-Channel Logout 1.0。G5）。
//!
//! ログアウト処理は「誰へ何を送るか」を永続キューへ積むだけで終わり（[`enqueue`]）、実際の HTTP
//! 送信はバックグラウンドのワーカー（[`BackchannelLogoutDeliveryService::deliver_due`]）が行う。
//! 従来は `tokio::spawn` の撃ちっぱなしで、非 2xx は WARN を出すだけ・プロセス再起動で未送信分が
//! 消えていた（RP 側のログアウトが黙って落ち、ログアウトしたはずのセッションが RP に残る）。
//!
//! `logout_token` は送信の**直前**に署名する。署名済み JWT を DB に残すと、RP へ提示すれば
//! ログアウトが成立する値が長期間残り、再試行のたびに `iat` / `exp` も古いままになる。`jti` だけは
//! 行の作成時に確定させ、再試行でも変えない（RP は `jti` で重複配送を弾ける）。

use crate::domain::backchannel_logout::{
    retry_backoff, BackchannelLogoutDelivery, NewBackchannelLogoutDelivery,
};
use crate::domain::clock::Clock;
use crate::domain::error::Result;
use crate::domain::id_generator::IdGenerator;
use crate::domain::issuer::tenant_issuer;
use crate::domain::jwt;
use crate::domain::outbound_uri::is_internal_destination;
use crate::domain::repositories::BackchannelLogoutDeliveryRepository;
use crate::domain::tenant::TenantId;
use serde::Serialize;
use std::sync::Arc;
use uuid::Uuid;

/// `logout_token` の TTL（秒）。OIDC Back-Channel Logout 1.0 は短命であることを求める
/// （仕様上の固定値ではないが、配送遅延を吸収できる範囲で最小にする）。
const LOGOUT_TOKEN_TTL_SECS: i64 = 300;

/// back-channel logout token のクレーム（OpenID Back-Channel Logout 1.0 §2.4）。
///
/// `exp` は必須ではないが、付けないと RP 側は「いつまで有効な通知か」を判断できず、傍受された
/// トークンを無期限に再送されうる。`sid` はセッション単位のログアウトに必須（無いと RP は `sub`
/// 単位でしか失効できず、同一利用者の別デバイスのセッションまで巻き添えになる）。
#[derive(Debug, Serialize)]
pub struct LogoutTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    pub events: serde_json::Value,
}

impl LogoutTokenClaims {
    fn build(delivery: &BackchannelLogoutDelivery, issuer: String, now: i64) -> Self {
        Self {
            iss: issuer,
            sub: delivery.subject.clone(),
            aud: delivery.client_id.clone(),
            iat: now,
            exp: now + LOGOUT_TOKEN_TTL_SECS,
            jti: delivery.jti.to_string(),
            sid: delivery.sid.clone(),
            events: serde_json::json!({
                "http://schemas.openid.net/event/backchannel-logout": {}
            }),
        }
    }
}

/// 1 クライアントへの通知要求（Application 層が組み立てる入力）。
#[derive(Debug, Clone)]
pub struct LogoutNotification {
    pub client_id: String,
    pub backchannel_logout_uri: String,
}

/// 署名鍵の取得（`KeyService` への依存を Application 層内で閉じるための最小ポート）。
///
/// `KeyService` は具象（`Arc<KeyService>`）だが、本サービスが必要とするのは「今の署名鍵」だけ
/// なので、テストで差し替えられるようトレイトで受ける。
#[async_trait::async_trait]
pub trait LogoutTokenSigner: Send + Sync {
    /// クレームへ署名して `logout+jwt` を返す。
    async fn sign(&self, claims: &LogoutTokenClaims) -> anyhow::Result<String>;
}

/// `logout_token` を RP の `backchannel_logout_uri` へ POST する出口。
#[async_trait::async_trait]
pub trait BackchannelLogoutSender: Send + Sync {
    /// 送信結果を返す。`Ok(())` = 2xx。`Err` = 接続失敗・非 2xx（理由は運用言語＝英語で書く）。
    async fn post(&self, uri: &str, logout_token: &str) -> std::result::Result<(), String>;
}

pub struct BackchannelLogoutDeliveryService {
    deliveries: Arc<dyn BackchannelLogoutDeliveryRepository>,
    signer: Arc<dyn LogoutTokenSigner>,
    sender: Arc<dyn BackchannelLogoutSender>,
    ids: Arc<dyn IdGenerator>,
    clock: Arc<dyn Clock>,
    /// 基底 issuer。`logout_token` の `iss` はテナント毎に合成する（ADR-0009 §6）。
    base_issuer: String,
    /// 試行の打ち切り回数。これに達した行はもう送らない（打ち切りの記録は残す）。
    max_attempts: i32,
    /// 1 回のワーカー起動で扱う最大件数。
    batch_size: u32,
}

impl BackchannelLogoutDeliveryService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        deliveries: Arc<dyn BackchannelLogoutDeliveryRepository>,
        signer: Arc<dyn LogoutTokenSigner>,
        sender: Arc<dyn BackchannelLogoutSender>,
        ids: Arc<dyn IdGenerator>,
        clock: Arc<dyn Clock>,
        base_issuer: String,
        max_attempts: i32,
        batch_size: u32,
    ) -> Self {
        Self {
            deliveries,
            signer,
            sender,
            ids,
            clock,
            base_issuer,
            max_attempts,
            batch_size,
        }
    }

    /// ログアウト通知をキューへ積む（同期区間はここまで。HTTP 送信は行わない）。
    ///
    /// `sid` はセッション単位のログアウトのための識別子。ログアウト対象のセッションが特定できな
    /// かった場合のみ `None`（RP は `sub` 単位の失効に落とす）。
    pub async fn enqueue(
        &self,
        tenant_id: TenantId,
        subject: &str,
        sid: Option<&str>,
        notifications: &[LogoutNotification],
    ) -> Result<()> {
        if notifications.is_empty() {
            return Ok(());
        }
        let now = self.clock.now();
        let rows: Vec<BackchannelLogoutDelivery> = notifications
            .iter()
            .map(|n| {
                BackchannelLogoutDelivery::new(
                    NewBackchannelLogoutDelivery {
                        id: self.ids.new_id(),
                        jti: self.ids.new_id(),
                        tenant_id,
                        client_id: n.client_id.clone(),
                        target_uri: n.backchannel_logout_uri.clone(),
                        subject: subject.to_string(),
                        sid: sid.map(str::to_string),
                    },
                    now,
                )
            })
            .collect();
        self.deliveries.enqueue(&rows).await
    }

    /// 送信期限が来た要求を処理する（ワーカーが定期的に呼ぶ）。処理した件数を返す。
    pub async fn deliver_due(&self) -> Result<usize> {
        let now = self.clock.now();
        let due = self
            .deliveries
            .claim_due(now, self.max_attempts, self.batch_size)
            .await?;
        let mut handled = 0usize;
        for delivery in due {
            self.deliver_one(&delivery).await;
            handled += 1;
        }
        Ok(handled)
    }

    /// 決着済み（送信成功・試行打ち切り）の古い行を削除する。
    pub async fn purge_settled(&self, retention: chrono::Duration) -> Result<u64> {
        let cutoff = self.clock.now() - retention;
        self.deliveries
            .purge_settled(cutoff, self.max_attempts)
            .await
    }

    async fn deliver_one(&self, delivery: &BackchannelLogoutDelivery) {
        // 送信直前にも宛先を検査する（SEC2）。登録時の検証だけでは、検証導入より前に登録された行や
        // DB を直接編集された行が素通りしてしまう。宛先が不正な要求は再試行しても直らないので、
        // 打ち切り扱い（`max_attempts` まで進めて）にする。
        if is_internal_destination(&delivery.target_uri) {
            tracing::warn!(
                client_id = %delivery.client_id,
                "skipped back-channel logout: the registered URI points at an internal destination"
            );
            self.abandon(delivery, "target URI points at an internal destination")
                .await;
            return;
        }

        let issuer = tenant_issuer(&self.base_issuer, delivery.tenant_id);
        let claims = LogoutTokenClaims::build(delivery, issuer, self.clock.now().timestamp());
        let token = match self.signer.sign(&claims).await {
            Ok(t) => t,
            Err(e) => {
                // 署名できないのは鍵側の問題で、宛先を変えても直らないが一時的な可能性はある。
                // 再試行に載せる（バックオフは通常の失敗と同じ）。
                self.record_failure(delivery, &format!("failed to sign logout token: {e}"))
                    .await;
                return;
            }
        };

        match self.sender.post(&delivery.target_uri, &token).await {
            Ok(()) => {
                if let Err(e) = self
                    .deliveries
                    .mark_delivered(delivery.id, self.clock.now())
                    .await
                {
                    tracing::error!(error = %e, "failed to record back-channel logout delivery");
                }
            }
            Err(reason) => {
                if delivery.attempts >= self.max_attempts {
                    tracing::warn!(
                        client_id = %delivery.client_id,
                        attempts = delivery.attempts,
                        reason = %reason,
                        "giving up on back-channel logout delivery"
                    );
                }
                self.record_failure(delivery, &reason).await;
            }
        }
    }

    async fn record_failure(&self, delivery: &BackchannelLogoutDelivery, reason: &str) {
        let next = self.clock.now() + retry_backoff(delivery.attempts);
        if let Err(e) = self.deliveries.mark_failed(delivery.id, next, reason).await {
            tracing::error!(error = %e, "failed to record back-channel logout failure");
        }
    }

    /// 再試行しても直らない要求を打ち切る（次回時刻は動かさず、試行回数を上限まで進める）。
    async fn abandon(&self, delivery: &BackchannelLogoutDelivery, reason: &str) {
        // `claim_due` は `attempts < max_attempts` の行しか拾わないため、上限まで進めれば
        // 二度と選ばれない。理由は行に残して運用から追えるようにする。
        let far_future = self.clock.now() + chrono::Duration::days(3_650);
        if let Err(e) = self
            .deliveries
            .mark_failed(delivery.id, far_future, reason)
            .await
        {
            tracing::error!(error = %e, "failed to record back-channel logout abandonment");
        }
    }
}

/// `KeyService` を [`LogoutTokenSigner`] として使うアダプタ。
pub struct KeyServiceLogoutTokenSigner {
    keys: Arc<crate::application::key_service::KeyService>,
}

impl KeyServiceLogoutTokenSigner {
    pub fn new(keys: Arc<crate::application::key_service::KeyService>) -> Self {
        Self { keys }
    }
}

#[async_trait::async_trait]
impl LogoutTokenSigner for KeyServiceLogoutTokenSigner {
    async fn sign(&self, claims: &LogoutTokenClaims) -> anyhow::Result<String> {
        let key = self.keys.active_signing_key().await?;
        jwt::sign(
            &key.private_pem,
            &key.kid,
            "logout+jwt",
            &key.algorithm,
            claims,
        )
    }
}

/// `Uuid` を返す ID ジェネレータのうち、`jti` 用に v4 を使いたい箇所のための補助。
/// （`IdGenerator` は UUIDv7 を返す。`jti` は時刻の推測余地を残さない v4 が望ましい。）
pub fn new_jti() -> Uuid {
    Uuid::new_v4()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::tenant::TenantId;
    use chrono::{DateTime, TimeZone, Utc};
    use std::sync::Mutex;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap()
    }

    struct FixedClock;
    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            now()
        }
    }

    struct SequentialIds {
        next: Mutex<u128>,
    }
    impl IdGenerator for SequentialIds {
        fn new_id(&self) -> Uuid {
            let mut n = self.next.lock().unwrap();
            *n += 1;
            Uuid::from_u128(*n)
        }
    }

    #[derive(Default)]
    struct RecordingRepo {
        enqueued: Mutex<Vec<BackchannelLogoutDelivery>>,
        due: Mutex<Vec<BackchannelLogoutDelivery>>,
        delivered: Mutex<Vec<Uuid>>,
        failed: Mutex<Vec<(Uuid, DateTime<Utc>, String)>>,
    }

    #[async_trait::async_trait]
    impl BackchannelLogoutDeliveryRepository for RecordingRepo {
        async fn enqueue(&self, deliveries: &[BackchannelLogoutDelivery]) -> Result<()> {
            self.enqueued.lock().unwrap().extend_from_slice(deliveries);
            Ok(())
        }
        async fn claim_due(
            &self,
            _now: DateTime<Utc>,
            _max_attempts: i32,
            _limit: u32,
        ) -> Result<Vec<BackchannelLogoutDelivery>> {
            Ok(std::mem::take(&mut *self.due.lock().unwrap()))
        }
        async fn mark_delivered(&self, id: Uuid, _at: DateTime<Utc>) -> Result<()> {
            self.delivered.lock().unwrap().push(id);
            Ok(())
        }
        async fn mark_failed(
            &self,
            id: Uuid,
            next_attempt_at: DateTime<Utc>,
            error: &str,
        ) -> Result<()> {
            self.failed
                .lock()
                .unwrap()
                .push((id, next_attempt_at, error.to_string()));
            Ok(())
        }
        async fn purge_settled(&self, _older: DateTime<Utc>, _max: i32) -> Result<u64> {
            Ok(0)
        }
    }

    struct StubSigner;
    #[async_trait::async_trait]
    impl LogoutTokenSigner for StubSigner {
        async fn sign(&self, claims: &LogoutTokenClaims) -> anyhow::Result<String> {
            Ok(serde_json::to_string(claims).unwrap())
        }
    }

    struct StubSender {
        succeed: bool,
        sent: Mutex<Vec<(String, String)>>,
    }
    #[async_trait::async_trait]
    impl BackchannelLogoutSender for StubSender {
        async fn post(&self, uri: &str, token: &str) -> std::result::Result<(), String> {
            self.sent
                .lock()
                .unwrap()
                .push((uri.to_string(), token.to_string()));
            if self.succeed {
                Ok(())
            } else {
                Err("connection refused".to_string())
            }
        }
    }

    fn service(
        repo: Arc<RecordingRepo>,
        sender: Arc<StubSender>,
    ) -> BackchannelLogoutDeliveryService {
        BackchannelLogoutDeliveryService::new(
            repo,
            Arc::new(StubSigner),
            sender,
            Arc::new(SequentialIds {
                next: Mutex::new(0),
            }),
            Arc::new(FixedClock),
            "https://idp.example.com".to_string(),
            5,
            10,
        )
    }

    fn tenant() -> TenantId {
        TenantId::from(Uuid::from_u128(0x0197_0000_0000_7000_8000_0000_0000_0001))
    }

    fn delivery(uri: &str, attempts: i32) -> BackchannelLogoutDelivery {
        BackchannelLogoutDelivery {
            attempts,
            ..BackchannelLogoutDelivery::new(
                NewBackchannelLogoutDelivery {
                    id: Uuid::from_u128(100),
                    jti: Uuid::from_u128(200),
                    tenant_id: tenant(),
                    client_id: "rp-1".to_string(),
                    target_uri: uri.to_string(),
                    subject: "sub-1".to_string(),
                    sid: Some("sid-1".to_string()),
                },
                now(),
            )
        }
    }

    /// ログアウトの同期区間では HTTP を打たず、行を積むだけで終わる。
    #[tokio::test]
    async fn enqueue_persists_one_row_per_client_and_sends_nothing() {
        let repo = Arc::new(RecordingRepo::default());
        let sender = Arc::new(StubSender {
            succeed: true,
            sent: Mutex::new(Vec::new()),
        });
        let svc = service(repo.clone(), sender.clone());

        svc.enqueue(
            tenant(),
            "sub-1",
            Some("sid-1"),
            &[
                LogoutNotification {
                    client_id: "rp-1".to_string(),
                    backchannel_logout_uri: "https://rp1.example.com/logout".to_string(),
                },
                LogoutNotification {
                    client_id: "rp-2".to_string(),
                    backchannel_logout_uri: "https://rp2.example.com/logout".to_string(),
                },
            ],
        )
        .await
        .unwrap();

        let rows = repo.enqueued.lock().unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.sid.as_deref() == Some("sid-1")));
        assert!(rows.iter().all(|r| r.attempts == 0));
        // jti は行ごとに異なる（RP 側の冪等判定が別の通知を同一視しないため）。
        assert_ne!(rows[0].jti, rows[1].jti);
        assert!(
            sender.sent.lock().unwrap().is_empty(),
            "同期区間では送らない"
        );
    }

    #[tokio::test]
    async fn successful_delivery_is_recorded_and_not_retried() {
        let repo = Arc::new(RecordingRepo::default());
        repo.due
            .lock()
            .unwrap()
            .push(delivery("https://rp1.example.com/logout", 1));
        let sender = Arc::new(StubSender {
            succeed: true,
            sent: Mutex::new(Vec::new()),
        });
        let svc = service(repo.clone(), sender.clone());

        assert_eq!(svc.deliver_due().await.unwrap(), 1);
        assert_eq!(repo.delivered.lock().unwrap().len(), 1);
        assert!(repo.failed.lock().unwrap().is_empty());
        // logout_token に sid と exp が載っている（G5 の要）。
        let (_, token) = sender.sent.lock().unwrap()[0].clone();
        let claims: serde_json::Value = serde_json::from_str(&token).unwrap();
        assert_eq!(claims["sid"], "sid-1");
        assert_eq!(claims["exp"], now().timestamp() + LOGOUT_TOKEN_TTL_SECS);
        assert_eq!(
            claims["iss"],
            format!("https://idp.example.com/{}", tenant())
        );
    }

    /// 非 2xx・接続失敗は失敗として記録し、バックオフ後に再試行できる状態にする。
    #[tokio::test]
    async fn failed_delivery_is_rescheduled_with_backoff() {
        let repo = Arc::new(RecordingRepo::default());
        repo.due
            .lock()
            .unwrap()
            .push(delivery("https://rp1.example.com/logout", 2));
        let sender = Arc::new(StubSender {
            succeed: false,
            sent: Mutex::new(Vec::new()),
        });
        let svc = service(repo.clone(), sender);

        svc.deliver_due().await.unwrap();
        assert!(repo.delivered.lock().unwrap().is_empty());
        let failed = repo.failed.lock().unwrap();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].1, now() + retry_backoff(2));
        assert_eq!(failed[0].2, "connection refused");
    }

    /// 内部宛先は送信せず打ち切る（SSRF 防止。再試行しても直らない）。
    #[tokio::test]
    async fn internal_destinations_are_abandoned_without_sending() {
        let repo = Arc::new(RecordingRepo::default());
        repo.due
            .lock()
            .unwrap()
            .push(delivery("http://127.0.0.1:8080/logout", 1));
        let sender = Arc::new(StubSender {
            succeed: true,
            sent: Mutex::new(Vec::new()),
        });
        let svc = service(repo.clone(), sender.clone());

        svc.deliver_due().await.unwrap();
        assert!(sender.sent.lock().unwrap().is_empty());
        assert!(repo.delivered.lock().unwrap().is_empty());
        let failed = repo.failed.lock().unwrap();
        assert_eq!(failed.len(), 1);
        // 再試行の対象から外れるよう、次回時刻がはるか先へ倒れている。
        assert!(failed[0].1 > now() + chrono::Duration::days(3_000));
    }
}
