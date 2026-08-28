//! 署名鍵のユースケース: ブートストラップ（ACTIVE 鍵の確保）、署名材料の取得、JWKS 構築、管理操作。
#![allow(dead_code)]

use crate::domain::clock::Clock;
use crate::domain::error::DomainError;
use crate::domain::message::MessageKey;
use crate::domain::repositories::SigningKeyRepository;
use crate::domain::signing_key::{current_signer_at, SigningKey};
use crate::domain::values::{SigningAlgorithm, SigningKeyStatus};
use crate::domain::{crypto, jwt};
use chrono::Duration;
use std::sync::Arc;

/// 鍵の有効期間（新規生成時の not_after までの日数）。
const KEY_VALIDITY_DAYS: i64 = 365;

/// 署名に使う ACTIVE 鍵の材料（復号済み秘密鍵 PEM・kid・アルゴリズム）。
pub struct ActiveSigningKey {
    pub kid: String,
    pub algorithm: String,
    pub private_pem: String,
}

/// 署名鍵管理エラー。
#[derive(Debug, thiserror::Error)]
pub enum KeyManagementError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("validation error: {0}")]
    Validation(MessageKey),
    #[error("internal error: {0}")]
    Internal(String),
}

pub struct KeyService {
    repo: Arc<dyn SigningKeyRepository>,
    clock: Arc<dyn Clock>,
    key_encryption_key: [u8; 32],
}

impl KeyService {
    pub fn new(
        repo: Arc<dyn SigningKeyRepository>,
        clock: Arc<dyn Clock>,
        key_encryption_key: [u8; 32],
    ) -> Self {
        Self {
            repo,
            clock,
            key_encryption_key,
        }
    }

    /// **いま署名できる鍵**が無ければ鍵ペアを生成し、秘密鍵を暗号化して永続化する（冪等）。
    ///
    /// 判定は `current_signer_at` —— 「ACTIVE 行があるか」ではない。公開しただけの後継鍵
    /// （`not_before` が未来）や期限切れのまま ACTIVE で残った鍵は署名できないので、
    /// それしか無い状態はブートストラップが要る状態である。
    ///
    /// 挿入は `insert_if_no_active`（repository の排他区間）で行い、複数インスタンスの同時起動
    /// （ローリングデプロイ・並列テスト）でも鍵が重複生成されない（SEC5）。
    /// 排他区間で負けた側は生成済みの鍵材料を破棄して成功扱いにする。
    pub async fn ensure_active_key(&self) -> anyhow::Result<()> {
        let keys = self
            .repo
            .list_all()
            .await
            .map_err(|e| anyhow::anyhow!("list signing keys: {e}"))?;
        if current_signer_at(&keys, self.clock.now()).is_some() {
            return Ok(());
        }
        // **直前に使っていた鍵のアルゴリズムを引き継ぐ**（`rotate_if_needed` の補充と同じ規則）。
        // 決め打ちにすると、ES256 で運用していた環境がこの経路を通っただけで黙って RS256 へ戻る。
        let algorithm = keys
            .first()
            .and_then(|key| SigningAlgorithm::parse(&key.algorithm).ok())
            .unwrap_or(SigningAlgorithm::Rs256);
        // ブートストラップは**猶予を置かない**。署名できる鍵が 1 本も無い状態なので、待つと
        // そのあいだトークンを発行できない。
        let key = self.new_key_material(algorithm, Duration::zero()).await?;
        let inserted = self
            .repo
            .insert_if_no_active(&key)
            .await
            .map_err(|e| anyhow::anyhow!("bootstrap signing key: {e}"))?;
        if inserted {
            tracing::info!(kid = %key.kid, "bootstrapped the active signing key");
        } else {
            tracing::info!("active signing key already bootstrapped by another instance");
        }
        Ok(())
    }

    /// 署名に使う ACTIVE 鍵（秘密鍵を復号して返す）。
    pub async fn active_signing_key(&self) -> anyhow::Result<ActiveSigningKey> {
        let key = self
            .find_active_key()
            .await?
            .ok_or_else(|| anyhow::anyhow!("no active signing key"))?;
        let private_bytes = crypto::decrypt(&key.private_key_encrypted, &self.key_encryption_key)?;
        let private_pem = String::from_utf8(private_bytes)
            .map_err(|e| anyhow::anyhow!("decrypted private key is not valid UTF-8: {e}"))?;
        Ok(ActiveSigningKey {
            kid: key.kid,
            algorithm: key.algorithm,
            private_pem,
        })
    }

    /// いま署名に使っている鍵の `kid`。**秘密鍵を復号しない**ので、公開エンドポイント
    /// （SAML メタデータ）から `kid` だけが要るときはこちらを使う。
    pub async fn signing_kid(&self) -> anyhow::Result<Option<String>> {
        Ok(self.find_active_key().await?.map(|key| key.kid))
    }

    /// JWKS（ACTIVE + RETIRED のうち not_after が未来のもの）を構築する。
    pub async fn jwks(&self) -> anyhow::Result<jwt::Jwks> {
        let keys = self
            .repo
            .list_published()
            .await
            .map_err(|e| anyhow::anyhow!("list published keys: {e}"))?;
        let mut jwk_list = Vec::with_capacity(keys.len());
        for key in keys {
            jwk_list.push(jwt::public_jwk(&key.kid, &key.algorithm, &key.public_key)?);
        }
        Ok(jwt::Jwks { keys: jwk_list })
    }

    // ── 自動ローテーション（K2）─────────────────────────────────────────────────

    /// 鍵の入れ替えを進める（冪等。バックグラウンドタスクから定期的に呼ぶ）。
    ///
    /// **入れ替えは 3 段で進む。** 1 回の呼び出しで全部やろうとすると、公開と署名開始が同時に
    /// なってしまい、JWKS をキャッシュしている RP の検証が落ちる。
    ///
    /// 1. 現行鍵の `not_after` まで `lead_days` 日を切ったら、**後継鍵を公開する**
    ///    （`not_before` は `publish_lead_hours` 後）。JWKS には即座に載るが、署名はまだ旧鍵。
    /// 2. `not_before` が来ると、署名は後継鍵へ自動的に移る（`current_signer_at` の規則）。
    ///    ここに呼び出しは要らない。
    /// 3. 引き継ぎ後の呼び出しで、**追い越された ACTIVE 鍵を退役させる**。
    ///
    /// 退役を 3 段目に置くのが要点である。公開と同時に旧鍵を退役させると、`not_before` が来るまで
    /// 署名できる鍵が 1 本も無くなる。
    ///
    /// ACTIVE 鍵が 1 本も無い場合は補充する（管理者が最後の鍵を退役させた場合など）。
    pub async fn rotate_if_needed(
        &self,
        lead_days: u32,
        publish_lead_hours: u32,
    ) -> anyhow::Result<()> {
        let now = self.clock.now();
        // 一覧を 1 回引いて、現行鍵・後継鍵・追い越された鍵をまとめて判断する。
        let keys = self
            .repo
            .list_all()
            .await
            .map_err(|e| anyhow::anyhow!("list signing keys: {e}"))?;

        let Some(active) = current_signer_at(&keys, now).cloned() else {
            // **直前に使っていた鍵のアルゴリズムを引き継ぐ。** 決め打ちにすると、ES256 で運用して
            // いた環境がこの経路を通っただけで黙って RS256 へ戻る（画面では ES256 も選べる）。
            let algorithm = keys
                .first()
                .and_then(|key| SigningAlgorithm::parse(&key.algorithm).ok())
                .unwrap_or(SigningAlgorithm::Rs256);
            tracing::warn!(
                algorithm = %algorithm.as_str(),
                "no usable signing key found during rotation check; bootstrapping"
            );
            self.generate_key_internal(algorithm, Duration::zero())
                .await?;
            return Ok(());
        };

        // 3 段目: 現行鍵に追い越された ACTIVE 鍵を退役させる。`not_before` が未来の後継鍵は
        // 対象にしない（まだ出番が来ていないだけで、追い越されたわけではない）。
        for key in keys
            .iter()
            .filter(|key| key.status == SigningKeyStatus::Active)
            .filter(|key| key.kid != active.kid && key.not_before <= now)
        {
            self.repo
                .update_status(&key.kid, SigningKeyStatus::Retired)
                .await
                .map_err(|e| anyhow::anyhow!("retire superseded key {}: {e}", key.kid))?;
            tracing::info!(
                kid = %key.kid,
                superseded_by = %active.kid,
                "retired signing key superseded by the current signer"
            );
        }

        // 1 段目: 後継鍵が既に公開されていれば、あとは `not_before` を待つだけ。
        if let Some(pending) = keys.iter().find(|key| key.is_pending_at(now)) {
            tracing::debug!(
                kid = %pending.kid,
                signs_from = %pending.not_before,
                "a successor signing key is already published; waiting for its not_before"
            );
            return Ok(());
        }

        let remaining = active.not_after - now;
        if remaining > Duration::days(lead_days as i64) {
            return Ok(());
        }

        // **署名を引き継ぐのは現行鍵が切れる前でなければならない。** `publish_lead_hours` が
        // `lead_days` より長い設定でも、現行鍵の `not_after` を越えないところで頭打ちにする
        // （越えると、切れた瞬間から `not_before` までのあいだ署名できる鍵が無くなる）。
        let signs_from = std::cmp::min(
            now + Duration::hours(publish_lead_hours as i64),
            active.not_after,
        );

        tracing::info!(
            kid = %active.kid,
            not_after = %active.not_after,
            remaining_hours = remaining.num_hours(),
            signs_from = %signs_from,
            "signing key approaching expiry; publishing a successor"
        );

        let algorithm = SigningAlgorithm::parse(&active.algorithm)
            .map_err(|e| anyhow::anyhow!("unknown algorithm on active key: {e}"))?;
        self.generate_key_internal(algorithm, signs_from - now)
            .await?;

        Ok(())
    }

    // ── 管理操作 ──────────────────────────────────────────────────────────────

    /// 全署名鍵を作成日時の降順で返す（管理画面用）。
    pub async fn list_keys(&self) -> Result<Vec<SigningKey>, KeyManagementError> {
        self.repo
            .list_all()
            .await
            .map_err(|e| KeyManagementError::Internal(e.to_string()))
    }

    /// 指定アルゴリズムの新規鍵を生成して ACTIVE で登録する。
    ///
    /// `publish_lead` を置くと、鍵は JWKS に即座に載るが署名には使われない（`not_before` が
    /// その分だけ未来になる）。**通常の入れ替えはこちら** —— RP が新しい `kid` を取り込む猶予に
    /// なる。`Duration::zero()` は「いますぐ署名に使う」で、鍵の危殆化のように猶予を置く余裕が
    /// ないときに限って使う。
    pub async fn generate_key(
        &self,
        algorithm: SigningAlgorithm,
        publish_lead: Duration,
    ) -> Result<SigningKey, KeyManagementError> {
        let publish_lead = self
            .capped_publish_lead(publish_lead)
            .await
            .map_err(|e| KeyManagementError::Internal(e.to_string()))?;
        self.generate_key_internal(algorithm, publish_lead)
            .await
            .map_err(|e| KeyManagementError::Internal(e.to_string()))
    }

    /// 指定 kid の ACTIVE 鍵を RETIRED に変更する。
    ///
    /// **最後の署名可能な鍵は退役させない。** 退役させるとその瞬間からトークンを発行できなくなり、
    /// `rotate_if_needed` による補充は次回の確認まで走らない（既定 1 時間おき）。1 クリックで
    /// トークン発行を止められる導線を残さない。公開済みの後継鍵があっても、`not_before` が
    /// 来ていなければ「署名可能」には数えない。
    pub async fn retire_key(&self, kid: &str) -> Result<(), KeyManagementError> {
        let keys = self
            .repo
            .list_all()
            .await
            .map_err(|e| KeyManagementError::Internal(e.to_string()))?;
        let key = keys
            .iter()
            .find(|key| key.kid == kid)
            .ok_or_else(|| KeyManagementError::NotFound(kid.to_string()))?;

        if key.status == SigningKeyStatus::Retired {
            return Err(KeyManagementError::Validation(MessageKey::new(
                "api-signing-key-retire-failed",
            )));
        }

        let now = self.clock.now();
        let another_key_can_sign = keys
            .iter()
            .any(|other| other.kid != kid && other.is_usable_for_signing_at(now));
        if !another_key_can_sign {
            return Err(KeyManagementError::Validation(MessageKey::new(
                "api-signing-key-retire-last-active",
            )));
        }

        self.repo
            .update_status(kid, SigningKeyStatus::Retired)
            .await
            .map_err(|e| match e {
                DomainError::NotFound => KeyManagementError::NotFound(kid.to_string()),
                other => KeyManagementError::Internal(other.to_string()),
            })
    }

    /// 指定 kid の鍵を削除する。ACTIVE 鍵の削除は禁止する（先に退役させること）。
    pub async fn delete_key(&self, kid: &str) -> Result<(), KeyManagementError> {
        let key = self
            .repo
            .find_by_kid(kid)
            .await
            .map_err(|e| KeyManagementError::Internal(e.to_string()))?
            .ok_or_else(|| KeyManagementError::NotFound(kid.to_string()))?;

        if key.status == SigningKeyStatus::Active {
            return Err(KeyManagementError::Validation(MessageKey::new(
                "api-signing-key-delete-failed",
            )));
        }

        self.repo
            .delete(kid)
            .await
            .map_err(|e| KeyManagementError::Internal(e.to_string()))
    }

    // ── プライベートヘルパー ───────────────────────────────────────────────────

    async fn find_active_key(&self) -> anyhow::Result<Option<SigningKey>> {
        self.repo
            .find_active()
            .await
            .map_err(|e| anyhow::anyhow!("find active key: {e}"))
    }

    /// 公開から署名開始までの猶予を、**署名できる鍵が途切れない範囲**へ丸める。
    ///
    /// `rotate_if_needed` が自動生成でやっている頭打ちと同じ規則を、手動生成にも効かせる。
    /// - 現行鍵の `not_after` を越えない。越えると、現行鍵が切れてから `not_before` までのあいだ
    ///   署名できる鍵が 1 本も無くなる。
    /// - いま署名できる鍵が無いなら猶予は置かない。待つ相手（署名を続ける旧鍵）が居らず、
    ///   猶予のあいだトークンを発行できなくなるだけである。
    async fn capped_publish_lead(&self, publish_lead: Duration) -> anyhow::Result<Duration> {
        if publish_lead <= Duration::zero() {
            return Ok(Duration::zero());
        }
        let keys = self
            .repo
            .list_all()
            .await
            .map_err(|e| anyhow::anyhow!("list signing keys: {e}"))?;
        let now = self.clock.now();
        let Some(active) = current_signer_at(&keys, now) else {
            return Ok(Duration::zero());
        };
        Ok(std::cmp::min(publish_lead, active.not_after - now))
    }

    async fn generate_key_internal(
        &self,
        algorithm: SigningAlgorithm,
        publish_lead: Duration,
    ) -> anyhow::Result<SigningKey> {
        let key = self.new_key_material(algorithm, publish_lead).await?;
        self.repo
            .insert(&key)
            .await
            .map_err(|e| anyhow::anyhow!("insert signing key: {e}"))?;
        tracing::info!(
            kid = %key.kid,
            algorithm = %algorithm.as_str(),
            signs_from = %key.not_before,
            "generated new signing key"
        );
        Ok(key)
    }

    /// 新しい ACTIVE 鍵の材料（鍵ペア生成・秘密鍵暗号化・kid 採番）を組み立てる（永続化しない）。
    ///
    /// 鍵ペア生成は blocking プールへ退避する（下記 `generate_keypair`）。秘密鍵の暗号化（AES-GCM）は
    /// 短時間で終わるためそのまま実行する。
    async fn new_key_material(
        &self,
        algorithm: SigningAlgorithm,
        publish_lead: Duration,
    ) -> anyhow::Result<SigningKey> {
        let (private_pem, public_pem) = generate_keypair(algorithm).await?;
        let now = self.clock.now();
        // 署名を始める時刻。**有効期間はここから数える** —— `now` から数えると、猶予を置いた分
        // だけ実際に使える期間が短くなる。
        let not_before = now + publish_lead.max(Duration::zero());
        let alg_tag = algorithm.as_str().to_lowercase().replace("256", "");
        let kid = format!(
            "{}-{}-{}",
            now.format("%Y%m%d"),
            alg_tag,
            crypto::random_token(6)
        );
        let private_key_encrypted =
            crypto::encrypt(private_pem.as_bytes(), &self.key_encryption_key)?;

        Ok(SigningKey {
            kid,
            algorithm: algorithm.as_str().to_string(),
            public_key: public_pem,
            private_key_encrypted,
            status: SigningKeyStatus::Active,
            not_before,
            not_after: not_before + Duration::days(KEY_VALIDITY_DAYS),
            created_at: now,
            updated_at: now,
        })
    }
}

/// 署名鍵ペアを **blocking プールで**生成し、`(秘密鍵 PEM, 公開鍵 PEM)` を返す。
///
/// RSA 鍵生成は素数探索のため CPU バウンドで、実行時間の裾が長い（数百 ms〜秒級）。これを非同期
/// タスクの中で直接呼ぶと tokio のワーカースレッドを占有し、そのスレッドに載っている**他の全 future**
/// （HTTP リクエスト処理・DB I/O・排他区間を保持したブートストラップタスク）が生成完了まで進まない。
/// ワーカー数を超える並走が起きると、advisory lock を保持したタスクが poll されず、待機側は
/// プール接続を握ったまま滞留する（→ サーバ側タイムアウトによる接続断）。
/// `spawn_blocking` で専用スレッドへ退避することで、生成中もランタイムは他の future を進められる。
async fn generate_keypair(algorithm: SigningAlgorithm) -> anyhow::Result<(String, String)> {
    tokio::task::spawn_blocking(move || match algorithm {
        SigningAlgorithm::Rs256 => jwt::generate_rsa_keypair(),
        SigningAlgorithm::Es256 => jwt::generate_ec_keypair(),
    })
    .await
    .map_err(|e| anyhow::anyhow!("signing key generation task failed: {e}"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::clock::Clock;
    use crate::domain::error::Result as RepoResult;
    use chrono::{DateTime, Utc};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use tokio::sync::Notify;

    /// 進められる時計（`rotate_if_needed` は「いつ呼ばれたか」で挙動が変わるため）。
    struct TestClock(Mutex<DateTime<Utc>>);

    impl TestClock {
        fn at(rfc3339: &str) -> Arc<Self> {
            Arc::new(Self(Mutex::new(parse(rfc3339))))
        }
        fn advance(&self, by: Duration) {
            let mut now = self.0.lock().unwrap();
            *now += by;
        }
    }

    impl Clock for TestClock {
        fn now(&self) -> DateTime<Utc> {
            *self.0.lock().unwrap()
        }
    }

    fn parse(rfc3339: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(rfc3339)
            .expect("valid timestamp")
            .with_timezone(&Utc)
    }

    /// メモリ上の署名鍵リポジトリ。`find_active` は本番の SQL と**同じ規則**で選ぶ
    /// （`current_signer_at`）。ここを別の規則で書くと、テストが通っても本番と挙動が違う。
    #[derive(Default)]
    struct FakeRepo(Mutex<Vec<SigningKey>>);

    impl FakeRepo {
        fn with(keys: Vec<SigningKey>) -> Arc<Self> {
            Arc::new(Self(Mutex::new(keys)))
        }
        fn snapshot(&self) -> Vec<SigningKey> {
            self.0.lock().unwrap().clone()
        }
        fn get(&self, kid: &str) -> SigningKey {
            self.snapshot()
                .into_iter()
                .find(|key| key.kid == kid)
                .expect("key exists")
        }
    }

    #[async_trait::async_trait]
    impl SigningKeyRepository for FakeRepo {
        async fn insert(&self, key: &SigningKey) -> RepoResult<()> {
            self.0.lock().unwrap().insert(0, key.clone());
            Ok(())
        }
        async fn insert_if_no_active(&self, _key: &SigningKey) -> RepoResult<bool> {
            // 本番の条件は `find_active` と同じ（ACTIVE かつ有効期間内）で、時刻は SQL 側の
            // `UTC_TIMESTAMP(6)` に依る。ここに近似を書くと本番とずれるので、使わない。
            unreachable!("not exercised by these tests")
        }
        async fn find_active(&self) -> RepoResult<Option<SigningKey>> {
            unreachable!("rotate_if_needed reads the whole list")
        }
        async fn list_published(&self) -> RepoResult<Vec<SigningKey>> {
            unreachable!("not exercised by these tests")
        }
        async fn find_by_kid(&self, kid: &str) -> RepoResult<Option<SigningKey>> {
            Ok(self.snapshot().into_iter().find(|key| key.kid == kid))
        }
        async fn list_all(&self) -> RepoResult<Vec<SigningKey>> {
            // 本番と同じく作成日時の降順。
            let mut keys = self.snapshot();
            keys.sort_by_key(|key| std::cmp::Reverse(key.created_at));
            Ok(keys)
        }
        async fn update_status(&self, kid: &str, status: SigningKeyStatus) -> RepoResult<()> {
            let mut keys = self.0.lock().unwrap();
            match keys.iter_mut().find(|key| key.kid == kid) {
                Some(key) => {
                    key.status = status;
                    Ok(())
                }
                None => Err(DomainError::NotFound),
            }
        }
        async fn delete(&self, kid: &str) -> RepoResult<()> {
            self.0.lock().unwrap().retain(|key| key.kid != kid);
            Ok(())
        }
    }

    /// 既存鍵の見立て。**ES256 を使う** —— RSA の鍵生成はテストには重い。
    fn existing(
        kid: &str,
        status: SigningKeyStatus,
        not_before: &str,
        not_after: &str,
    ) -> SigningKey {
        SigningKey {
            kid: kid.to_string(),
            algorithm: "ES256".to_string(),
            public_key: String::new(),
            private_key_encrypted: String::new(),
            status,
            not_before: parse(not_before),
            not_after: parse(not_after),
            created_at: parse(not_before),
            updated_at: parse(not_before),
        }
    }

    fn service(repo: Arc<FakeRepo>, clock: Arc<TestClock>) -> KeyService {
        KeyService::new(repo, clock, [7u8; 32])
    }

    const LEAD_DAYS: u32 = 30;
    const PUBLISH_LEAD_HOURS: u32 = 24;

    /// 1 段目: 期限が近づいたら**後継鍵を公開するだけ**。旧鍵はまだ署名を続け、退役もしない。
    ///
    /// ここで旧鍵を退役させると、後継鍵の `not_before` が来るまで署名できる鍵が無くなる。
    /// 公開と署名開始を同時にすると、JWKS をキャッシュしている RP の検証が落ちる。
    #[tokio::test]
    async fn a_key_near_expiry_gets_a_successor_that_is_published_but_not_signing() {
        let clock = TestClock::at("2026-08-27T00:00:00Z");
        let repo = FakeRepo::with(vec![existing(
            "old",
            SigningKeyStatus::Active,
            "2025-09-01T00:00:00Z",
            "2026-09-06T00:00:00Z", // 残り 10 日 < lead 30 日
        )]);
        service(repo.clone(), clock.clone())
            .rotate_if_needed(LEAD_DAYS, PUBLISH_LEAD_HOURS)
            .await
            .expect("rotate");

        let keys = repo.snapshot();
        assert_eq!(keys.len(), 2, "a successor must be published");
        let now = clock.now();
        let successor = keys.iter().find(|key| key.kid != "old").expect("successor");
        assert!(
            successor.is_pending_at(now),
            "the successor must not sign yet"
        );
        assert_eq!(successor.not_before, now + Duration::hours(24));
        // 署名は旧鍵のまま。退役もしていない。
        assert_eq!(
            current_signer_at(&keys, now).map(|key| key.kid.as_str()),
            Some("old")
        );
        assert_eq!(repo.get("old").status, SigningKeyStatus::Active);
        // アルゴリズムは引き継ぐ。
        assert_eq!(successor.algorithm, "ES256");
    }

    /// 待っているあいだに呼ばれても、後継鍵を作り直さない（冪等）。作り直すと、待ち時間が
    /// いつまでも終わらない。
    #[tokio::test]
    async fn a_waiting_successor_is_not_generated_again() {
        let clock = TestClock::at("2026-08-27T00:00:00Z");
        let repo = FakeRepo::with(vec![existing(
            "old",
            SigningKeyStatus::Active,
            "2025-09-01T00:00:00Z",
            "2026-09-06T00:00:00Z",
        )]);
        let keys = service(repo.clone(), clock.clone());
        keys.rotate_if_needed(LEAD_DAYS, PUBLISH_LEAD_HOURS)
            .await
            .expect("rotate");
        clock.advance(Duration::hours(1));
        keys.rotate_if_needed(LEAD_DAYS, PUBLISH_LEAD_HOURS)
            .await
            .expect("rotate again");
        assert_eq!(repo.snapshot().len(), 2);
    }

    /// 2 段目と 3 段目: `not_before` を過ぎると署名が移り、**その後の呼び出しで**旧鍵が退役する。
    #[tokio::test]
    async fn the_old_key_is_retired_only_after_the_successor_takes_over() {
        let clock = TestClock::at("2026-08-27T00:00:00Z");
        let repo = FakeRepo::with(vec![existing(
            "old",
            SigningKeyStatus::Active,
            "2025-09-01T00:00:00Z",
            "2026-09-06T00:00:00Z",
        )]);
        let keys = service(repo.clone(), clock.clone());
        keys.rotate_if_needed(LEAD_DAYS, PUBLISH_LEAD_HOURS)
            .await
            .expect("rotate");

        clock.advance(Duration::hours(25));
        let now = clock.now();
        // 呼び出しを待たずに署名は移っている（選ぶ規則が `not_before` を見るため）。
        let successor_kid = repo
            .snapshot()
            .into_iter()
            .find(|key| key.kid != "old")
            .expect("successor")
            .kid;
        assert_eq!(
            current_signer_at(&repo.snapshot(), now).map(|key| key.kid.clone()),
            Some(successor_kid.clone())
        );

        keys.rotate_if_needed(LEAD_DAYS, PUBLISH_LEAD_HOURS)
            .await
            .expect("rotate");
        assert_eq!(repo.get("old").status, SigningKeyStatus::Retired);
        assert_eq!(repo.get(&successor_kid).status, SigningKeyStatus::Active);
        // 退役しても JWKS からは消えない（`not_after` までは検証に使える）。
        assert!(repo.get("old").not_after > now);
    }

    /// 手動生成で ACTIVE が 2 本になっても、追い越された側は次の確認で退役する。放置すると
    /// 「どちらが署名しているか分からない ACTIVE が 2 本」という状態が最長 1 年残る。
    #[tokio::test]
    async fn an_active_key_overtaken_by_a_newer_one_is_retired() {
        let clock = TestClock::at("2026-08-27T00:00:00Z");
        let repo = FakeRepo::with(vec![
            existing(
                "older",
                SigningKeyStatus::Active,
                "2026-01-01T00:00:00Z",
                "2027-01-01T00:00:00Z",
            ),
            existing(
                "newer",
                SigningKeyStatus::Active,
                "2026-08-26T00:00:00Z",
                "2027-08-26T00:00:00Z",
            ),
        ]);
        service(repo.clone(), clock.clone())
            .rotate_if_needed(LEAD_DAYS, PUBLISH_LEAD_HOURS)
            .await
            .expect("rotate");
        assert_eq!(repo.get("older").status, SigningKeyStatus::Retired);
        assert_eq!(repo.get("newer").status, SigningKeyStatus::Active);
        assert_eq!(repo.snapshot().len(), 2, "no new key is needed here");
    }

    /// 猶予が現行鍵の残余期間より長くても、**引き継ぎは現行鍵が切れる前**に起きる。
    /// 越えさせると、切れた瞬間から `not_before` までのあいだ署名できる鍵が無くなる。
    #[tokio::test]
    async fn the_publish_lead_never_pushes_the_handover_past_the_current_key_expiry() {
        let clock = TestClock::at("2026-08-27T00:00:00Z");
        let expiry = "2026-09-06T00:00:00Z"; // 残り 10 日 = 240 時間
        let repo = FakeRepo::with(vec![existing(
            "old",
            SigningKeyStatus::Active,
            "2025-09-01T00:00:00Z",
            expiry,
        )]);
        service(repo.clone(), clock.clone())
            .rotate_if_needed(LEAD_DAYS, 1_000)
            .await
            .expect("rotate");

        let successor = repo
            .snapshot()
            .into_iter()
            .find(|key| key.kid != "old")
            .expect("successor");
        assert_eq!(successor.not_before, parse(expiry));
    }

    /// 署名できる鍵が 1 本も無いときは補充する。**アルゴリズムは直前の鍵から引き継ぐ** ——
    /// 決め打ちにすると、ES256 で運用していた環境がこの経路を通っただけで RS256 へ戻る。
    #[tokio::test]
    async fn bootstrapping_after_the_last_key_was_retired_keeps_the_algorithm() {
        let clock = TestClock::at("2026-08-27T00:00:00Z");
        let repo = FakeRepo::with(vec![existing(
            "retired",
            SigningKeyStatus::Retired,
            "2026-01-01T00:00:00Z",
            "2027-01-01T00:00:00Z",
        )]);
        service(repo.clone(), clock.clone())
            .rotate_if_needed(LEAD_DAYS, PUBLISH_LEAD_HOURS)
            .await
            .expect("rotate");

        let now = clock.now();
        let fresh = repo
            .snapshot()
            .into_iter()
            .find(|key| key.kid != "retired")
            .expect("a replacement key");
        assert_eq!(fresh.algorithm, "ES256");
        // 補充は猶予を置かない（置くと、そのあいだトークンを発行できない）。
        assert!(fresh.is_usable_for_signing_at(now));
    }

    /// **最後の署名可能な鍵は退役させない。** 退役させるとトークン発行が止まり、補充は次回の
    /// ローテーション確認（既定 1 時間おき）まで走らない。
    #[tokio::test]
    async fn the_last_key_that_can_sign_cannot_be_retired() {
        let clock = TestClock::at("2026-08-27T00:00:00Z");
        let repo = FakeRepo::with(vec![existing(
            "only",
            SigningKeyStatus::Active,
            "2026-01-01T00:00:00Z",
            "2027-01-01T00:00:00Z",
        )]);
        let err = service(repo.clone(), clock)
            .retire_key("only")
            .await
            .expect_err("retiring the last usable key must be refused");
        assert!(matches!(err, KeyManagementError::Validation(_)), "{err:?}");
        assert_eq!(repo.get("only").status, SigningKeyStatus::Active);
    }

    /// 公開しただけの後継鍵は「署名可能」に数えない。数えると、`not_before` が来るまでのあいだ
    /// 現行鍵を退役させられてしまい、署名鍵が無い時間が生まれる。
    #[tokio::test]
    async fn a_successor_that_is_only_published_does_not_unlock_retiring_the_current_key() {
        let clock = TestClock::at("2026-08-27T00:00:00Z");
        let repo = FakeRepo::with(vec![
            existing(
                "current",
                SigningKeyStatus::Active,
                "2026-01-01T00:00:00Z",
                "2027-01-01T00:00:00Z",
            ),
            existing(
                "successor",
                SigningKeyStatus::Active,
                "2026-08-28T00:00:00Z", // まだ来ていない
                "2027-08-28T00:00:00Z",
            ),
        ]);
        let err = service(repo.clone(), clock)
            .retire_key("current")
            .await
            .expect_err("must be refused while the successor is still pending");
        assert!(matches!(err, KeyManagementError::Validation(_)), "{err:?}");
    }

    /// 引き継ぎが済んでいれば退役できる。
    #[tokio::test]
    async fn a_superseded_key_can_be_retired_by_hand() {
        let clock = TestClock::at("2026-08-27T00:00:00Z");
        let repo = FakeRepo::with(vec![
            existing(
                "old",
                SigningKeyStatus::Active,
                "2026-01-01T00:00:00Z",
                "2027-01-01T00:00:00Z",
            ),
            existing(
                "new",
                SigningKeyStatus::Active,
                "2026-08-26T00:00:00Z",
                "2027-08-26T00:00:00Z",
            ),
        ]);
        service(repo.clone(), clock)
            .retire_key("old")
            .await
            .expect("retiring a superseded key is allowed");
        assert_eq!(repo.get("old").status, SigningKeyStatus::Retired);
    }

    /// **手動生成の猶予も現行鍵が切れる前で頭打ちにする。** 越えさせると、現行鍵が切れてから
    /// `not_before` までのあいだ署名できる鍵が 1 本も無くなる（`rotate_if_needed` は公開済みの
    /// 後継鍵を見つけて待つだけなので、この穴は次の確認では埋まらない）。
    #[tokio::test]
    async fn a_hand_generated_key_never_starts_signing_after_the_current_key_expires() {
        let clock = TestClock::at("2026-08-27T00:00:00Z");
        let expiry = "2026-08-27T02:00:00Z"; // 残り 2 時間 < 猶予 24 時間
        let repo = FakeRepo::with(vec![existing(
            "current",
            SigningKeyStatus::Active,
            "2025-09-01T00:00:00Z",
            expiry,
        )]);
        let key = service(repo.clone(), clock)
            .generate_key(SigningAlgorithm::Es256, Duration::hours(24))
            .await
            .expect("generate");
        assert_eq!(key.not_before, parse(expiry));
    }

    /// 署名できる鍵が 1 本も無いところへ手動生成したら、猶予は置かない。待つ相手（署名を続ける
    /// 旧鍵）が居らず、猶予のあいだトークンを発行できなくなるだけである。
    #[tokio::test]
    async fn a_hand_generated_key_skips_the_grace_when_nothing_can_sign() {
        let clock = TestClock::at("2026-08-27T00:00:00Z");
        let repo = FakeRepo::with(vec![existing(
            "retired",
            SigningKeyStatus::Retired,
            "2026-01-01T00:00:00Z",
            "2027-01-01T00:00:00Z",
        )]);
        let now = clock.now();
        let key = service(repo.clone(), clock)
            .generate_key(SigningAlgorithm::Es256, Duration::hours(24))
            .await
            .expect("generate");
        assert!(key.is_usable_for_signing_at(now));
    }

    /// 鍵生成中もランタイムが他タスクを進められることの回帰テスト（DB 不要）。
    ///
    /// ワーカースレッド 1 本のランタイム上で、(A) RSA 鍵生成タスクと (B) 即座に完了するタスクを
    /// 「A が生成に入ってから B を投入する」順で走らせ、**B が先に完了する**ことを確認する。
    /// 生成をワーカースレッド上で直接実行する実装（`spawn_blocking` 無し）では、A が生成を終える
    /// まで B は poll されないため完了順が逆転して落ちる。
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn keypair_generation_does_not_block_the_runtime_worker() {
        let completion_order = Arc::new(AtomicUsize::new(0));
        let generation_started = Arc::new(Notify::new());

        let keygen = {
            let completion_order = completion_order.clone();
            let generation_started = generation_started.clone();
            tokio::spawn(async move {
                generation_started.notify_one();
                generate_keypair(SigningAlgorithm::Rs256)
                    .await
                    .expect("generate RSA keypair");
                completion_order.fetch_add(1, Ordering::SeqCst)
            })
        };

        // A が実際に走り出してから B を投入する（投入順による偶然の逆転を排除する）。
        generation_started.notified().await;

        let other = {
            let completion_order = completion_order.clone();
            tokio::spawn(async move { completion_order.fetch_add(1, Ordering::SeqCst) })
        };

        let other_position = other.await.expect("join the non-blocking task");
        let keygen_position = keygen.await.expect("join the keygen task");
        assert!(
            other_position < keygen_position,
            "keygen must not occupy the runtime worker: other task finished at {other_position}, keygen at {keygen_position}"
        );
    }
}
