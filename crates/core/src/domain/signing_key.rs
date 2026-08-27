//! SigningKeys エンティティ（設計仕様 §3.6）。
#![allow(dead_code)]

use crate::domain::values::SigningKeyStatus;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct SigningKey {
    pub kid: String,
    /// 署名アルゴリズム。MVP は `RS256` のみ。
    pub algorithm: String,
    /// 公開鍵（JWKS 公開用）。
    pub public_key: String,
    /// DB 外の鍵で暗号化した秘密鍵。
    pub private_key_encrypted: String,
    pub status: SigningKeyStatus,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SigningKey {
    /// 新規署名に使える鍵か（ACTIVE かつ有効期間内）。
    pub fn is_usable_for_signing_at(&self, now: DateTime<Utc>) -> bool {
        self.status == SigningKeyStatus::Active && self.not_before <= now && now < self.not_after
    }

    /// **公開済みだが、まだ署名には使われない鍵**（`not_before` が未来の ACTIVE 鍵）。
    ///
    /// 鍵の入れ替えでこの状態を経由するのが要点である。JWKS は `not_before` を見ずに公開する
    /// ので、後継鍵は生成した瞬間から RP に配られる一方、署名は `not_before` が来るまで旧鍵が
    /// 続ける。**JWKS をキャッシュしている RP が新しい `kid` を取り込む猶予**がここで生まれる。
    /// 公開と署名開始を同時にすると、キャッシュを持つ RP は TTL が切れるまで検証に失敗する。
    pub fn is_pending_at(&self, now: DateTime<Utc>) -> bool {
        self.status == SigningKeyStatus::Active && now < self.not_before
    }
}

/// いま署名に使われる鍵を選ぶ（使用可能なもののうち `not_before` が最も新しい 1 本）。
///
/// **`SigningKeyRepository::find_active` の SQL と同じ規則**である。管理画面の「署名中」表示と
/// 実際に署名する鍵は同じ規則で選ばれなければならない —— ずれると、画面で「署名中」と見えている
/// 鍵を退役させたのに署名が止まらない（あるいはその逆）という、画面からは説明のつかない挙動になる。
pub fn current_signer_at(keys: &[SigningKey], now: DateTime<Utc>) -> Option<&SigningKey> {
    keys.iter()
        .filter(|key| key.is_usable_for_signing_at(now))
        .max_by_key(|key| key.not_before)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn key(kid: &str, status: SigningKeyStatus, not_before: DateTime<Utc>) -> SigningKey {
        SigningKey {
            kid: kid.to_string(),
            algorithm: "RS256".to_string(),
            public_key: String::new(),
            private_key_encrypted: String::new(),
            status,
            not_before,
            not_after: not_before + Duration::days(365),
            created_at: not_before,
            updated_at: not_before,
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-08-27T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    /// 後継鍵を公開しても、`not_before` が来るまで署名するのは旧鍵のまま。ここが崩れると、
    /// JWKS を配る猶予が無くなり、キャッシュを持つ RP の検証が落ちる。
    #[test]
    fn a_published_successor_does_not_take_over_signing_until_its_not_before() {
        let now = now();
        let old = key("old", SigningKeyStatus::Active, now - Duration::days(300));
        let successor = key("new", SigningKeyStatus::Active, now + Duration::hours(24));
        let keys = vec![old, successor];

        assert!(keys[1].is_pending_at(now));
        assert_eq!(
            current_signer_at(&keys, now).map(|k| k.kid.as_str()),
            Some("old")
        );
        // `not_before` を過ぎたら、そこで初めて引き継ぐ。
        let later = now + Duration::hours(25);
        assert!(!keys[1].is_pending_at(later));
        assert_eq!(
            current_signer_at(&keys, later).map(|k| k.kid.as_str()),
            Some("new")
        );
    }

    /// ACTIVE が 2 本並んでも、署名するのは `not_before` が新しい 1 本だけ。
    #[test]
    fn only_one_of_several_active_keys_signs() {
        let now = now();
        let keys = vec![
            key("older", SigningKeyStatus::Active, now - Duration::days(200)),
            key("newer", SigningKeyStatus::Active, now - Duration::days(1)),
            // 退役済みは候補に入らない（JWKS には残るが署名には使わない）。
            key(
                "retired",
                SigningKeyStatus::Retired,
                now - Duration::hours(1),
            ),
        ];
        assert_eq!(
            current_signer_at(&keys, now).map(|k| k.kid.as_str()),
            Some("newer")
        );
    }

    /// 使える鍵が 1 本も無ければ `None`。呼び出し側はこれを「トークン発行が止まる」と読む。
    #[test]
    fn no_usable_key_yields_no_signer() {
        let now = now();
        let keys = vec![
            key(
                "retired",
                SigningKeyStatus::Retired,
                now - Duration::days(1),
            ),
            key(
                "pending",
                SigningKeyStatus::Active,
                now + Duration::hours(1),
            ),
        ];
        assert!(current_signer_at(&keys, now).is_none());
    }
}
