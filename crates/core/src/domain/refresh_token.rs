//! RefreshTokens エンティティ（設計仕様 §9.1）。
//! DB には平文ではなく `token_hash = SHA-256(refresh_token)` を保存する。
//! `parent_hash` は rotation / reuse detection に使う。
#![allow(dead_code)]

use crate::domain::tenant::TenantId;
use crate::domain::values::AuthenticationMethod;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct RefreshToken {
    pub token_hash: String,
    /// rotation で発行する際に設定する（チェーンの前トークンの hash）。
    pub parent_hash: Option<String>,
    /// このトークンを生んだ認可グラント（authorization code）の SHA-256（SEC8）。code 交換で
    /// 発行した根トークンと、そこから rotation で派生した子孫すべてが同じ値を持つ ＝ **トークン
    /// ファミリの識別子**。再利用を検知したときはこの値でファミリごと失効させる。
    ///
    /// `parent_hash` はチェーンを 1 段ずつしか辿れず、再利用検知時に子孫を追えない。
    /// `None` は移行前（0025 より前）に rotation 済みだった行だけで、次の rotation で埋まる。
    pub grant_hash: Option<String>,
    /// トークンを発行したテナント（ADR-0009 §8。使用・失効は同一テナントに限る）。
    pub tenant_id: TenantId,
    pub user_id: Uuid,
    pub client_id: String,
    pub scope: Vec<String>,
    /// ID Token へ載せる SSO セッション識別子（G5）。rotation で引き継ぐ。
    pub sid: Option<String>,
    /// このグラントを生んだ認証で検証された方式（ADR-0043）。`sid` と同じく rotation で
    /// 引き継ぐ ——refresh では認証をやり直していないので、名乗る強度も変わらないため。
    /// `None` = 記録なし（本列の導入前に発行されたトークン）。
    pub authentication_methods: Option<Vec<AuthenticationMethod>>,
    /// このグラントを生んだ認証の時刻（ID Token の `auth_time`。task #584）。`sid` と同じく
    /// rotation で引き継ぐ ——refresh では認証をやり直していないので、「最後にログインした時刻」も
    /// 変わらない。`None` = 記録なし（本列の導入前に発行されたトークン。[`Self::auth_time_or_issued`]）。
    pub auth_time: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl RefreshToken {
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }

    pub fn is_valid_at(&self, now: DateTime<Utc>) -> bool {
        !self.is_revoked() && !self.is_expired_at(now)
    }

    /// このトークンから rotation で発行する子へ引き継ぐファミリ識別子（SEC8）。
    ///
    /// 自身が `grant_hash` を持たない移行前の行なら、**自身の hash を新しい家族の起点にする**。
    /// 祖先を辿らないのは、辿るための再帰が rotation のホットパスに載るため。こうしておけば、
    /// 移行前から生きているチェーンも次の rotation 以降はファミリ失効の対象になる。
    /// ID Token の `auth_time` に使う時刻。記録が無い移行前の行は、そのトークンを出した時刻で代える
    /// （実際の認証はそれより前なので、少なくとも「今ログインした」とは名乗らない）。
    pub fn auth_time_or_issued(&self) -> DateTime<Utc> {
        self.auth_time.unwrap_or(self.created_at)
    }

    pub fn family_hash(&self) -> String {
        self.grant_hash
            .clone()
            .unwrap_or_else(|| self.token_hash.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(token_hash: &str, grant_hash: Option<&str>) -> RefreshToken {
        let now = Utc::now();
        RefreshToken {
            token_hash: token_hash.to_string(),
            parent_hash: None,
            grant_hash: grant_hash.map(str::to_string),
            tenant_id: Uuid::nil().into(),
            user_id: Uuid::nil(),
            client_id: "rp".to_string(),
            scope: vec!["openid".to_string()],
            sid: None,
            authentication_methods: None,
            auth_time: None,
            expires_at: now,
            revoked_at: None,
            created_at: now,
        }
    }

    #[test]
    fn family_is_inherited_from_the_authorization_grant() {
        assert_eq!(token("child", Some("grant")).family_hash(), "grant");
    }

    #[test]
    fn legacy_rows_start_a_new_family_at_their_own_hash() {
        // 0025 より前に rotation 済みだった行は `grant_hash` を持たない。祖先を辿らずに
        // 自分を起点とすることで、次の rotation 以降はファミリ失効の対象になる。
        assert_eq!(token("legacy", None).family_hash(), "legacy");
    }

    #[test]
    fn auth_time_falls_back_to_when_the_token_was_issued() {
        let mut t = token("t", None);
        let issued = t.created_at;
        assert_eq!(t.auth_time_or_issued(), issued);
        let signed_in = issued - chrono::Duration::hours(3);
        t.auth_time = Some(signed_in);
        assert_eq!(t.auth_time_or_issued(), signed_in);
    }
}
