//! アカウント ——assay へ名乗る主体の総称（ADR-0038 / ADR-0065）。
//!
//! 種別は 2 つ: **人**（`users` ＋ テナントのメンバーシップ）と**サービスアカウント**（`client_credentials`
//! だけで動く `clients`）。識別子・資格情報・止め方は種別で違う（ADR-0038 の決定 2）が、
//! 「これは何者で、どこを使えるか」への答え方（管理者メモ・使えるアプリ・一覧）は種別を問わず
//! 同じ形で持つ。食い違いの根は、それらが人の形でだけ作られていたことにあった（ADR-0065）。

use crate::domain::account_note::AccountNote;
use crate::domain::error::DomainError;
use crate::domain::tenant::TenantId;
use crate::domain::tenant_membership::TenantMember;
use crate::domain::values::ClientStatus;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// アカウント 1 つを指す値（ADR-0059 の決定 5・ADR-0065 の決定 2）。
///
/// アプリの割り当て（`application_assignments`）と管理者メモ（`account_notes`）が同じ形で持つ
/// ——`kind` 列と、`user_id` / `client_id` のどちらか 1 つだけが埋まる。
///
/// ⚠ 種類で振る舞いが違う（割り当てのとき）:
///
/// - 「全員（`EVERYONE`）」に含まれるのは**人だけ**。サービスアカウントは必ず個別に割り当てる
/// - 人の割り当て = ログインしてよい（code の発行時の判定が見るのは人だけ）
/// - サービスアカウントの割り当て = そのアプリの宛名（`resource` の名乗り）宛のトークンを取ってよい
/// - 名簿（self）に載るのは人だけ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountRef {
    /// 人（`users.id`）。
    User { user_id: Uuid },
    /// サービスアカウント（`client_credentials` だけの `clients.id`）。
    ServiceAccount { client_row_id: Uuid },
}

impl AccountRef {
    /// DB の `kind` 列に入る値。許可値の単一の出所は本 enum。
    pub fn kind(&self) -> &'static str {
        self.account_kind().db_value()
    }

    /// 種別だけを取り出す。
    pub fn account_kind(&self) -> AccountKind {
        match self {
            Self::User { .. } => AccountKind::User,
            Self::ServiceAccount { .. } => AccountKind::ServiceAccount,
        }
    }

    /// 人なら `users.id`。
    pub fn user_id(&self) -> Option<Uuid> {
        match self {
            Self::User { user_id } => Some(*user_id),
            Self::ServiceAccount { .. } => None,
        }
    }

    /// サービスアカウントなら `clients.id`。
    pub fn client_row_id(&self) -> Option<Uuid> {
        match self {
            Self::User { .. } => None,
            Self::ServiceAccount { client_row_id } => Some(*client_row_id),
        }
    }
}

/// 管理 API の経路がアカウントを指す値（ADR-0065）。
///
/// 人は内部 ID、サービスアカウントは `client_id`（人が知っている値）で指す ——割り当ての要求
/// （ADR-0059）と同じ指し方。[`AccountRef`]（`clients.id`）への読み替えは、要求テナントに居るか・
/// サービスアカウントかを確かめたうえで Application 層が行う。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountLocator<'a> {
    User { user_id: Uuid },
    ServiceAccount { client_id: &'a str },
}

/// アカウントの種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccountKind {
    User,
    ServiceAccount,
}

impl AccountKind {
    /// 並べる順（一覧で「すべて」のとき、応答に載せる種別の順）。
    pub const ALL: [AccountKind; 2] = [AccountKind::User, AccountKind::ServiceAccount];

    /// 管理 API の語彙（`?kind=`・応答の `kind`）。割り当ての要求（ADR-0059）と同じ綴り。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::ServiceAccount => "service_account",
        }
    }

    /// DB の `kind` 列の値（`application_assignments` / `account_notes`）。
    pub fn db_value(&self) -> &'static str {
        match self {
            Self::User => "USER",
            Self::ServiceAccount => "SERVICE_ACCOUNT",
        }
    }

    /// 管理 API の語彙から読む。未知の値は `None`（呼び出し側が 400 にする）。
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "user" => Some(Self::User),
            "service_account" => Some(Self::ServiceAccount),
            _ => None,
        }
    }

    /// DB の `kind` 列の値から読む。
    pub fn from_db(raw: &str) -> Result<Self, DomainError> {
        match raw {
            "USER" => Ok(Self::User),
            "SERVICE_ACCOUNT" => Ok(Self::ServiceAccount),
            other => Err(DomainError::Repository(format!(
                "unknown account kind `{other}`"
            ))),
        }
    }
}

/// サービスアカウント 1 件（管理画面が読む読み取りモデル。ADR-0065）。
#[derive(Debug, Clone)]
pub struct ServiceAccount {
    /// `clients.id`（割り当て・メモの相手）。
    pub client_row_id: Uuid,
    /// 発行された `client_id`（人が見分ける値。経路にもこれを書く）。
    pub client_id: String,
    /// 登録名。
    pub app_name: String,
    pub status: ClientStatus,
    pub created_at: DateTime<Utc>,
    /// このサービスアカウントを名乗り（binding）に持つアプリ（ADR-0059 の決定 1）。無ければ `None`。
    ///
    /// ⚠ 「使えるアプリ」（割り当て）とは別の関係である。取り違えると管理トークンが出ない。
    pub identity_of: Option<IdentityApplication>,
    /// 管理者メモ。⚠ **管理画面の外へ出さない。**
    pub note: Option<AccountNote>,
}

/// サービスアカウントを名乗りに持つアプリ（id と表示名だけ）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityApplication {
    pub application_id: Uuid,
    pub display_name: String,
}

/// 一覧の 1 行。
#[derive(Debug, Clone)]
pub enum Account {
    User(TenantMember),
    ServiceAccount(ServiceAccount),
}

impl Account {
    pub fn kind(&self) -> AccountKind {
        match self {
            Self::User(_) => AccountKind::User,
            Self::ServiceAccount(_) => AccountKind::ServiceAccount,
        }
    }
}

/// アカウント一覧の絞り込み条件（呼び出し側がクランプ・正規化した後の値）。
#[derive(Debug, Clone)]
pub struct AccountFilter {
    pub tenant_id: TenantId,
    /// 並べる種別。⚠ **空にしない**（読める種別が無ければ呼び出し側が 403 にする）。
    pub kinds: Vec<AccountKind>,
    pub search: Option<String>,
    pub limit: i64,
    pub offset: i64,
}

/// アカウント一覧の 1 ページ分。`total` は `limit` / `offset` を無視した該当総数。
#[derive(Debug, Clone)]
pub struct AccountPage {
    pub accounts: Vec<Account>,
    pub total: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_and_db_spellings_round_trip() {
        for kind in AccountKind::ALL {
            assert_eq!(AccountKind::parse(kind.as_str()), Some(kind));
            assert_eq!(AccountKind::from_db(kind.db_value()).unwrap(), kind);
        }
        assert_eq!(AccountKind::parse("USER"), None);
        assert!(AccountKind::from_db("user").is_err());
    }

    #[test]
    fn ref_kind_matches_the_db_value_used_by_assignments() {
        let user = AccountRef::User {
            user_id: Uuid::nil(),
        };
        let sa = AccountRef::ServiceAccount {
            client_row_id: Uuid::nil(),
        };
        assert_eq!(user.kind(), "USER");
        assert_eq!(sa.kind(), "SERVICE_ACCOUNT");
    }
}
