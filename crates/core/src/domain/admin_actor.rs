//! 管理操作の実行主体（ADR-0037）。
//!
//! 管理 API を呼べるのは利用者（管理コンソールにログインした人）だけではなくなり、システム用
//! クライアント（`client_credentials`）自身も主体になり得る。「主体 = 利用者 ID」という前提が
//! 崩れるため、**主体をひとつの型で表す**。
//!
//! 監査ログは元から `user_id` と `client_id` の 2 列を持つ（`audit_log`）。本 enum はその 2 列へ
//! そのまま写る形にしてあり、[`AdminActor::user_id`] / [`AdminActor::client_id`] が写像を担う。
//! 「機械が実行した操作の `user_id` を何で埋めるか」を各所で考えずに済ませるための型である。

use uuid::Uuid;

/// 管理操作を実行した主体。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminActor {
    /// 管理コンソールにログインした利用者。
    User(Uuid),
    /// システム用クライアント自身（`client_credentials` で取得した管理トークン）。
    Client {
        /// `clients.id`（代理キー）。権限行の参照に使う。
        id: Uuid,
        /// 発行された `client_id`（監査ログに残す値）。
        client_id: String,
    },
}

impl AdminActor {
    /// 利用者主体なら内部 ID。クライアント主体なら `None`（監査ログの `user_id` 列へ写る）。
    pub fn user_id(&self) -> Option<Uuid> {
        match self {
            Self::User(id) => Some(*id),
            Self::Client { .. } => None,
        }
    }

    /// クライアント主体なら `client_id`。利用者主体なら `None`（監査ログの `client_id` 列へ写る）。
    pub fn client_id(&self) -> Option<&str> {
        match self {
            Self::User(_) => None,
            Self::Client { client_id, .. } => Some(client_id),
        }
    }

    /// クライアント主体なら `clients.id`（権限行の参照キー）。
    pub fn client_row_id(&self) -> Option<Uuid> {
        match self {
            Self::User(_) => None,
            Self::Client { id, .. } => Some(*id),
        }
    }

    /// 主体がクライアント自身か。
    pub fn is_client(&self) -> bool {
        matches!(self, Self::Client { .. })
    }

    /// 監査ログの理由欄へ添える主体表記（クライアント主体のときだけ `Some`）。
    ///
    /// 監査ログの `client_id` 列が**操作対象**のクライアントで既に埋まっている記録（クライアントの
    /// 登録・更新・削除）で使う。そこへ実行主体を書くと対象と主体が同じ列で混ざるため、主体は
    /// 理由欄へ回す。利用者主体は `user_id` 列に出るので `None`。
    pub fn audit_note(&self) -> Option<String> {
        self.client_id().map(|id| format!("actor_client={id}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_actor_maps_to_the_user_id_column_only() {
        let id = Uuid::new_v4();
        let actor = AdminActor::User(id);
        assert_eq!(actor.user_id(), Some(id));
        assert_eq!(actor.client_id(), None);
        assert_eq!(actor.client_row_id(), None);
        assert!(!actor.is_client());
    }

    #[test]
    fn audit_note_names_the_client_actor_only() {
        assert_eq!(AdminActor::User(Uuid::new_v4()).audit_note(), None);
        assert_eq!(
            AdminActor::Client {
                id: Uuid::new_v4(),
                client_id: "batch-job".to_string(),
            }
            .audit_note()
            .as_deref(),
            Some("actor_client=batch-job")
        );
    }

    #[test]
    fn client_actor_maps_to_the_client_id_column_only() {
        let row_id = Uuid::new_v4();
        let actor = AdminActor::Client {
            id: row_id,
            client_id: "batch-job".to_string(),
        };
        assert_eq!(actor.user_id(), None);
        assert_eq!(actor.client_id(), Some("batch-job"));
        assert_eq!(actor.client_row_id(), Some(row_id));
        assert!(actor.is_client());
    }
}
