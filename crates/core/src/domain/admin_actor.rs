//! The principal performing an admin operation (ADR-0037).
//!
//! The admin API can now be called not only by users (people signed in to the admin console) but also by
//! system clients (`client_credentials`) themselves. Since the assumption "principal = user ID"
//! no longer holds, **the principal is represented by a single type**.
//!
//! The audit log already has two columns, `user_id` and `client_id` (`audit_log`). This enum is shaped to map
//! directly onto those two columns, and [`AdminActor::user_id`] / [`AdminActor::client_id`] do the mapping.
//! It is a type that saves every call site from deciding "what to put in `user_id` for an operation a machine performed".

use uuid::Uuid;

/// The principal that performed an admin operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminActor {
    /// A user signed in to the admin console.
    User(Uuid),
    /// A system client itself (an admin token obtained via `client_credentials`).
    Client {
        /// `clients.id` (surrogate key). Used to look up permission rows.
        id: Uuid,
        /// The issued `client_id` (the value recorded in the audit log).
        client_id: String,
    },
}

impl AdminActor {
    /// The internal ID for a user principal. `None` for a client principal (maps to the audit log's `user_id` column).
    pub fn user_id(&self) -> Option<Uuid> {
        match self {
            Self::User(id) => Some(*id),
            Self::Client { .. } => None,
        }
    }

    /// `client_id` for a client principal. `None` for a user principal (maps to the audit log's `client_id` column).
    pub fn client_id(&self) -> Option<&str> {
        match self {
            Self::User(_) => None,
            Self::Client { client_id, .. } => Some(client_id),
        }
    }

    /// `clients.id` for a client principal (the key for looking up permission rows).
    pub fn client_row_id(&self) -> Option<Uuid> {
        match self {
            Self::User(_) => None,
            Self::Client { id, .. } => Some(*id),
        }
    }

    /// Whether the principal is a client itself.
    pub fn is_client(&self) -> bool {
        matches!(self, Self::Client { .. })
    }

    /// Principal notation appended to the audit log's reason field (`Some` only for a client principal).
    ///
    /// Used for records whose `client_id` column is already filled with the **target** client (client
    /// registration, update, deletion). Writing the principal there would mix target and principal in the same column,
    /// so the principal goes to the reason field. A user principal appears in the `user_id` column, so `None`.
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
