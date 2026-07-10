//! `IdGenerator` の実装（UUIDv7。ADR-0009 §12）。

use crate::domain::id_generator::IdGenerator;
use uuid::Uuid;

pub struct UuidV7Generator;

impl IdGenerator for UuidV7Generator {
    fn new_id(&self) -> Uuid {
        Uuid::now_v7()
    }
}
