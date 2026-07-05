//! アプリケーション層（ユースケース・トランザクション境界）。
//!
//! ドメイン層のトレイトを介して Infrastructure に依存する（具象に直接依存しない）。
//! register / authorize / login / token / userinfo / code_issuance（共通）/ key_service /
//! audit 等のユースケースは以降のフェーズ（T2〜）で追加する。
