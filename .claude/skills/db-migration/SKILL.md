---
name: db-migration
description: Use when creating or reviewing sqlx (MariaDB) migrations, changing master data, or editing DB-related CI/CD pipeline steps. Enforces migration-version-based schema/master-data version sync.
---

# DB Schema / Master Data Version Sync

- sqlx マイグレーションの version（`_sqlx_migrations` テーブル）を SSOT とする。バージョン番号の手動管理は禁止。
- マスタデータ（clients seed・初期管理ユーザー等）の変更も必ずマイグレーション（冪等 upsert）として書く。
- readiness/起動時チェックは「DB が期待 version 以上」で判定する（厳密一致にしない）。
- 破壊的 DDL 変更は必ず expand/contract で分割する。
- マイグレーション適用は専用ジョブで単独実行し、並行実行しない。
- CI の Verify ステージで、マイグレーションの適用可否（up/down 往復）と head 数の検証を必須にする。
- 各マイグレーションは reversible（`.up.sql` / `.down.sql` を対で用意）とし、`down` も動作させる。
- MariaDB では DB ネイティブ ENUM を使わない（`VARCHAR` + `CHECK`）。UUID は `CHAR(36)`、時刻は UTC の `DATETIME(6)`。

詳細な設計根拠は `docs/adr/0004-schema-version-sync.md`（Alembic 前提の記述は sqlx version に読み替える）、
採用スタックの判断は `docs/adr/0005-rust-mariadb-stack.md` を参照。
