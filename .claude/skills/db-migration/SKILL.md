---
name: db-migration
description: Use when creating or reviewing Alembic migrations, changing master data, or editing DB-related CI/CD pipeline steps. Enforces revision-based schema/master-data version sync.
---

# DB Schema / Master Data Version Sync

- Alembicのrevision idをSSOTとする。バージョン番号の手動管理は禁止。
- マスタデータの変更も必ずAlembicのデータマイグレーション(冪等upsert)として書く。
- readiness/起動時チェックは「DBが期待revision以上」で判定する(厳密一致にしない)。
- CIでは alembic check とhead数検証をVerifyステージで必須にする。
- マイグレーション適用は専用ジョブで単独実行し、並行実行しない。
- 破壊的DDL変更は必ずexpand/contractで分割する。

詳細な設計根拠とコード例は `references/schema-version-sync.md` を参照。
