# ADR-0005: 実装スタックを Rust + MariaDB とする

- Status: Accepted
- Date: 2026-07-05
- 関連: `docs/OIDC_INPUT.md`（設計仕様）、`docs/adr/0004-schema-version-sync.md`（スキーマ整合の思想）、`CLAUDE.md`

## Context

本リポジトリには当初、2 系統の前提が混在していた。

- **設計仕様 `docs/OIDC_INPUT.md`** と **`.gitignore`（Cargo 用）** は **Rust** 実装を前提。
  データモデルは PostgreSQL 固有型（`CITEXT` / `timestamptz` / `inet` / `text[]` / 部分 UNIQUE 索引）で記述。
- **`CLAUDE.md` / `docs/adr/0004-schema-version-sync.md` / `.claude/skills/db-migration/`** は
  **Python/FastAPI/SQLAlchemy/Alembic + MariaDB** を前提（他プロジェクトのテンプレート由来）。

この不整合を解消し、実装スタックを一意に定める必要があった。

## Decision

- **実装言語 / フレームワーク: Rust（axum + tokio、DB アクセスは sqlx）。**
  設計仕様本文の「Rust で実装する」および Cargo 用 `.gitignore` に従う。
- **データベース: MariaDB 10.11。**
- Python 前提で書かれていた `CLAUDE.md` / ADR-0004 / db-migration スキルは、
  **思想（DDD 4層、SOLID、scope ベース認可、version を SSOT とした fail-fast なスキーマ照合、
  DB ネイティブ ENUM 禁止、UTC 徹底、PII 非出力）を踏襲**しつつ、
  実装手段を Rust エコシステムに読み替える（Alembic → sqlx マイグレーション、SQLAlchemy → sqlx、
  Pydantic → serde、FastAPI → axum）。
- 設計仕様の PostgreSQL 固有型は MariaDB 向けに読み替える（`CLAUDE.md`「DB モデリング」参照）。

### PostgreSQL → MariaDB 型読み替え

| 設計仕様（PostgreSQL） | MariaDB での実装 |
|---|---|
| `UUID` | `CHAR(36)`（正準文字列。最適化時のみ `BINARY(16)`） |
| `CITEXT` | `VARCHAR` + 大小無視照合（`utf8mb4_0900_ai_ci` 等） |
| `timestamptz` | `DATETIME(6)`（UTC で保持） |
| `inet` | `VARCHAR(45)` |
| `text[]`（配列） | `JSON` |
| 部分 UNIQUE 索引 `WHERE col IS NOT NULL` | 通常の UNIQUE 索引（MariaDB は複数 NULL を許容） |
| `enum(...)` | `VARCHAR` + `CHECK` 制約（Rust 側 enum で許可値集中管理） |
| `RETURNING *` | `UPDATE ... WHERE ...` の affected rows 判定 |

## Consequences

- `CLAUDE.md` を Rust/axum/sqlx 前提へ全面改訂した。
- ADR-0004 の Alembic 固有記述は「revision id → sqlx マイグレーション version」と読み替える
  （ADR-0004 冒頭に読み替え注記を追加）。
- db-migration スキルを sqlx 前提へ改訂した。
- 設計仕様 `docs/OIDC_INPUT.md` 自体は spec として温存し、DB 実装差分は本 ADR と `CLAUDE.md` を出所とする。
- セッションストア（AuthSession / SsoSession）は MVP では MariaDB 単独で完結させ、Redis はスケール時に導入する。
