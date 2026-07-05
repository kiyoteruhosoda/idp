# CHANGELOG

完了した重要な変更の要約（詳しい経緯は `history/`、設計判断は `adr/`）。

## 2026-07-05

- **ドキュメントを実装スタック（Rust + MariaDB）に整合**。CLAUDE.md・db-migration スキルを
  Rust/axum/sqlx 前提へ改訂し、ADR-0005（スタック採用）を追加、ADR-0004 と OIDC_INPUT.md に
  MariaDB 読み替え注記を追加（ADR-0005）。
- **T0: プロジェクト基盤を構築**。単一バイナリクレート（`idp`）を作成し、DDD 4層のモジュール骨格
  （domain / application / infrastructure / presentation）を配置。axum によるサーバ起動、`config`
  モジュール（環境変数 > 既定値、issuer 正規化・各種 TTL）、`tracing` の JSON 構造化ログ、sqlx の
  MariaDB 接続プール、起動時のスキーマ version 照合（`_sqlx_migrations` を SSOT とした fail-fast）、
  `/healthz`・`/readyz` ヘルスチェック、開発用 `docker-compose.yml`（MariaDB 10.11 / 任意 Redis）を実装。
