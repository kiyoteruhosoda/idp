# Progress

進行中・未着手タスクのみを管理する（完了したら本ファイルから削除し、必要なら `CHANGELOG.md` / `history/` へ）。

OIDC IdP MVP（**Rust + MariaDB**）の実装計画。設計仕様は `docs/OIDC_INPUT.md`、
スタック採用理由は `docs/adr/0005-rust-mariadb-stack.md`。

| 優先 | # | 概要 | 状態 | 影響度 | 工数 |
|---|---|---|---|---|---|
| 1 | T9 | Web（IdP アプリ）のコンテナ化と Docker Compose 統合（DB とネットワーク連携） | ⬜未着手 | 中 | 中 |
| 2 | T10 | 設定・秘密情報の .env 一元管理（鍵・パスワード・TEST_DATABASE_URL） | ⬜未着手 | 中 | 小 |
| 3 | T11 | 初期設定スクリプト（db・web を初期化。パスワード・鍵を生成して .env へ記載） | ⬜未着手 | 中 | 中 |
| 4 | T12 | 初期管理ユーザーのマスタデータ管理（変更前提のデフォルト値として seed 管理） | ⬜未着手 | 中 | 小 |
| 5 | T13 | デプロイスクリプト（同一ホスト Compose。DDL 適用・マスタデータ投入を含む） | ⬜未着手 | 大 | 中 |
| 6 | D2 | OPERATIONS.md へ運用手順を統合（初期化・デプロイ・バックアップ等） | ⬜未着手 | 小 | 小 |

## 詳細

- **T9**: IdP アプリの Dockerfile（`rust:slim` マルチステージビルド、CLAUDE.md「環境要件」準拠）を作成し、
  `docker-compose.yml` に `web` サービスを追加。既存 `mariadb` サービスと同一 Compose ネットワークで連携する
  （`DATABASE_URL` はサービス名解決 `mysql://...@mariadb:3306/idp`）。`depends_on` + healthcheck で起動順序を制御、
  `web` にもヘルスチェック（`/healthz`）を付与。ポート公開・`ISSUER` 等は .env から注入（T10 と連動）。
- **T10**: 秘密情報（MariaDB root/idp パスワード、`KEY_ENCRYPTION_KEY`）と環境設定を `.env` に集約する。
  Docker Compose は `.env` を自動読込。統合テストの `TEST_DATABASE_URL` も `.env` に記載し、
  テスト実行時に読み込まれるようにする（`config.rs` の「必ず config 経由」ルールは維持。
  `.env` は `.gitignore` に追加し、雛形として `.env.example` をコミットする）。
- **T11**: 初期設定スクリプト（例: `scripts/init.sh`）を用意し、db・web をこれ 1 本で初期化する。
  内容: パスワード・鍵（MariaDB root/idp パスワード、`KEY_ENCRYPTION_KEY` 等）を乱数生成して `.env` へ書き出し →
  MariaDB コンテナ起動 → マイグレーション適用 → web ビルド・起動。冪等にする（既存 `.env` があれば上書きしない）。
- **T12**: 初期管理ユーザーは「変更前提のデフォルト値」としてマスタデータで管理する
  （CLAUDE.md「DDL 管理」: 単一の出所＝`migrations/masterdata/*.sql` または domain 定数を seed マイグレーションが参照、
  冪等 upsert）。初回ログイン後にパスワード変更する運用を D2 の手順書に明記する。
- **T13**: デプロイスクリプト（例: `scripts/deploy.sh`）。想定環境は同一ホストの Docker Compose。
  手順: イメージビルド → DDL（`sqlx migrate run`、専用ジョブとして単独実行）→ マスタデータ投入
  （seed マイグレーションに含めて migrate で一括適用）→ `docker compose up -d` → `/readyz` で起動確認。
  ロールバック方針（直前イメージへの戻し・migration は expand/contract 前提）も含める。
- **D2**: 運用向け手順書は新設せず `docs/OPERATIONS.md` に統合する。初期化（T11）・デプロイ（T13）・
  バックアップ/リストア・鍵ローテーション・初期管理ユーザーのパスワード変更などの運用手順を追記する。

> 依存関係: T10 → T11 → T13、T9 → T13、T12 → T13。D2 は各タスク完了に合わせて随時追記。
> MVP フェーズ T0〜T8・D1 はすべて完了（`docs/CHANGELOG.md` 参照）。
> 設計仕様 §10 の MVP 完了条件 1〜13 は `tests/oidc_flow.rs` の E2E テストで検証済み。
> 将来拡張の候補（Refresh Token / Consent / Client 管理 / Token 管理）は設計仕様 §9 を参照し、
> 着手時に本ファイルへタスクとして起票する。
