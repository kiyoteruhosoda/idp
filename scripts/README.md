# scripts/

運用・ビルド・検証をワンコマンド化したシェルスクリプト群。すべてリポジトリルートからの相対パスに
依存せず、どのディレクトリから実行しても動く（各スクリプトが自身の位置からリポジトリルートを解決する）。

| スクリプト | 用途 | 単体実行 |
|---|---|---|
| `build.sh` | ソースから成果物をビルド（ネイティブ binary または Docker イメージ）・任意で検証。 | ○ |
| `init.sh` | **初回の配置＋初期化**（`.env` 生成 → イメージビルド → **DB コンテナ新規作成** → マイグレーション → 起動）。冪等。 | ○ |
| `deploy.sh` | **2 回目以降の更新デプロイ**（イメージ再ビルド → マイグレーション → 再起動 → readiness 確認）。 | ○ |
| `e2e.sh` | web→api の疎通 E2E（api・web を実プロセス起動して HTTP で検証）。 | ○ |
| `lib.sh` | 上記が共有するヘルパ（ログ・Compose コマンド判定・`.env` 操作・healthy 待ち）。 | ✗（`source` 専用） |

**ライフサイクル**: 最初は**ソースだけ**の状態から始まる。`init.sh`（初回）と `deploy.sh`（更新）が
Compose のイメージ（api / web / migrate）を**自前でビルド**し、DB は `mariadb` コンテナとして
`init.sh` 実行時に**新規作成される**（事前に用意しておく必要はない）。`build.sh` は成果物の単体ビルドと
デプロイ前検証（`--check`）に使う独立したツールで、`init.sh` / `deploy.sh` の前提ではない。

前提となるツールは各スクリプトのヘッダコメントに記載している。

---

## build.sh — ビルド（ソース → 成果物）

```bash
./scripts/build.sh            # ネイティブ release binary（target/release/idp・idp-web）
./scripts/build.sh --check    # fmt チェック・clippy（-D warnings）・test を実行してからビルド
./scripts/build.sh --docker   # Docker イメージ（api / web / migrate）を compose でビルド
./scripts/build.sh --check --docker
./scripts/build.sh --help
```

| オプション | 効果 |
|---|---|
| （なし） | `cargo build --release --locked --bin idp --bin idp-web` |
| `--docker` | `docker compose build api web migrate` |
| `--check` | ビルド前に `cargo fmt --check` → `cargo clippy -D warnings` → `cargo test` |

主にデプロイ前の検証（`--check`）や、成果物を単体で得たいときに使う。**なお `init.sh` / `deploy.sh` は
Compose のイメージを自前でビルドするため、配置の前に `build.sh` を実行する必要はない**（検証したい場合のみ）。

前提: ネイティブビルドは `cargo`（rustup）。Docker ビルドは `docker`（Compose v2）。

## init.sh — 初回の配置＋初期化

```bash
./scripts/init.sh
```

**ソースだけの状態から、初回の配置と初期化をこれ 1 本で行う**（冪等）。この時点では DB もアプリイメージも
存在しないことを前提とし、必要なものをすべて作る。

- `.env` が無ければ `.env.example` を基に生成し、秘密情報（DB パスワード・`KEY_ENCRYPTION_KEY`・
  `INTERNAL_SERVICE_TOKEN`）を乱数生成する。**既存の `.env` は上書きしない**（冪等）。
- `mariadb` **コンテナを新規作成**して起動する（`init` の時点ではまだ DB は存在しない）。
- migrate ジョブのイメージをビルドし、マイグレーション（DDL + マスタデータ）を
  `docker compose run --rm migrate` で適用する。
- api・web・proxy のイメージをビルドして起動する（`up -d --build`）。
- 完了後、ログイン/管理コンソール・Swagger UI の URL と初期管理ユーザーを表示する。

前提: `docker`（Compose v2）と `openssl`。2 回目以降の更新は `init.sh` ではなく `deploy.sh` を使う。

## deploy.sh — 更新デプロイ（2 回目以降）

```bash
./scripts/deploy.sh
```

1. イメージビルド（api / web / migrate）
2. DDL + マスタデータ適用（`sqlx migrate run` を単独ジョブで実行）
3. api・web・proxy を再起動（`docker compose up -d`）
4. `/readyz`（プロキシ経由 = api の readiness）で起動確認

**前提: 事前に `init.sh` を実行済み（`.env` が存在する）こと。** ロールバック方針はスクリプト冒頭の
コメントおよび `docs/OPERATIONS.md`「ロールバックしたいとき」を参照。

## e2e.sh — 疎通 E2E

```bash
TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' ./scripts/e2e.sh
```

api（DB 直結）と web（HTML 画面）を実際に別プロセスで起動し、ブラウザ相当の HTTP で
「OIDC 認可コードフロー（web ログイン経由）」と「管理コンソール（web→api JSON 管理 API）」を検証する。

前提: MariaDB が起動しマイグレーション適用済み（初期管理ユーザー seed 済み）。既定 DB は
`mysql://idp:idp@127.0.0.1:3306/idp`（`TEST_DATABASE_URL` で上書き可）。テスト用クライアント投入に
`docker exec idp-test-db` を使うため、対応する MariaDB コンテナが必要。

---

## 典型的な流れ

```bash
# === 初回（ソースだけの状態から） ===
# 1. （任意）ソースを検証する
./scripts/build.sh --check

# 2. 初回の配置＋初期化: .env 生成 → イメージビルド → DB コンテナ新規作成 → マイグレーション → 起動
#    ※ DB はこの init で作られる（事前に用意しておく必要はない）
./scripts/init.sh

# === 2 回目以降（更新デプロイ） ===
# 3. イメージ再ビルド → マイグレーション → 再起動 → readiness 確認
./scripts/deploy.sh
```

CI/ローカルでの疎通確認が必要なときは `./scripts/e2e.sh` を追加で実行する。
