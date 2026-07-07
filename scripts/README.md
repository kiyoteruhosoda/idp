# scripts/

運用・ビルド・検証をワンコマンド化したシェルスクリプト群。すべてリポジトリルートからの相対パスに
依存せず、どのディレクトリから実行しても動く（各スクリプトが自身の位置からリポジトリルートを解決する）。

## ホストの分離（重要）

**ソースがある「ビルド側」と、稼働する「デプロイ先」は別ホスト**を前提とする。

| ホスト | 持つもの | 実行するスクリプト |
|---|---|---|
| ビルド側 | Rust ソース・Dockerfile | `build.sh`（イメージ作成→push / tar 保存。**起動しない**） |
| デプロイ先 | イメージ＋配置バンドル<br>（`docker-compose.deploy.yml`・`docker/nginx.conf`・`scripts/`・`.env`） | `init.sh`（初回）・`deploy.sh`（更新）。**ソース不要・ビルドしない** |

イメージ（`${IMAGE_PREFIX:-idp}/{api,web,migrate}:${IMAGE_TAG:-latest}`）の受け渡しは 2 通り:

- **レジストリ配布**: `IMAGE_PREFIX` にレジストリホストを含める（例 `registry.example.com/idp`）。
  ビルド側で `build.sh --docker --push`、デプロイ先で `init.sh`/`deploy.sh` が自動 `pull`。
- **tar 配布**（レジストリ不要）: ビルド側で `build.sh --docker --save ./dist` → `dist/*.tar` を転送 →
  デプロイ先で `docker load -i` してから `init.sh`/`deploy.sh`。

| スクリプト | 用途 | 単体実行 |
|---|---|---|
| `build.sh` | **ビルド側**: ソースから成果物をビルド（binary / Docker イメージ）。起動しない。 | ○ |
| `init.sh` | **デプロイ先**: 初回の配置＋初期化（`.env` 生成 → イメージ確認 → **DB コンテナ新規作成** → マイグレーション → 起動）。冪等。 | ○ |
| `deploy.sh` | **デプロイ先**: 更新デプロイ（イメージ取得 → マイグレーション → 再起動 → readiness 確認）。 | ○ |
| `e2e.sh` | web→api の疎通 E2E（api・web を実プロセス起動して HTTP で検証）。 | ○ |
| `lib.sh` | 上記が共有するヘルパ（ログ・Compose 判定・`.env` 操作・healthy 待ち・イメージ名/確認）。 | ✗（`source` 専用） |

前提となるツールは各スクリプトのヘッダコメントに記載している。

---

## build.sh — ビルド（ビルド側・起動しない）

```bash
./scripts/build.sh                     # ネイティブ release binary（target/release/idp・idp-web）
./scripts/build.sh --check             # fmt チェック・clippy（-D warnings）・test を実行してからビルド
./scripts/build.sh --docker            # Docker イメージ（api / web / migrate）をビルド＆タグ付け
./scripts/build.sh --docker --push     # ビルド後レジストリへ push（IMAGE_PREFIX にホストを含めること）
./scripts/build.sh --docker --save ./dist   # ビルド後 dist/*.tar へ保存（レジストリ不要の受け渡し）
./scripts/build.sh --help
```

| オプション | 効果 |
|---|---|
| （なし） | `cargo build --release --locked --bin idp --bin idp-web` |
| `--docker` | `docker build` で 3 イメージをビルドし `${IMAGE_PREFIX}/…:${IMAGE_TAG}` にタグ付け |
| `--push` | `--docker` 後にレジストリへ push |
| `--save DIR` | `--docker` 後に `docker save` で `DIR/*.tar` を書き出す |
| `--check` | ビルド前に `cargo fmt --check` → `cargo clippy -D warnings` → `cargo test` |

**コンテナを起動しない**（配置は init/deploy の役割）。前提: ネイティブは `cargo`（rustup）、Docker は `docker`。

## init.sh — 初回の配置＋初期化（デプロイ先）

```bash
./scripts/init.sh
```

デプロイ先で初回の配置と初期化をこれ 1 本で行う（冪等）。この時点では DB もアプリも存在しないことを
前提とし、ソースを持たずに（＝ビルドせずに）必要なものを作る。

- `.env` が無ければ `.env.example` を基に生成し、秘密情報（DB パスワード・`KEY_ENCRYPTION_KEY`・
  `INTERNAL_SERVICE_TOKEN`）を乱数生成する。**既存の `.env` は上書きしない**（冪等）。
- ビルド済みイメージ（api/web/migrate）を確認する（無ければ `pull`。tar 配布時は事前に `docker load` 済みが前提）。
- `mariadb` **コンテナを新規作成**して起動する（`init` の時点ではまだ DB は無い）。
- マイグレーション（DDL + マスタデータ）を `docker compose run --rm migrate` で適用する。
- api・web・proxy を起動する。
- 完了後、ログイン/管理コンソール・Swagger UI の URL と初期管理ユーザーを表示する。

前提: `docker`（Compose v2）と `openssl`。Rust ソースは不要。2 回目以降の更新は `deploy.sh` を使う。

## deploy.sh — 更新デプロイ（デプロイ先・2 回目以降）

```bash
./scripts/deploy.sh
```

1. ビルド済みイメージの取得（`pull`。tar 配布時は `docker load` 済みを確認。**ビルドはしない**）
2. DDL + マスタデータ適用（`sqlx migrate run` を単独ジョブで実行）
3. api・web・proxy を再起動（`docker compose up -d`）
4. `/readyz`（プロキシ経由 = api の readiness）で起動確認

**前提: 事前に `init.sh` を実行済み（`.env` が存在する）こと。** ロールバックは `IMAGE_TAG` を前の
バージョンに戻して再実行。詳細はスクリプト冒頭コメントおよび `docs/OPERATIONS.md`「ロールバックしたいとき」。

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
# === ビルド側（ソースがあるホスト） ===
# 例1: レジストリ配布
IMAGE_PREFIX=registry.example.com/idp IMAGE_TAG=1.0.0 ./scripts/build.sh --check --docker --push
# 例2: tar 配布（レジストリ不要）
./scripts/build.sh --check --docker --save ./dist
scp dist/*.tar deploy-host:/opt/idp/dist/        # 転送（例）

# === デプロイ先（別ホスト。ソース不要） ===
# tar 配布のときは先に読み込む:
for t in /opt/idp/dist/*.tar; do docker load -i "$t"; done

# 初回（.env 生成・DB コンテナ新規作成・マイグレーション・起動）
./scripts/init.sh
# 2 回目以降（更新デプロイ）
./scripts/deploy.sh
```

レジストリ配布なら、デプロイ先で `IMAGE_PREFIX`/`IMAGE_TAG` を `.env` に設定すれば `init.sh`/`deploy.sh` が
自動で `pull` する。CI/ローカルでの疎通確認が必要なときは `./scripts/e2e.sh` を追加で実行する。
