# scripts/

運用・ビルド・検証をワンコマンド化したシェルスクリプト群。どのディレクトリから実行しても動く
（各スクリプトが自身の位置から基準ディレクトリを解決する）。

## ホストの分離（重要）

**ソースがある「ビルド側」と、稼働する「デプロイ先」は別ホスト**を前提とする。
受け渡しは **tar（デプロイバンドル）** で行う。レジストリは不要。

| ホスト | 持つもの | 実行するもの |
|---|---|---|
| ビルド側 | Rust ソース・Dockerfile | `./scripts/build.sh` → `dist/` を出力（**起動しない**） |
| デプロイ先 | `dist/`（バンドル一式） | `./deploy.sh`（バンドル同梱。**ソース不要・ビルドしない**） |

| スクリプト | 用途 |
|---|---|
| `build.sh` | **ビルド側**: Docker イメージ（api/web/migrate）をビルドし、tar ＋ デプロイ一式を `dist/` へ出力 |
| `deploy.sh` | **デプロイ先**: デプロイの単一入口（初回・更新・migrate・reset）。`dist/` に同梱される |
| `build-remote.sh` | **デプロイ先（一ホスト方式）**: git 取得 → 自己更新 → `build.sh` → `deploy.sh` を 1 本で実行。dist/ の転送が不要 |
| `e2e.sh` | web→api の疎通 E2E（api・web を実プロセス起動して HTTP で検証） |
| `test_deploy.sh` | `deploy.sh` の CLI/エラー処理をスタブ docker で検証（CI 用） |
| `test_build_remote.sh` | `build-remote.sh` の取得・自己更新・委譲をスタブで検証（CI 用） |

## build.sh — ビルド（ビルド側・起動しない）

```bash
./scripts/build.sh                  # イメージビルド → dist/ に tar ＋ デプロイ一式を出力
IMAGE_TAG=1.0.0 ./scripts/build.sh  # イメージタグを指定（既定 latest）
./scripts/build.sh /path/to/out     # 出力先を変更（既定 dist/）
```

`dist/` の中身（＝デプロイバンドル。これだけでデプロイできる）:

```
dist/
├── idp-api.tar / idp-web.tar / idp-migrate.tar   # ビルド済みイメージ
├── docker-compose.yml                            # デプロイ用 Compose（image: 参照のみ）
├── docker/nginx.conf                             # リバースプロキシ設定
├── .env.example                                  # 設定テンプレート
├── deploy.sh                                     # デプロイ入口
└── manifest.env / manifest.sha256               # 照合用メタデータ
```

## deploy.sh — デプロイ（デプロイ先・単一入口）

```bash
./deploy.sh app      # デプロイ（初回は .env 自動生成 → イメージ読込 → migrate → 起動 → readiness 確認）
./deploy.sh migrate  # DB 起動と migrate（あれば DB 更新）後、アプリコンテナも入れ替える
./deploy.sh reset    # DB を初期化（volume 削除）してからデプロイし直す（破壊的操作）
```

- 初回実行時に `.env` を `.env.example` から自動生成し、秘密情報（DB パスワード・
  `KEY_ENCRYPTION_KEY`・`INTERNAL_SERVICE_TOKEN`・`CSRF_SECRET`）を乱数生成する。
  **既存の `.env` は上書きしない**（冪等）。環境に合わせて確認する項目は `ISSUER`（公開 URL）と
  `WEB_PORT`（公開ポート）の 2 つ。stg/prod を同一ホストに置く場合は、
  `.env.staging.example` / `.env.production.example` を `.env` にコピーし、`WEB_PORT` と `IMAGE_TAG` を
  環境ごとに分ける。
- イメージは隣の `idp-*.tar` から自動で `docker load` する（読込済みで manifest と一致すればスキップ）。
- 使う Compose ファイルは固定: バンドル内では同梱の `docker-compose.yml`、リポジトリ内から実行した
  場合はルートの `docker-compose.deploy.yml`。選択の余地はない。
- `reset` は DB volume を削除する破壊的操作（確認なしで即実行される）。`.env` は保持される。

前提: `docker`（Compose v2 または v1）と `openssl`。

## 典型的な流れ

```bash
# === ビルド側（ソースがあるホスト） ===
./scripts/build.sh
scp -r dist/ deploy-host:/opt/idp/            # 転送（例）

# === デプロイ先（別ホスト。ソース不要） ===
cd /opt/idp/dist
./deploy.sh app      # 初回も更新もこれだけ
```

更新は新しい `dist/` を上書き転送して `./deploy.sh app` を再実行する。ロールバックは前のバージョンの
`dist/` を残しておき、そこで `./deploy.sh app` を実行する。

## build-remote.sh — デプロイ先だけで完結する一ホスト方式

上の二ホスト方式（ビルド側で `build.sh` → `dist/` を転送）に対し、`build-remote.sh` は
**デプロイ先で git 取得からデプロイまでを一気通貫**で行う。デプロイ先に置くのは最初に
この 1 本だけでよく、以後の運用でスクリプト自体が更新されても、実行時に git 上の最新版へ
自分を書き換えて再実行する（自己更新）。

```bash
# === デプロイ先（Docker が動くホスト。最初に build-remote.sh を 1 本だけ配置） ===
./build-remote.sh            # app: git 取得 → 自己更新 → build.sh → deploy.sh app
./build-remote.sh migrate    # migrate を委譲
./build-remote.sh reset      # reset を委譲（破壊的）
```

- ソースを git から取得（`clone` / `fetch`）するので **`dist/` の転送は不要**。`build.sh` を
  デプロイ先で実行してイメージをローカルにビルドし、そのまま `deploy.sh` へ渡す。
- 実行のたびに git 上の `scripts/build-remote.sh` と自分を比較し、不一致なら自分を上書きして
  再実行する。取得と自己更新は初回のみで、再実行後は二重取得しない。
- 設定は環境変数（既定のままでも動く）:

  | 変数 | 既定 | 用途 |
  |---|---|---|
  | `IDP_REPO_URL` | `https://github.com/kiyoteruhosoda/idp.git` | 取得元 git URL |
  | `IDP_BRANCH` | `main` | 取得ブランチ |
  | `IDP_SRC_DIR` | `<スクリプトの場所>/src` | ソース取得先 |
  | `IMAGE_TAG` | `latest` | `build.sh` / `deploy` へ引き継ぐイメージタグ |

前提: `git` と、`build.sh` / `deploy.sh` の前提（`docker`・`openssl`）。

## e2e.sh — 疎通 E2E

```bash
TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' ./scripts/e2e.sh
```

api（DB 直結）と web（HTML 画面）を実際に別プロセスで起動し、ブラウザ相当の HTTP で
「OIDC 認可コードフロー（web ログイン経由）」と「管理コンソール（web→api JSON 管理 API）」を検証する。

前提: MariaDB が起動しマイグレーション適用済み（初期管理ユーザー seed 済み）。既定 DB は
`mysql://idp:idp@127.0.0.1:3306/idp`（`TEST_DATABASE_URL` で上書き可）。テスト用クライアント投入に
`docker exec idp-test-db` を使うため、対応する MariaDB コンテナが必要。
