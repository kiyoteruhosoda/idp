# scripts/

運用・ビルド・検証をワンコマンド化したシェルスクリプト群。各スクリプトは基準ディレクトリ
（`.env`・Compose・`dist/` の置き場所）を、**実行時のカレントディレクトリ(`$PWD`)ではなく
「スクリプトファイル自身の置き場所」**から解決する（`build-remote-container.sh` は `IDP_TARGET_DIR` で明示上書き可）。

- 利点: 事前に `cd` しなくても、フルパスで呼べば常に正しい基準で動く。
- 注意: **`cd` してもデプロイ対象は変わらない。対象は「どの場所にあるスクリプト実体を実行したか」で決まる。**
  例えば `cd stg` してから本番ディレクトリにあるスクリプト実体を呼ぶと、本番の `.env` が使われる。
  stg/prod を同一ホストに分ける運用は下記「stg/prod を同一ホストに置く」を参照。

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
| `build-remote.sh` | **デプロイ先（一ホスト方式・git あり）**: git 取得 → 自己更新 → `build.sh` → `deploy.sh` を 1 本で実行。dist/ の転送が不要 |
| `build-remote-container.sh` | **デプロイ先（一ホスト方式・git 無し）**: dev コンテナ内で `git pull` → `build.sh` → 生成 `dist/` を取り込み → `deploy.sh` を 1 本で実行。Synology 等 git 非搭載向け（旧 `pick.sh` を統合） |
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
  `WEB_PORT`（公開ポート）の 2 つ。
- イメージは隣の `idp-*.tar` から自動で `docker load` する（読込済みで manifest と一致すればスキップ）。
- 使う Compose ファイルは固定: バンドル内では同梱の `docker-compose.yml`、リポジトリ内から実行した
  場合はルートの `docker-compose.deploy.yml`。選択の余地はない。
- `reset` は DB volume を削除する破壊的操作（確認なしで即実行される）。`.env` は保持される。
- MariaDB 起動後・migration 前に**アプリ用ユーザーの認証**を検証する。`Access denied for user 'idp'` で
  停止した場合は、`.env` の `MARIADB_PASSWORD` が既存 DB volume（初回作成時のパスワードで固定）と不一致。
  データを破棄してよければ `./deploy.sh reset` で volume を作り直し、保持したければ `.env` のパスワードを
  volume 作成時の値へ戻す（MariaDB は初回以降 `.env` の変更を既存 volume へ反映しない）。

前提: `docker`（Compose v2 または v1）と `openssl`。

## stg/prod を同一ホストに置く

基準ディレクトリは**スクリプト実体の置き場所**で決まる（冒頭「基準ディレクトリの解決」参照）。
したがって stg/prod を同一ホストで分ける場合は、**環境ごとに別ディレクトリを用意し、その中に
デプロイ一式（`deploy.sh` ＝ `dist/` のバンドル）と、その環境の `.env`（＋一ホスト方式なら
`build-remote-container.sh` と `build-remote-container.env`）を置く**。

```
/opt/idp/
├── stg/    deploy.sh + build-remote-container.sh + build-remote-container.env + .env  # COMPOSE_PROJECT_NAME=idp-stg
└── prod/   deploy.sh + build-remote-container.sh + build-remote-container.env + .env  # COMPOSE_PROJECT_NAME=idp-prod
```

**ディレクトリ名で環境を自動判定する。** ディレクトリ名が `stg`/`staging`/`*-stg`（stg 系）または
`prod`/`production`/`*-prod`（prod 系）なら、初回の `.env` 未作成時に **`deploy.sh` がそのディレクトリの
`.env.staging.example` / `.env.production.example` を生成元に選び**（`WEB_PORT`・`IMAGE_TAG`・
`COMPOSE_PROJECT_NAME` が環境ごとに分離済み）、秘密情報（`CHANGE-ME`）は乱数で自動生成する。
`build-remote-container.sh` も同じ規則で初回のビルドタグ（`stg`/`prod`）を決めるため、
「`latest` でビルド → `.env` は `stg` を要求 → イメージ不一致」は起きない。上記に当てはまらない名前の
ディレクトリは汎用 `.env.example`（`WEB_PORT=8060`・`IMAGE_TAG=latest`）にフォールバックする。

```
/opt/idp/
├── stg/    …ディレクトリ名 stg → .env.staging.example から生成（COMPOSE_PROJECT_NAME=idp-stg, WEB_PORT=8061, IMAGE_TAG=stg）
└── prod/   …ディレクトリ名 prod → .env.production.example から生成（COMPOSE_PROJECT_NAME=idp-prod, WEB_PORT=8060, IMAGE_TAG=prod）
```

**各環境ディレクトリで必要な設定**:

1. **`.env.staging.example` / `.env.production.example`** をそのディレクトリに置く（`dist/` バンドルに同梱。
   `build.sh` が出力する）。初回デプロイ時に `deploy.sh` がこれを生成元にして `.env` を作り、秘密を乱数生成する。
   - デプロイ後、生成された `.env` の **`ISSUER`（既定 `http://localhost:<port>`）を外部公開ホスト名/IP に合わせる**。
   - `.env` を**自分で先に作る**場合（`cp .env.staging.example .env`）は、`deploy.sh` が既存 `.env` を上書きせず
     秘密も生成しないため、**`CHANGE-ME`（`MARIADB_PASSWORD`・`KEY_ENCRYPTION_KEY`・`INTERNAL_SERVICE_TOKEN`・
     `CSRF_SECRET` 等）を必ず実値に置換する**。プレースホルダのままだと base64 不正で API/web が起動しない。
2. **`build-remote-container.env`**（一ホスト方式のみ）: `IDP_DIST_DIR`（必須。ホストから見える
   ビルド済み `dist/` の絶対パス）等を書く。無いと `IDP_DIST_DIR` 未設定で `build-remote-container.sh` が
   即エラー終了する（`build-remote-container.sh:110`）。環境変数で `IDP_DIST_DIR=...` を直接渡してもよい。

デプロイ対象の選び方（どちらか。**`cd` だけでは対象は切り替わらない**）:

```bash
# 1) その環境ディレクトリにある“その環境のコピー”を実行する（build-remote-container.env も同ディレクトリで読む）
cd /opt/idp/stg && ./build-remote-container.sh app     # → stg/.env を使用
cd /opt/idp/prod && ./build-remote-container.sh app    # → prod/.env を使用

# 2) IDP_TARGET_DIR で対象を明示する（build-remote-container.sh のみ）
IDP_TARGET_DIR=/opt/idp/stg IDP_DIST_DIR=/path/to/dist /opt/idp/prod/build-remote-container.sh app  # → stg/.env
```

`cd /opt/idp/stg` してから `../prod/build-remote-container.sh` のように**別ディレクトリの実体**を
呼ぶと、`IDP_TARGET_DIR` 未指定なら基準は prod になり **prod の `.env` が使われる**（`cd` は無視される）。
同様に、シェルに `IDP_TARGET_DIR` が export 済みだとスクリプト位置より優先される点にも注意。

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
