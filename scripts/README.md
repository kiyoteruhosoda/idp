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
| `deploy.sh` | **デプロイ先**: デプロイの単一入口（初回・更新・migration・reset）。`dist/` に同梱される |
| `e2e.sh` | web→api の疎通 E2E（api・web を実プロセス起動して HTTP で検証） |
| `test_deploy.sh` | `deploy.sh` の CLI/エラー処理をスタブ docker で検証（CI 用） |

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
./deploy.sh              # デプロイ（初回は .env 自動生成 → イメージ読込 → migration → 起動 → readiness 確認）
./deploy.sh migration    # DB 起動と migration（あれば DB 更新）のみ
./deploy.sh reset --yes  # DB を初期化（volume 削除）してからデプロイし直す
```

- 初回実行時に `.env` を `.env.example` から自動生成し、秘密情報（DB パスワード・
  `KEY_ENCRYPTION_KEY`・`INTERNAL_SERVICE_TOKEN`・`CSRF_SECRET`）を乱数生成する。
  **既存の `.env` は上書きしない**（冪等）。環境に合わせて確認する項目は `ISSUER`（公開 URL）と
  `WEB_PORT`（公開ポート）の 2 つ。詳細は `.env` 内コメント参照。
- イメージは隣の `idp-*.tar` から自動で `docker load` する（読込済みで manifest と一致すればスキップ）。
- 使う Compose ファイルは固定: バンドル内では同梱の `docker-compose.yml`、リポジトリ内から実行した
  場合はルートの `docker-compose.deploy.yml`。選択の余地はない。
- `reset` は DB volume を削除する破壊的操作のため `--yes` が必須。`.env` は保持される。

前提: `docker`（Compose v2 または v1）と `openssl`。

## 典型的な流れ

```bash
# === ビルド側（ソースがあるホスト） ===
./scripts/build.sh
scp -r dist/ deploy-host:/opt/idp/            # 転送（例）

# === デプロイ先（別ホスト。ソース不要） ===
cd /opt/idp/dist
./deploy.sh          # 初回も更新もこれだけ
```

更新は新しい `dist/` を上書き転送して `./deploy.sh` を再実行する。ロールバックは前のバージョンの
`dist/` を残しておき、そこで `./deploy.sh` を実行する。

## e2e.sh — 疎通 E2E

```bash
TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' ./scripts/e2e.sh
```

api（DB 直結）と web（HTML 画面）を実際に別プロセスで起動し、ブラウザ相当の HTTP で
「OIDC 認可コードフロー（web ログイン経由）」と「管理コンソール（web→api JSON 管理 API）」を検証する。

前提: MariaDB が起動しマイグレーション適用済み（初期管理ユーザー seed 済み）。既定 DB は
`mysql://idp:idp@127.0.0.1:3306/idp`（`TEST_DATABASE_URL` で上書き可）。テスト用クライアント投入に
`docker exec idp-test-db` を使うため、対応する MariaDB コンテナが必要。
