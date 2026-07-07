#!/usr/bin/env bash
# scripts/init.sh — デプロイ先で初回の配置＋初期化を行う（冪等）。
#
#   1. 秘密情報（DB パスワード・KEY_ENCRYPTION_KEY 等）を乱数生成して .env を作成
#      （既存 .env があれば上書きしない ＝ 冪等）。
#   2. ビルド済みイメージ（api/web/migrate）の存在を確認（無ければ pull。ここではビルドしない）。
#   3. MariaDB コンテナを新規作成して healthy を待つ（init の時点ではまだ DB は存在しない）。
#   4. マイグレーション（DDL + マスタデータ）を専用ジョブで適用する。
#   5. api・web・proxy を起動して healthy を待つ。
#
# 前提:
#   - デプロイ先とソースは別ホスト。イメージはソース側の scripts/build.sh で作成し、レジストリ push か
#     tar 転送（docker load）で本ホストへ用意しておくこと（本スクリプトはビルドしない）。
#   - docker（Compose v2）と openssl。デプロイ先に必要なのは docker-compose.deploy.yml・docker/nginx.conf・
#     scripts・.env（本スクリプトが生成）で、Rust ソースは不要。
#   - 2 回目以降の更新は init.sh ではなく deploy.sh を使う。
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

source "$repo_root/scripts/lib.sh"

env_file="$repo_root/.env"
example_file="$repo_root/.env.example"
[[ -f "$repo_root/$DEPLOY_COMPOSE_FILE" ]] || die "$DEPLOY_COMPOSE_FILE がありません（デプロイ用 compose）。"

# --- 1. .env 生成（冪等） -------------------------------------------------------
if [[ -f "$env_file" ]]; then
  log "既存の .env を使用します（上書きしません）。"
else
  log ".env を新規生成します（秘密情報を乱数生成）。"
  [[ -f "$example_file" ]] || die ".env.example が見つかりません。"

  db_password="$(openssl rand -hex 24)"
  root_password="$(openssl rand -hex 24)"
  key_encryption_key="$(openssl rand -base64 32)"
  internal_service_token="$(openssl rand -hex 32)"

  cp "$example_file" "$env_file"
  set_env_var MARIADB_PASSWORD       "$db_password"                                  "$env_file"
  set_env_var MARIADB_ROOT_PASSWORD  "$root_password"                                "$env_file"
  set_env_var KEY_ENCRYPTION_KEY     "$key_encryption_key"                           "$env_file"
  set_env_var INTERNAL_SERVICE_TOKEN "$internal_service_token"                       "$env_file"
  set_env_var DATABASE_URL           "mysql://idp:${db_password}@127.0.0.1:3306/idp" "$env_file"
  set_env_var TEST_DATABASE_URL      "mysql://idp:${db_password}@127.0.0.1:3306/idp" "$env_file"
  chmod 600 "$env_file"
  log ".env を生成しました（パーミッション 600）。"
fi

# デプロイ先ではソースを持たない image 参照専用の compose を使う（build: を持たない）。
compose="$(compose_cmd) -f $DEPLOY_COMPOSE_FILE"

# --- 2. イメージ確認（ビルドはしない） -----------------------------------------
command -v docker >/dev/null 2>&1 || die "docker が見つかりません。"
log "ビルド済みイメージを確認します（無ければ pull）..."
ensure_images

# --- 3. MariaDB コンテナを新規作成 ---------------------------------------------
log "MariaDB コンテナを作成・起動します..."
$compose up -d mariadb
wait_healthy "$compose" mariadb

# --- 4. マイグレーション適用（DDL + マスタデータ） -----------------------------
log "マイグレーションを適用します（専用ジョブ）..."
$compose run --rm migrate

# --- 5. api・web・proxy 起動 ----------------------------------------------------
log "api・web・proxy を起動します..."
$compose up -d api web proxy
wait_healthy "$compose" api
wait_healthy "$compose" web

log "初期化が完了しました。"
log "  - IdP（プロキシ経由）: ${ISSUER:-http://localhost:8080}"
log "  - Swagger UI:          ${ISSUER:-http://localhost:8080}/api/docs"
log "  - ログイン/管理コンソール: ${ISSUER:-http://localhost:8080}/admin/console"
log "  - 初期管理ユーザー: admin@example.com（既定パスワードは初回ログイン後に変更すること）"
