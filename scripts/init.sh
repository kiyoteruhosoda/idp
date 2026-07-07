#!/usr/bin/env bash
# scripts/init.sh — db・web をこれ 1 本で初期化する（冪等）。
#
#   1. 秘密情報（DB パスワード・KEY_ENCRYPTION_KEY）を乱数生成して .env を作成
#      （既存 .env があれば上書きしない ＝ 冪等）。
#   2. MariaDB を起動して healthy を待つ。
#   3. マイグレーション（DDL + マスタデータ）を専用ジョブで適用。
#   4. web をビルド・起動して /healthz を待つ。
#
# 前提: docker（Compose v2）と openssl。sqlx-cli はコンテナ側にあるためホストには不要。
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

source "$repo_root/scripts/lib.sh"

env_file="$repo_root/.env"
example_file="$repo_root/.env.example"

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
  set_env_var MARIADB_PASSWORD      "$db_password"                                      "$env_file"
  set_env_var MARIADB_ROOT_PASSWORD "$root_password"                                    "$env_file"
  set_env_var KEY_ENCRYPTION_KEY    "$key_encryption_key"                               "$env_file"
  set_env_var INTERNAL_SERVICE_TOKEN "$internal_service_token"                          "$env_file"
  set_env_var DATABASE_URL          "mysql://idp:${db_password}@127.0.0.1:3306/idp"     "$env_file"
  set_env_var TEST_DATABASE_URL     "mysql://idp:${db_password}@127.0.0.1:3306/idp"     "$env_file"
  chmod 600 "$env_file"
  log ".env を生成しました（パーミッション 600）。"
fi

compose="$(compose_cmd)"

# --- 2. MariaDB 起動 -----------------------------------------------------------
log "MariaDB を起動します..."
$compose up -d mariadb
wait_healthy "$compose" mariadb

# --- 3. マイグレーション適用（DDL + マスタデータ） -----------------------------
log "マイグレーションを適用します（専用ジョブ）..."
$compose build migrate
$compose run --rm migrate

# --- 4. api・web・proxy 起動 ----------------------------------------------------
log "api・web・proxy をビルド・起動します..."
$compose up -d --build api web proxy
wait_healthy "$compose" api
wait_healthy "$compose" web

log "初期化が完了しました。"
log "  - IdP（プロキシ経由）: ${ISSUER:-http://localhost:8080}"
log "  - Swagger UI:          ${ISSUER:-http://localhost:8080}/api/docs"
log "  - ログイン/管理コンソール: ${ISSUER:-http://localhost:8080}/admin/console"
log "  - 初期管理ユーザー: admin@example.com（既定パスワードは初回ログイン後に変更すること）"
