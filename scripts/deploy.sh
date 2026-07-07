#!/usr/bin/env bash
# scripts/deploy.sh — 同一ホストの Docker Compose へデプロイする。
#
#   1. イメージビルド（api / web / migrate）
#   2. DDL + マスタデータ適用（専用ジョブ = sqlx migrate run を単独実行）
#   3. api・web・proxy を再起動（docker compose up -d）
#   4. /readyz で起動確認（プロキシ経由 = api の readiness）
#
# 前提: 事前に scripts/init.sh を実行済み（.env が存在する）こと。
#
# ロールバック方針:
#   - アプリ: 直前イメージへ戻す（イメージにタグ運用しているなら該当タグで up -d、
#     未タグ運用なら 1 つ前のコミットを checkout して再ビルド）。
#   - スキーマ: migration は expand/contract 前提のため、直前バージョンのアプリは新スキーマ上でも
#     動作する（破壊的変更は contract フェーズを分離）。DDL の巻き戻しが必要な場合のみ
#     `docker compose run --rm --entrypoint sqlx migrate migrate revert --source /migrate/migrations`。
#   詳細な手順は docs/OPERATIONS.md「ロールバックしたいとき」を参照。
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
source "$repo_root/scripts/lib.sh"

env_file="$repo_root/.env"
[[ -f "$env_file" ]] || die ".env がありません。先に scripts/init.sh を実行してください。"

compose="$(compose_cmd)"

# --- 1. イメージビルド ---------------------------------------------------------
log "イメージをビルドします（api / web / migrate）..."
$compose build api web migrate

# --- 2. DDL + マスタデータ適用（専用ジョブ） -----------------------------------
log "MariaDB を起動します..."
$compose up -d mariadb
wait_healthy "$compose" mariadb
log "マイグレーションを適用します..."
$compose run --rm migrate

# --- 3. api・web・proxy 再起動 --------------------------------------------------
log "api・web・proxy を再起動します..."
$compose up -d api web proxy
wait_healthy "$compose" api
wait_healthy "$compose" web

# --- 4. /readyz で起動確認（プロキシ経由 = api の readiness） -------------------
web_port="$(get_env_var WEB_PORT "$env_file")"
web_port="${web_port:-8080}"
ready_url="http://127.0.0.1:${web_port}/readyz"
log "readiness を確認します: $ready_url"
for i in $(seq 1 30); do
  if curl -fsS "$ready_url" >/dev/null 2>&1; then
    log "readyz OK。デプロイが完了しました。"
    exit 0
  fi
  sleep 2
done
die "readyz が OK になりませんでした。ログ: $compose logs api web proxy"
