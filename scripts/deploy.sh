#!/usr/bin/env bash
# scripts/deploy.sh — デプロイ先の単一入口（app / migration / reset）。
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
source "$repo_root/scripts/lib.sh"

env_file="$repo_root/.env"
example_file="$repo_root/.env.example"
compose="$(compose_cmd) -f $DEPLOY_COMPOSE_FILE"
DEPLOY_COMPOSE="$compose"
trap 'on_deploy_error $? $LINENO "$BASH_COMMAND"' ERR

usage() {
  cat >&2 <<USAGE
Usage: $0 <app|migration|reset> [--yes]

  app        DB を保持して migration（必要時）後に api/web/proxy を更新します。
  migration  DB 起動と migration のみ実行します。
  reset      --yes 必須。DB volume を削除し、migration と app 起動をやり直します。
USAGE
}

mode="${1:-}"
[[ -n "$mode" ]] || { usage; exit 2; }
shift || true
case "$mode" in
  app|migration|reset) ;;
  *) usage; exit 2 ;;
esac

yes=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes) yes=1 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
  shift
done

[[ -f "$repo_root/$DEPLOY_COMPOSE_FILE" ]] || die "$DEPLOY_COMPOSE_FILE がありません（デプロイ用 compose）。"
command -v docker >/dev/null 2>&1 || die "docker が見つかりません。"

phase_begin "env"
ensure_env_file "$env_file" "$example_file"
phase_end

run_migration() {
  phase_begin "migration"
  log "MariaDB を起動します..."
  $compose up -d mariadb
  wait_healthy "$compose" mariadb
  log "マイグレーションを適用します..."
  $compose run --rm migrate
  phase_end
}

root_tenant_id() {
  local db_user db_name db_password
  db_user="$(get_env_var MARIADB_USER "$env_file")"
  db_name="$(get_env_var MARIADB_DATABASE "$env_file")"
  db_password="$(get_env_var MARIADB_PASSWORD "$env_file")"
  $compose exec -T mariadb mariadb -u"${db_user:-idp}" -p"$db_password" "${db_name:-idp}" -N -B \
    -e 'SELECT id FROM tenants WHERE parent_tenant_id IS NULL' 2>/dev/null || true
}

run_app() {
  local web_port issuer root login_url ready_url
  phase_begin "image-check"
  log "ビルド済みイメージを確認します（無ければ pull）..."
  ensure_images
  phase_end
  run_migration
  phase_begin "app"
  log "api・web・proxy を起動します..."
  $compose up -d api web proxy
  wait_healthy "$compose" api
  wait_healthy "$compose" web
  web_port="$(get_env_var WEB_PORT "$env_file")"
  web_port="${web_port:-8080}"
  issuer="$(get_env_var ISSUER "$env_file")"
  issuer="${issuer:-http://localhost:${web_port}}"
  ready_url="http://127.0.0.1:${web_port}/readyz"
  log "readiness を確認します: $ready_url"
  for _ in $(seq 1 30); do
    if curl -fsS "$ready_url" >/dev/null 2>&1; then
      root="$(root_tenant_id)"
      login_url="${issuer%/}/${root:-<root-tenant-id>}/login"
      log "readyz OK。デプロイが完了しました。"
      log "ログイン URL: $login_url"
      phase_end
      return 0
    fi
    sleep 2
  done
  compose_diagnostics
  die "readyz が OK になりませんでした。"
}

case "$mode" in
  migration)
    phase_begin "image-check"
    log "ビルド済み migrate イメージを確認します（無ければ pull）..."
    ensure_image migrate
    phase_end
    run_migration
    ;;
  app)
    run_app
    ;;
  reset)
    [[ $yes -eq 1 ]] || die "reset は破壊的操作です。実行するには --yes を付けてください。"
    project="$($compose config --format json 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("name", "idp"))' 2>/dev/null || basename "$repo_root")"
    phase_begin "reset"
    log "reset 対象 Compose project: $project"
    log "DB volume と DB 管理設定を削除します（.env のオペレーター固定領域は保持します）。"
    $compose down -v --remove-orphans
    phase_end
    run_app
    ;;
esac
