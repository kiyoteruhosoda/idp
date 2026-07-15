#!/usr/bin/env bash
# deploy.sh — デプロイ先の単一入口（app / migrate / reset）。
#
# 使い方（モード引数は必須）:
#   ./deploy.sh app      通常デプロイ（migration を冪等に適用し、アプリコンテナを必ず入れ替える）
#   ./deploy.sh migrate  DDL 更新時（migration 適用後、アプリコンテナも必ず入れ替える）
#   ./deploy.sh reset    DB 初期化（volume 削除）後、migration 適用とアプリコンテナ入れ替えを行う
#
# 前提: docker（Compose v2 または docker-compose v1）と openssl。ソース不要・ビルドしない。
set -Eeuo pipefail

log() { printf '\033[36m[idp:deploy]\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[33m[idp:deploy][warn]\033[0m %s\n' "$*" >&2; }
err() { printf '\033[31m[idp:deploy][error]\033[0m %s\n' "$*" >&2; }
die() { err "$*"; exit 1; }

usage() {
  sed -n '2,10p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$script_dir/docker-compose.yml" ]]; then
  base="$script_dir"
  compose_file="docker-compose.yml"
  dist_dir="$script_dir"
else
  base="$(cd "$script_dir/.." && pwd)"
  compose_file="docker-compose.deploy.yml"
  dist_dir="$base/dist"
fi
cd "$base"
[[ -f "$base/$compose_file" ]] || die "$compose_file がありません（デプロイ用 Compose）。"

env_file="$base/.env"
example_file="$base/.env.example"

mode="${1:-}"
case "$mode" in
  app|migrate|reset) ;;
  -h|--help) usage; exit 0 ;;
  *) usage; exit 2 ;;
esac
[[ $# -eq 1 ]] || { usage; exit 2; }

command -v docker >/dev/null 2>&1 || die "docker が見つかりません。"
if docker compose version >/dev/null 2>&1; then
  compose=(docker compose -f "$compose_file")
elif command -v docker-compose >/dev/null 2>&1; then
  compose=(docker-compose -f "$compose_file")
else
  die "docker compose（v2）または docker-compose（v1）が見つかりません。"
fi

if ! docker info >/dev/null 2>&1; then
  die "Docker daemon に接続できません（daemon 停止または権限不足）。docker info が成功する状態で再実行してください。"
fi

CURRENT_PHASE="startup"
PHASE_STARTED_AT=0
APP_SERVICES=(api web proxy)
DIAGNOSTIC_SERVICES=(mariadb migrate api web proxy)

get_env_var() {
  local key="$1"
  [[ -f "$env_file" ]] || return 0
  grep -E "^${key}=" "$env_file" 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' || true
}

mask_secrets() {
  local sed_expr=() key value
  if [[ -f "$env_file" ]]; then
    for key in MARIADB_PASSWORD MARIADB_ROOT_PASSWORD KEY_ENCRYPTION_KEY INTERNAL_SERVICE_TOKEN CSRF_SECRET; do
      value="$(get_env_var "$key" 2>/dev/null || true)"
      [[ -n "$value" ]] && sed_expr+=(-e "s|${value//|/\\|}|***MASKED***|g")
    done
  fi
  if [[ ${#sed_expr[@]} -gt 0 ]]; then sed "${sed_expr[@]}"; else cat; fi
}

phase_begin() { CURRENT_PHASE="$1"; PHASE_STARTED_AT="$(date +%s)"; log "▶ $CURRENT_PHASE を開始します"; }
phase_end() { log "✓ $CURRENT_PHASE が完了しました ($(($(date +%s) - PHASE_STARTED_AT))s)"; }

diagnostic_service_block() {
  local service="$1" cid image status
  cid="$("${compose[@]}" ps -q "$service" 2>/dev/null || true)"
  [[ -n "$cid" ]] || { echo "[idp][diagnostic] service=$service container=not-found"; return 0; }
  status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null || true)"
  image="$(docker inspect -f '{{.Image}}' "$cid" 2>/dev/null || true)"
  echo "[idp][diagnostic] service=$service status=${status:-unknown} image=${image:-unknown}"
  echo "[idp][diagnostic] logs tail: $service"
  "${compose[@]}" logs --tail=100 --timestamps "$service" || true
}

compose_diagnostics_for() {
  local service
  {
    echo "[idp][diagnostic] phase=${CURRENT_PHASE:-unknown}"
    echo "[idp][diagnostic] compose ps"
    "${compose[@]}" ps -a || true
    for service in "$@"; do
      diagnostic_service_block "$service"
    done
  } 2>&1 | mask_secrets >&2
}

compose_diagnostics() {
  compose_diagnostics_for "${DIAGNOSTIC_SERVICES[@]}"
}

on_deploy_error() {
  local exit_code="$1" line="$2" command="$3"
  trap - ERR
  echo "[idp][error] phase=${CURRENT_PHASE:-unknown} line=$line exit=$exit_code command=$command" | mask_secrets >&2
  compose_diagnostics
  exit "$exit_code"
}
trap 'on_deploy_error $? $LINENO "$BASH_COMMAND"' ERR

set_env_var() {
  local key="$1" value="$2" tmp replaced=0 line
  tmp="$(mktemp)"
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" == "${key}="* ]]; then printf '%s=%s\n' "$key" "$value" >>"$tmp"; replaced=1
    else printf '%s\n' "$line" >>"$tmp"; fi
  done <"$env_file"
  [[ $replaced -eq 1 ]] || printf '%s=%s\n' "$key" "$value" >>"$tmp"
  mv "$tmp" "$env_file"
}

ensure_env_file() {
  if [[ -f "$env_file" ]]; then log "既存の .env を使用します（上書きしません）。"; return 0; fi
  [[ -f "$example_file" ]] || die ".env.example が見つかりません。"
  command -v openssl >/dev/null 2>&1 || die "openssl が見つかりません。"
  log ".env を新規生成します（秘密情報を乱数生成）。"
  cp "$example_file" "$env_file"
  local db_password
  db_password="$(openssl rand -hex 24)"
  set_env_var MARIADB_PASSWORD "$db_password"
  set_env_var MARIADB_ROOT_PASSWORD "$(openssl rand -hex 24)"
  set_env_var KEY_ENCRYPTION_KEY "$(openssl rand -base64 32)"
  set_env_var INTERNAL_SERVICE_TOKEN "$(openssl rand -hex 32)"
  set_env_var CSRF_SECRET "$(openssl rand -base64 32)"
  set_env_var DATABASE_URL "mysql://idp:${db_password}@127.0.0.1:3306/idp"
  set_env_var TEST_DATABASE_URL "mysql://idp:${db_password}@127.0.0.1:3306/idp"
  chmod 600 "$env_file"
  log ".env を生成しました（パーミッション 600）。"
}

load_image_with_progress() {
  local tar="$1" size_human pid waited=0
  size_human="$(du -h "$tar" 2>/dev/null | cut -f1 || true)"
  log "イメージを読み込みます: $tar (${size_human:-unknown size})"
  if command -v pv >/dev/null 2>&1; then pv "$tar" | docker load; return; fi
  docker load -i "$tar" &
  pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    sleep 5; waited=$((waited + 5))
    kill -0 "$pid" 2>/dev/null && log "...still loading, ${waited}s elapsed (pid $pid)"
  done
  wait "$pid"
}

ensure_images() {
  local manifest="$dist_dir/manifest.env" svc ref tar expected_id actual_id ref_key id_key revision first_revision="" prefix tag
  prefix="$(get_env_var IMAGE_PREFIX)"
  tag="$(get_env_var IMAGE_TAG)"
  # shellcheck disable=SC1090
  [[ -f "$manifest" ]] && source "$manifest"
  for svc in api web migrate; do
    ref_key="${svc}_ref"; id_key="${svc}_image_id"
    ref="${!ref_key:-${prefix:-idp}/${svc}:${tag:-latest}}"
    expected_id="${!id_key:-}"
    tar="$dist_dir/idp-${svc}.tar"
    actual_id="$(docker image inspect -f '{{.Id}}' "$ref" 2>/dev/null || true)"
    if [[ -z "$actual_id" || ( -n "$expected_id" && "$actual_id" != "$expected_id" ) ]]; then
      [[ -f "$tar" ]] || die "イメージ $ref がありません（$tar も無し）。build.sh が出力した dist/ を配置してください。"
      load_image_with_progress "$tar"
      actual_id="$(docker image inspect -f '{{.Id}}' "$ref" 2>/dev/null || true)"
    fi
    [[ -n "$actual_id" ]] || die "イメージ $ref を解決できません。"
    [[ -z "$expected_id" || "$actual_id" == "$expected_id" ]] || die "$ref の image ID が manifest と不一致です: $actual_id != $expected_id"
    revision="$(docker image inspect -f '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$ref" 2>/dev/null || true)"
    if [[ -n "$revision" ]]; then
      [[ -z "$first_revision" || "$revision" == "$first_revision" ]] || die "api/web/migrate の commit label が一致しません。"
      first_revision="$revision"
    fi
    log "配置対象 image: service=$svc ref=$ref revision=${revision:-unknown}"
  done
}

health_timeout_secs() {
  local service="$1"
  case "$service" in
    mariadb) printf '%s\n' "${DEPLOY_MARIADB_HEALTH_TIMEOUT_SECS:-600}" ;;
    api|web) printf '%s\n' "${DEPLOY_APP_HEALTH_TIMEOUT_SECS:-120}" ;;
    *) printf '%s\n' "${DEPLOY_HEALTH_TIMEOUT_SECS:-120}" ;;
  esac
}

health_poll_interval_secs() {
  printf '%s\n' "${DEPLOY_HEALTH_POLL_INTERVAL_SECS:-2}"
}

wait_healthy() {
  local service="$1" timeout interval cid status now deadline next_log
  timeout="${2:-$(health_timeout_secs "$service")}"
  interval="$(health_poll_interval_secs)"
  now="$(date +%s)"
  deadline=$((now + timeout))
  next_log=$((now + 30))
  log "$service の起動を待機します... (timeout=${timeout}s)"
  while (( $(date +%s) < deadline )); do
    cid="$("${compose[@]}" ps -q "$service" 2>/dev/null || true)"
    if [[ -n "$cid" ]]; then
      status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null || true)"
      case "$status" in
        healthy|running) log "$service: $status"; return 0 ;;
        exited|dead) compose_diagnostics; die "$service が異常終了しました（status=$status）。" ;;
        unhealthy|starting|created|restarting|*)
          now="$(date +%s)"
          if (( now >= next_log )); then
            log "$service: ${status:-unknown} のため待機を継続します (remaining=$((deadline - now))s)"
            next_log=$((now + 30))
          fi
          ;;
      esac
    fi
    sleep "$interval"
  done
  compose_diagnostics
  die "$service が healthy になりませんでした（${timeout}s タイムアウト）。"
}

run_migrations_with_retry() {
  local attempt status
  for attempt in 1 2 3; do
    if "${compose[@]}" run --rm migrate; then return 0; fi
    status=$?
    warn "DB migration failed (attempt $attempt/3, exit=$status); Docker logs を出力します"
    compose_diagnostics_for migrate mariadb
    if [[ $attempt -lt 3 ]]; then
      warn "DB migration failed (attempt $attempt/3); retrying in 5s"
      sleep 5
    fi
  done
  compose_diagnostics_for migrate mariadb
  die "DB migration failed after 3 attempts"
}

root_tenant_id() {
  local db_user db_name db_password
  db_user="$(get_env_var MARIADB_USER)"; db_name="$(get_env_var MARIADB_DATABASE)"; db_password="$(get_env_var MARIADB_PASSWORD)"
  "${compose[@]}" exec -T mariadb mariadb -u"${db_user:-idp}" -p"$db_password" "${db_name:-idp}" -N -B \
    -e 'SELECT id FROM tenants WHERE parent_tenant_id IS NULL' 2>/dev/null || true
}

start_database() {
  log "MariaDB を起動します..."
  "${compose[@]}" up -d mariadb
  wait_healthy mariadb
}

replace_app_containers() {
  local web_port issuer ready_url root login_url
  log "api・web・proxy を起動します（--force-recreate で全モード必ずアプリコンテナを入れ替え）..."
  "${compose[@]}" up -d --force-recreate --remove-orphans "${APP_SERVICES[@]}"
  wait_healthy api
  wait_healthy web
  web_port="$(get_env_var WEB_PORT)"; web_port="${web_port:-8080}"
  issuer="$(get_env_var ISSUER)"; issuer="${issuer:-http://localhost:${web_port}}"
  ready_url="http://127.0.0.1:${web_port}/readyz"
  log "readiness を確認します: $ready_url"
  for _ in $(seq 1 30); do
    if curl -fsS "$ready_url" >/dev/null 2>&1; then
      root="$(root_tenant_id)"; login_url="${issuer%/}/${root:-<root-tenant-id>}/login"
      log "readyz OK。デプロイが完了しました。"
      log "ログイン URL: $login_url"
      return 0
    fi
    sleep 2
  done
  compose_diagnostics
  die "readyz が OK になりませんでした。"
}

phase_begin "env"; ensure_env_file; phase_end
phase_begin "images"; ensure_images; phase_end

case "$mode" in
  reset)
    phase_begin "reset"
    warn "DB volume を削除します（.env は保持します）。"
    "${compose[@]}" down -v --remove-orphans || true
    phase_end
    phase_begin "database"; start_database; phase_end
    phase_begin "migrate"; run_migrations_with_retry; phase_end
    ;;
  migrate)
    phase_begin "database"; start_database; phase_end
    phase_begin "migrate"; run_migrations_with_retry; phase_end
    ;;
  app)
    phase_begin "database"; start_database; phase_end
    phase_begin "migrate"; run_migrations_with_retry; phase_end
    ;;
esac

phase_begin "app"
replace_app_containers
phase_end

phase_begin "cleanup"
docker image prune -f >/dev/null 2>&1 || true
phase_end
log "Deploy complete (mode: $mode)"
