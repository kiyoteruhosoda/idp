#!/usr/bin/env bash
# deploy.sh — デプロイ先の単一入口。初回も更新もこれ 1 本（build.sh が作る dist/ に同梱される）。
#
# 使い方:
#   ./deploy.sh          デプロイ（初回は .env を自動生成。イメージ読込 → migrate → 起動 → readiness 確認）
#   ./deploy.sh migrate  DB 起動と migrate（あれば DB 更新）のみ
#   ./deploy.sh reset    DB を初期化（volume 削除）してからデプロイし直す（破壊的操作）
#
# 前提: docker（Compose v2 または docker-compose v1）と openssl。ソース不要・ビルドしない。
set -Eeuo pipefail

log() { printf '[idp] %s\n' "$*" >&2; }
die() { printf '[idp][error] %s\n' "$*" >&2; exit 1; }

usage() {
  sed -n '2,9p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
}

# --- 実行場所の解決 ---------------------------------------------------------------
# バンドル（dist/）内では deploy.sh の隣に docker-compose.yml とイメージ tar がある。
# リポジトリ内（scripts/）ではルートの docker-compose.deploy.yml と dist/ を使う。
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

# --- 引数 -------------------------------------------------------------------------
mode="deploy"
while [[ $# -gt 0 ]]; do
  case "$1" in
    migrate | reset) mode="$1" ;;
    -h | --help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
  shift
done

command -v docker >/dev/null 2>&1 || die "docker が見つかりません。"
if docker compose version >/dev/null 2>&1; then
  compose="docker compose -f $compose_file"
elif command -v docker-compose >/dev/null 2>&1; then
  compose="docker-compose -f $compose_file"
else
  die "docker compose（v2）または docker-compose（v1）が見つかりません。"
fi

# --- ログ・診断ヘルパ --------------------------------------------------------------
CURRENT_PHASE="startup"
PHASE_STARTED_AT=0

# .env から KEY の値を取り出す（最後の一致。無ければ空）。
get_env_var() {
  local key="$1"
  [[ -f "$env_file" ]] || return 0
  grep -E "^${key}=" "$env_file" | tail -n1 | cut -d= -f2-
}

mask_secrets() {
  local sed_expr=() key value
  if [[ -f "$env_file" ]]; then
    for key in MARIADB_PASSWORD MARIADB_ROOT_PASSWORD KEY_ENCRYPTION_KEY INTERNAL_SERVICE_TOKEN CSRF_SECRET; do
      value="$(get_env_var "$key" 2>/dev/null || true)"
      [[ -n "$value" ]] && sed_expr+=(-e "s|${value//|/\|}|***MASKED***|g")
    done
  fi
  if [[ ${#sed_expr[@]} -gt 0 ]]; then
    sed "${sed_expr[@]}"
  else
    cat
  fi
}

phase_begin() {
  CURRENT_PHASE="$1"
  PHASE_STARTED_AT="$(date +%s)"
  log "▶ $CURRENT_PHASE を開始します"
}

phase_end() {
  log "✓ $CURRENT_PHASE が完了しました ($(($(date +%s) - PHASE_STARTED_AT))s)"
}

compose_diagnostics() {
  local service cid image status
  {
    echo "[idp][diagnostic] phase=${CURRENT_PHASE:-unknown}"
    echo "[idp][diagnostic] compose ps"
    $compose ps || true
    for service in mariadb migrate api web proxy; do
      cid="$($compose ps -q "$service" 2>/dev/null || true)"
      [[ -n "$cid" ]] || continue
      status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null || true)"
      image="$(docker inspect -f '{{.Image}}' "$cid" 2>/dev/null || true)"
      echo "[idp][diagnostic] service=$service status=${status:-unknown} image=${image:-unknown}"
      echo "[idp][diagnostic] logs tail: $service"
      $compose logs --tail=80 "$service" || true
    done
  } 2>&1 | mask_secrets >&2
}

on_deploy_error() {
  local exit_code="$1" line="$2" command="$3"
  trap - ERR
  echo "[idp][error] phase=${CURRENT_PHASE:-unknown} line=$line exit=$exit_code command=$command" | mask_secrets >&2
  compose_diagnostics
  exit "$exit_code"
}
trap 'on_deploy_error $? $LINENO "$BASH_COMMAND"' ERR

# 指定サービスのコンテナが healthy（healthcheck 無い場合は running）になるまで待つ。
wait_healthy() {
  local service="$1" tries="${2:-60}" cid status i
  log "$service の起動を待機します..."
  for ((i = 0; i < tries; i++)); do
    cid="$($compose ps -q "$service" 2>/dev/null || true)"
    if [[ -n "$cid" ]]; then
      status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null || true)"
      case "$status" in
        healthy | running) log "$service: $status"; return 0 ;;
        exited | dead) compose_diagnostics; die "$service が異常終了しました（status=$status）。" ;;
      esac
    fi
    sleep 2
  done
  compose_diagnostics
  die "$service が healthy になりませんでした（タイムアウト）。"
}

# --- .env -------------------------------------------------------------------------
# .env の KEY 行を VALUE で置換する（無ければ追記）。VALUE は sed を通さず printf で
# リテラル書き込みするため、base64 の / + = や @ : を含んでも安全。
set_env_var() {
  local key="$1" value="$2" tmp replaced=0 line
  tmp="$(mktemp)"
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" == "${key}="* ]]; then
      printf '%s=%s\n' "$key" "$value" >>"$tmp"
      replaced=1
    else
      printf '%s\n' "$line" >>"$tmp"
    fi
  done <"$env_file"
  [[ $replaced -eq 1 ]] || printf '%s=%s\n' "$key" "$value" >>"$tmp"
  mv "$tmp" "$env_file"
}

# .env を .env.example から生成する。既存 .env は上書きしない（冪等）。
ensure_env_file() {
  if [[ -f "$env_file" ]]; then
    log "既存の .env を使用します（上書きしません）。"
    return 0
  fi
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
  log ".env を生成しました（パーミッション 600）。秘密情報は自動生成済みです。"
  log "環境に合わせて確認・変更する項目（詳細は .env 内コメント）:"
  log "  - ISSUER   : 利用者がアクセスする公開 URL（既定 http://localhost:8080）"
  log "  - WEB_PORT : ホストに公開するポート（既定 8080）"
}

# --- イメージ（tar 読込と確認） ------------------------------------------------------
# dist の tar からイメージを読み込み、api/web/migrate が揃っていることを確認する。
# manifest.env（build.sh が出力）があれば image ID を照合し、一致すれば読込をスキップする。
ensure_images() {
  local manifest="$dist_dir/manifest.env" svc ref tar expected_id actual_id ref_key id_key
  local first_revision="" revision prefix tag
  prefix="$(get_env_var IMAGE_PREFIX)"
  tag="$(get_env_var IMAGE_TAG)"
  # shellcheck disable=SC1090
  [[ -f "$manifest" ]] && source "$manifest"
  for svc in api web migrate; do
    ref_key="${svc}_ref"
    id_key="${svc}_image_id"
    ref="${!ref_key:-${prefix:-idp}/${svc}:${tag:-latest}}"
    expected_id="${!id_key:-}"
    tar="$dist_dir/idp-${svc}.tar"
    actual_id="$(docker image inspect -f '{{.Id}}' "$ref" 2>/dev/null || true)"
    if [[ -z "$actual_id" || (-n "$expected_id" && "$actual_id" != "$expected_id") ]]; then
      [[ -f "$tar" ]] || die "イメージ $ref がありません（$tar も無し）。build.sh が出力した dist/ を配置してください。"
      log "イメージを読み込みます: $tar ..."
      docker load -i "$tar" >/dev/null
      actual_id="$(docker image inspect -f '{{.Id}}' "$ref" 2>/dev/null || true)"
    fi
    [[ -n "$actual_id" ]] || die "イメージ $ref を解決できません。"
    [[ -z "$expected_id" || "$actual_id" == "$expected_id" ]] ||
      die "$ref の image ID が manifest と不一致です: $actual_id != $expected_id"
    revision="$(docker image inspect -f '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$ref" 2>/dev/null || true)"
    if [[ -n "$revision" ]]; then
      if [[ -z "$first_revision" ]]; then
        first_revision="$revision"
      else
        [[ "$revision" == "$first_revision" ]] || die "api/web/migrate の commit label が一致しません。"
      fi
    fi
    log "配置対象 image: service=$svc ref=$ref revision=${revision:-unknown}"
  done
}

# --- 各フェーズ ---------------------------------------------------------------------
run_migrate() {
  phase_begin "migrate"
  log "MariaDB を起動します..."
  $compose up -d mariadb
  wait_healthy mariadb
  log "マイグレーションを適用します（あれば DB 更新）..."
  $compose run --rm migrate
  phase_end
}

root_tenant_id() {
  local db_user db_name db_password
  db_user="$(get_env_var MARIADB_USER)"
  db_name="$(get_env_var MARIADB_DATABASE)"
  db_password="$(get_env_var MARIADB_PASSWORD)"
  $compose exec -T mariadb mariadb -u"${db_user:-idp}" -p"$db_password" "${db_name:-idp}" -N -B \
    -e 'SELECT id FROM tenants WHERE parent_tenant_id IS NULL' 2>/dev/null || true
}

run_deploy() {
  local web_port issuer root login_url ready_url
  phase_begin "images"
  ensure_images
  phase_end
  run_migrate
  phase_begin "app"
  # --force-recreate で必ずコンテナを作り直す。旧イメージのまま restart ループしている
  # コンテナが居座ると、新イメージを load（タグを付け替え）しても `up -d` が「変更なし」と
  # 判断してコンテナを置き換えず、古い（壊れた）バイナリが動き続けることがあるため
  # （mariadb は対象に含めないので DB は落とさない）。
  log "api・web・proxy を起動します（--force-recreate で旧コンテナを確実に置き換え）..."
  $compose up -d --force-recreate api web proxy
  wait_healthy api
  wait_healthy web
  web_port="$(get_env_var WEB_PORT)"
  web_port="${web_port:-8080}"
  issuer="$(get_env_var ISSUER)"
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

# --- 実行 --------------------------------------------------------------------------
phase_begin "env"
ensure_env_file
phase_end

case "$mode" in
  deploy)
    run_deploy
    ;;
  migrate)
    phase_begin "images"
    ensure_images
    phase_end
    run_migrate
    ;;
  reset)
    phase_begin "reset"
    log "DB volume を削除します（.env は保持します）。"
    $compose down -v --remove-orphans
    phase_end
    run_deploy
    ;;
esac
