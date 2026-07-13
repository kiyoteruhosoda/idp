#!/usr/bin/env bash
# scripts/lib.sh — init.sh / deploy.sh 共通ヘルパ。単体では実行しない（source して使う）。

log() { printf '[idp] %s\n' "$*" >&2; }
die() { printf '[idp][error] %s\n' "$*" >&2; exit 1; }

CURRENT_PHASE="${CURRENT_PHASE:-startup}"
PHASE_STARTED_AT=0

mask_secrets() {
  local sed_expr=() key value file="${env_file:-.env}"
  if [[ -f "$file" ]]; then
    for key in MARIADB_PASSWORD MARIADB_ROOT_PASSWORD KEY_ENCRYPTION_KEY INTERNAL_SERVICE_TOKEN CSRF_SECRET; do
      value="$(get_env_var "$key" "$file" 2>/dev/null || true)"
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
  local now elapsed
  now="$(date +%s)"
  elapsed=$((now - PHASE_STARTED_AT))
  log "✓ $CURRENT_PHASE が完了しました (${elapsed}s)"
}

compose_diagnostics() {
  local compose="${DEPLOY_COMPOSE:-}" service cid image status
  [[ -n "$compose" ]] || return 0
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
  {
    echo "[idp][error] phase=${CURRENT_PHASE:-unknown} line=$line exit=$exit_code command=$command"
  } | mask_secrets >&2
  compose_diagnostics
  exit "$exit_code"
}


# ビルド済みイメージの参照名。ソース側（build.sh）とデプロイ側（compose）で同じ規則を使い、
# レジストリ配布・tar 配布のどちらでも同名で解決できるようにする。
#   IMAGE_PREFIX 既定 idp（レジストリ配布時は registry.example.com/idp のようにホストを含める）
#   IMAGE_TAG    既定 latest
# 例: image_ref api → idp/api:latest
image_ref() { printf '%s/%s:%s' "${IMAGE_PREFIX:-idp}" "$1" "${IMAGE_TAG:-latest}"; }

# デプロイ側（ソースを持たない別ホスト）で使う compose ファイル。build: を持たず image: 参照のみ。
DEPLOY_COMPOSE_FILE="docker-compose.deploy.yml"

# デプロイに必要なイメージ（api/web/migrate）がローカルに揃っていることを保証する。
# 無ければ pull を試み（レジストリ配布）、それでも無ければ die（tar 配布なら事前に docker load 済みが前提）。
# デプロイ先はソースを持たないため、ここでビルドはしない。
image_manifest_file() { printf '%s' "${IMAGE_MANIFEST_FILE:-${ARTIFACT_MANIFEST_FILE:-dist/manifest.env}}"; }

ensure_registry_image() {
  local svc="$1" ref tag digest actual_digest revision expected_commit
  ref="$(image_ref "$svc")"
  tag="${IMAGE_TAG:-latest}"
  [[ "$tag" != "latest" ]] || die "レジストリ配布で IMAGE_TAG=latest は使用できません。immutable tag または digest を指定してください。"
  log "$ref を明示 pull します..."
  docker pull "$ref" >/dev/null 2> >(mask_secrets >&2) || die "pull に失敗しました: $ref"
  digest="${IMAGE_DIGEST:-}"
  if [[ -n "$digest" ]]; then
    actual_digest="$(docker image inspect -f '{{index .RepoDigests 0}}' "$ref" 2>/dev/null | sed 's/^.*@//')"
    [[ "$actual_digest" == "$digest" ]] || die "$ref の digest が期待値と不一致です: ${actual_digest:-unknown} != $digest"
  fi
  expected_commit="${IMAGE_COMMIT:-}"
  if [[ -n "$expected_commit" ]]; then
    revision="$(docker image inspect -f '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$ref" 2>/dev/null || true)"
    [[ "$revision" == "$expected_commit" ]] || die "$ref の commit label が期待値と不一致です: ${revision:-unknown} != $expected_commit"
  fi
}

ensure_tar_image() {
  local svc="$1" manifest ref_key id_key revision_key ref expected_id actual_id expected_revision actual_revision
  manifest="$(image_manifest_file)"
  [[ -f "$manifest" ]] || die "tar 配布 manifest が見つかりません: $manifest"
  # shellcheck disable=SC1090
  source "$manifest"
  ref_key="${svc}_ref"; id_key="${svc}_image_id"; revision_key="${svc}_revision"
  ref="${!ref_key:-$(image_ref "$svc")}"
  expected_id="${!id_key:-}"
  expected_revision="${!revision_key:-}"
  docker image inspect "$ref" >/dev/null 2>&1 || die "必要なイメージがありません: $ref。manifest に対応する tar を docker load してください。"
  actual_id="$(docker image inspect -f '{{.Id}}' "$ref")"
  [[ -z "$expected_id" || "$actual_id" == "$expected_id" ]] || die "$ref の image ID が manifest と不一致です: $actual_id != $expected_id"
  actual_revision="$(docker image inspect -f '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$ref" 2>/dev/null || true)"
  [[ -z "$expected_revision" || "$actual_revision" == "$expected_revision" ]] || die "$ref の commit label が manifest と不一致です: ${actual_revision:-unknown} != $expected_revision"
}

ensure_image() {
  local svc="$1"
  if [[ -f "$(image_manifest_file)" ]]; then
    ensure_tar_image "$svc"
  else
    ensure_registry_image "$svc"
  fi
}

ensure_images() {
  local svc first_revision revision ref
  for svc in api web migrate; do
    ensure_image "$svc"
    ref="$(image_ref "$svc")"
    revision="$(docker image inspect -f '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$ref" 2>/dev/null || true)"
    [[ -n "$revision" ]] || die "$ref に org.opencontainers.image.revision label がありません。build.sh で再ビルドしてください。"
    if [[ -z "${first_revision:-}" ]]; then first_revision="$revision"; else [[ "$revision" == "$first_revision" ]] || die "api/web/migrate の commit label が一致しません。"; fi
    log "配置対象 image: service=$svc ref=$ref id=$(docker image inspect -f '{{.Id}}' "$ref") revision=$revision"
  done
}

# 利用可能な Compose コマンド（v2: `docker compose` / v1: `docker-compose`）を返す。
compose_cmd() {
  if docker compose version >/dev/null 2>&1; then
    echo "docker compose"
  elif command -v docker-compose >/dev/null 2>&1; then
    echo "docker-compose"
  else
    die "docker compose（v2）または docker-compose（v1）が見つかりません。"
  fi
}

# .env を .env.example から生成する。既存 .env は上書きしない。
ensure_env_file() {
  local env_file="$1" example_file="$2"
  if [[ -f "$env_file" ]]; then
    log "既存の .env を使用します（上書きしません）。"
    return 0
  fi
  [[ -f "$example_file" ]] || die ".env.example が見つかりません。"
  command -v openssl >/dev/null 2>&1 || die "openssl が見つかりません。"
  log ".env を新規生成します（秘密情報を乱数生成）。"
  cp "$example_file" "$env_file"
  local db_password root_password key_encryption_key internal_service_token csrf_secret
  db_password="$(openssl rand -hex 24)"
  root_password="$(openssl rand -hex 24)"
  key_encryption_key="$(openssl rand -base64 32)"
  internal_service_token="$(openssl rand -hex 32)"
  csrf_secret="$(openssl rand -base64 32)"
  set_env_var MARIADB_PASSWORD       "$db_password"                                  "$env_file"
  set_env_var MARIADB_ROOT_PASSWORD  "$root_password"                                "$env_file"
  set_env_var KEY_ENCRYPTION_KEY     "$key_encryption_key"                           "$env_file"
  set_env_var INTERNAL_SERVICE_TOKEN "$internal_service_token"                       "$env_file"
  set_env_var CSRF_SECRET            "$csrf_secret"                                  "$env_file"
  set_env_var DATABASE_URL           "mysql://idp:${db_password}@127.0.0.1:3306/idp" "$env_file"
  set_env_var TEST_DATABASE_URL      "mysql://idp:${db_password}@127.0.0.1:3306/idp" "$env_file"
  chmod 600 "$env_file"
  log ".env を生成しました（パーミッション 600）。"
}

# .env の KEY 行を VALUE で置換する（無ければ追記）。VALUE は sed を通さず printf で
# リテラル書き込みするため、base64 の / + = や @ : を含んでも安全。
set_env_var() {
  local key="$1" value="$2" file="$3" tmp replaced=0 line
  tmp="$(mktemp)"
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" == "${key}="* ]]; then
      printf '%s=%s\n' "$key" "$value" >>"$tmp"
      replaced=1
    else
      printf '%s\n' "$line" >>"$tmp"
    fi
  done <"$file"
  [[ $replaced -eq 1 ]] || printf '%s=%s\n' "$key" "$value" >>"$tmp"
  mv "$tmp" "$file"
}

# .env から KEY の値を取り出す（最後の一致。無ければ空）。
get_env_var() {
  local key="$1" file="$2"
  [[ -f "$file" ]] || return 0
  grep -E "^${key}=" "$file" | tail -n1 | cut -d= -f2-
}

# 指定サービスのコンテナが healthy（healthcheck 無い場合は running）になるまで待つ。
wait_healthy() {
  local compose="$1" service="$2" tries="${3:-60}" cid status i
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
