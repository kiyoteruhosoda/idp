#!/usr/bin/env bash
# deploy.sh — single entry point on the deployment target (app / migrate / reset).
#
# Usage (the mode argument is required):
#   ./deploy.sh app      normal deploy (applies migrations idempotently and always replaces the app containers)
#   ./deploy.sh migrate  for DDL updates (after applying migrations, also always replaces the app containers)
#   ./deploy.sh reset    after initializing the DB (deleting the volume), applies migrations and replaces the app containers
#
# Requires: docker (Compose v2 or docker-compose v1) and openssl. No source needed; nothing is built.
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
[[ -f "$base/$compose_file" ]] || die "$compose_file is missing (deployment Compose)."
# Override for domain-split publishing (ADR-0015). Placed directly under $base both in the bundle and in the repository.
domain_split_compose_file="docker-compose.domain-split.yml"

timestamp_millis() {
  local ts
  ts="$(date +%Y%m%d%H%M%S%3N 2>/dev/null || true)"
  if [[ "$ts" =~ ^[0-9]{17}$ ]]; then
    printf '%s\n' "$ts"
  else
    printf '%s000\n' "$(date +%Y%m%d%H%M%S)"
  fi
}

if [[ -z "${DEPLOY_LOG_ACTIVE:-}" ]]; then
  deploy_log_file="$base/deploy-$(timestamp_millis).log"
  export DEPLOY_LOG_ACTIVE=1
  exec > >(tee -a "$deploy_log_file") 2>&1
  deploy_log_tee_pid=$!
  # ⚠ **Wait for tee when exiting.** Process substitution is asynchronous, so exiting without waiting leaves the last
  #   few lines not yet delivered to the caller's output (file, pipe). Tests reading the output right after the call
  #   (test_deploy.sh) were flaky because of this. Closing the output lets tee read everything and finish.
  #   The exit code does not change (no exit inside the trap).
  trap 'exec 1>&- 2>&-; wait "$deploy_log_tee_pid" 2>/dev/null || true' EXIT
  log "log file: $deploy_log_file"
fi

env_file="$base/.env"
example_file="$base/.env.example"

mode="${1:-}"
case "$mode" in
  app|migrate|reset) ;;
  -h|--help) usage; exit 0 ;;
  *) usage; exit 2 ;;
esac
[[ $# -eq 1 ]] || { usage; exit 2; }

command -v docker >/dev/null 2>&1 || die "docker not found."
if ! docker info >/dev/null 2>&1; then
  die "cannot connect to the Docker daemon (daemon stopped or insufficient permission). Re-run once docker info succeeds."
fi

CURRENT_PHASE="startup"
PHASE_STARTED_AT=0
APP_SERVICES=(api web proxy)
compose=()
COMPOSE_PROJECT=""
LEGACY_COMPOSE_PROJECT_NAME=""
DIAGNOSTIC_SERVICES=(mariadb migrate api web proxy)
# Publish topology (ADR-0015, ADR-0016). init_compose_command settles it from .env.
#   domain-split : splits web / api by listen port; the front proxy assigns separate subdomains (default)
#   single-origin: routes one port (WEB_PORT) by path
PUBLISH_TOPOLOGY="domain-split"
# List of service names Compose knows (settled in init_compose_command; empty if fetching fails).
COMPOSE_DEFINED_SERVICES=""
# Root tenant URLs for the summary at the end of deployment (settled in replace_app_containers).
ROOT_LOGIN_URL=""
ROOT_ADMIN_URL=""
# Extra patterns to mask with the values Compose actually resolved rather than the .env text (set by resolve_db_credentials).
EXTRA_MASK_VALUES=()
# DB credentials resolved by Compose (settled by resolve_db_credentials).
DB_USER=""
DB_NAME=""
DB_PASSWORD=""
DB_ROOT_PASSWORD=""

# Approximates Compose's dotenv parsing and strips a matching pair of quotes around the value ("..." / '...'). Only inside
# double quotes are \" \\ unescaped.
# This is an **approximation** and does not fully match Compose's dotenv implementation (inline comments, variable expansion,
# \n etc. are not reproduced). So this value is not used for decisions that rewrite the DB (password sync);
# the effective value is resolved by Compose itself via container_env_value. Its uses here are limited to masking logs and
# the fallback when it cannot be read from the container.
strip_env_quotes() {
  local value="$1"
  if [[ ${#value} -ge 2 && "${value:0:1}" == '"' && "${value: -1}" == '"' ]]; then
    value="${value:1:${#value}-2}"
    value="${value//\\\"/\"}"
    value="${value//\\\\/\\}"
  elif [[ ${#value} -ge 2 && "${value:0:1}" == "'" && "${value: -1}" == "'" ]]; then
    value="${value:1:${#value}-2}"
  fi
  printf '%s\n' "$value"
}

get_env_var() {
  local key="$1" value
  [[ -f "$env_file" ]] || return 0
  value="$(grep -E "^${key}=" "$env_file" 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' || true)"
  strip_env_quotes "$value"
}

mask_secrets() {
  local sed_expr=() key value escaped values=()
  if [[ -f "$env_file" ]]; then
    for key in MARIADB_PASSWORD MARIADB_ROOT_PASSWORD KEY_ENCRYPTION_KEY INTERNAL_SERVICE_TOKEN CSRF_SECRET; do
      values+=("$(get_env_var "$key" 2>/dev/null || true)")
    done
  fi
  # The .env text and the value Compose resolves do not always match (quotes, inline comments, variable expansion).
  # Also mask the values actually used (settled by resolve_db_credentials).
  values+=(${EXTRA_MASK_VALUES[@]+"${EXTRA_MASK_VALUES[@]}"})
  if [[ ${#values[@]} -gt 0 ]]; then
    for value in "${values[@]}"; do
      [[ -n "$value" ]] || continue
      # Masking is a simple substring replacement on log text, so short values collide with ordinary words.
      # For example masking MARIADB_PASSWORD=idp would mangle `[idp][diagnostic]` too, making the diagnostic output
      # meant for finding the cause unreadable (the opposite of masking's purpose). Only target values long enough not to collide.
      # Secrets generated by deploy.sh are 44-48 characters and always exceed this threshold.
      [[ ${#value} -ge 8 ]] || continue
      # Secret values are used as sed BRE patterns, so escape metacharacters (\ . * [ ] ^ $ and the delimiter |).
      # Otherwise a password with symbols (e.g. MARIADB_PASSWORD=[…) yields an invalid regex and sed fails, and under
      # pipefail even the masking after a successful migrate aborts the deployment.
      escaped="$(printf '%s' "$value" | sed 's/[][\.*^$|]/\\&/g')"
      sed_expr+=(-e "s|${escaped}|***MASKED***|g")
    done
  fi
  if [[ ${#sed_expr[@]} -gt 0 ]]; then sed "${sed_expr[@]}"; else cat; fi
}

phase_begin() { CURRENT_PHASE="$1"; PHASE_STARTED_AT="$(date +%s)"; log "▶ starting $CURRENT_PHASE"; }
phase_end() { log "✓ $CURRENT_PHASE completed ($(($(date +%s) - PHASE_STARTED_AT))s)"; }

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
  if [[ ${#compose[@]} -eq 0 ]]; then
    echo "[idp][diagnostic] compose command=not-initialized" >&2
    return 0
  fi
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

legacy_compose_project_name() {
  basename "$base"
}

default_compose_project_name() {
  local dir
  dir="$(legacy_compose_project_name)"
  case "$dir" in
    idp|idp-*) printf '%s\n' "$dir" ;;
    *) printf 'idp-%s\n' "$dir" ;;
  esac
}

# Choose the template for generating the initial .env from the deployment directory name. For stg/prod directories,
# prefer the dedicated template (with WEB_PORT, IMAGE_TAG, COMPOSE_PROJECT_NAME separated), falling back to the
# generic .env.example. This prevents the accident of "running without a .env and starting with generic defaults".
select_env_example() {
  local dir
  dir="$(basename "$base")"
  case "$dir" in
    stg | staging | *-stg | *-staging)
      [[ -f "$base/.env.staging.example" ]] && {
        printf '%s\n' "$base/.env.staging.example"
        return
      }
      ;;
    prod | production | *-prod | *-production)
      [[ -f "$base/.env.production.example" ]] && {
        printf '%s\n' "$base/.env.production.example"
        return
      }
      ;;
  esac
  printf '%s\n' "$example_file"
}

# Replace only the CHANGE-ME in the given key's current value with the replacement (other parts like host:port are kept).
# The stg/prod templates' DATABASE_URLs have different ports, so the whole value is not overwritten.
fill_change_me() {
  local key="$1" replacement="$2" current
  current="$(get_env_var "$key")"
  [[ -n "$current" ]] || return 0
  set_env_var "$key" "${current//CHANGE-ME/$replacement}"
}

init_compose_command() {
  local project_name topology
  project_name="$(get_env_var COMPOSE_PROJECT_NAME)"
  project_name="${project_name:-${LEGACY_COMPOSE_PROJECT_NAME:-$(default_compose_project_name)}}"
  if docker compose version >/dev/null 2>&1; then
    compose=(docker compose --project-name "$project_name" -f "$compose_file")
  elif command -v docker-compose >/dev/null 2>&1; then
    compose=(docker-compose --project-name "$project_name" -f "$compose_file")
  else
    die "neither docker compose (v2) nor docker-compose (v1) found."
  fi
  # Publish topology (ADR-0015, ADR-0016). The default domain-split layers the override, and proxy publishes
  # web / api on separate ports. Unknown values fail fast (never start with another topology due to a typo).
  topology="$(get_env_var PUBLISH_TOPOLOGY)"
  PUBLISH_TOPOLOGY="${topology:-domain-split}"
  case "$PUBLISH_TOPOLOGY" in
    single-origin) ;;
    domain-split)
      [[ -f "$base/$domain_split_compose_file" ]] \
        || die "PUBLISH_TOPOLOGY=domain-split but $domain_split_compose_file is missing."
      compose+=(-f "$domain_split_compose_file")
      ;;
    *)
      die "invalid PUBLISH_TOPOLOGY: '$PUBLISH_TOPOLOGY' (single-origin or domain-split)."
      ;;
  esac
  COMPOSE_PROJECT="$project_name"
  # Keep the list of service names so wait_healthy does not keep waiting for "a service not in the definition".
  COMPOSE_DEFINED_SERVICES="$("${compose[@]}" config --services 2>/dev/null || true)"
  log "Compose project name: $project_name"
  log "publish topology: $PUBLISH_TOPOLOGY"
}

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

# Append to an existing .env only the "setting keys" present in `.env.example` but missing (automatically
# following keys added by version updates). Existing values are never rewritten (secrets and hand edits are preserved). Excluded:
#   * Secrets (example value CHANGE-ME), so they are never overwritten with empty values or placeholders by mistake.
#   * Keys with empty values (set separately by deploy.sh, or optional).
#   * COMPOSE_PROJECT_NAME (volume namespace; pointing at another volume by mistake would corrupt data, so keep existing behaviour).
# Decide the value used when appending a "missing key" to an existing `.env`. The template (`.env.example`) defaults are
# **for new deployments**; inserting them as is into an existing deployment would silently change the public target or topology for some keys.
# Prints the value actually to write to stdout; returns 1 to skip appending altogether.
migration_value_for() {
  local key="$1" template_value="$2"
  case "$key" in
    # ADR-0016 changed the default to domain-split. A `.env` without this key was created before that = a deployment
    # that has been running single-origin, so keep single-origin as before. Topology changes are made by
    # operators explicitly editing `.env` (prevents redeployment from adding public ports).
    PUBLISH_TOPOLOGY) printf 'single-origin\n' ;;
    # Since ADR-0016 the template has a real value (the local web origin). Appending it to an existing `.env`
    # would keep the production ISSUER but send only login, invitation and reset redirects to
    # localhost. When unset, both api and web fall back to ISSUER (= previous behaviour), so
    # do not append. When moving to domain-split publishing, operators state the real domain.
    PUBLIC_WEB_BASE_URL) return 1 ;;
    *) printf '%s\n' "$template_value" ;;
  esac
}

merge_missing_env_keys() {
  [[ -f "$example_file" ]] || return 0
  local line key value added=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" == \#* ]] && continue
    [[ "$line" == *=* ]] || continue
    key="${line%%=*}"
    value="${line#*=}"
    key="${key//[[:space:]]/}"
    [[ -n "$key" ]] || continue
    [[ "$key" == COMPOSE_PROJECT_NAME ]] && continue
    [[ -z "$value" || "$value" == *CHANGE-ME* ]] && continue
    grep -qE "^[[:space:]]*${key}=" "$env_file" && continue
    # Keys whose template default would change an existing deployment's meaning if appended as is are
    # translated to values preserving previous behaviour (sometimes appending is skipped). So version updates never silently change the public target.
    if ! value="$(migration_value_for "$key" "$value")"; then continue; fi
    line="${key}=${value}"
    # Ensure a trailing newline before appending. Even if a hand-edited .env lacks one, do not concatenate onto
    # the last line's value and break it (e.g. prevents `FOO=bar` + `LOG_FORMAT=pretty` -> `FOO=barLOG_FORMAT=...`).
    if [[ -s "$env_file" && -n "$(tail -c1 "$env_file")" ]]; then printf '\n' >>"$env_file"; fi
    printf '%s\n' "$line" >>"$env_file"
    added=$((added + 1))
  done <"$example_file"
  [[ $added -gt 0 ]] &&
    log "appended ${added} setting key(s) missing from .env, from .env.example (existing values and secrets unchanged)."
  return 0
}

# Fail fast if the template placeholder CHANGE-ME remains in .env.
# If `.env.*.example` was copied by hand and not replaced, the api cannot decode KEY_ENCRYPTION_KEY etc. as base64
# and crash-loops (the error only says `Invalid symbol 45, offset 6`), so stop before starting containers,
# stating the cause and the fix.
ensure_no_placeholder_secrets() {
  local key value leftover=()
  for key in MARIADB_PASSWORD MARIADB_ROOT_PASSWORD KEY_ENCRYPTION_KEY INTERNAL_SERVICE_TOKEN CSRF_SECRET DATABASE_URL TEST_DATABASE_URL; do
    value="$(get_env_var "$key")"
    [[ "$value" == *CHANGE-ME* ]] && leftover+=("$key")
  done
  [[ ${#leftover[@]} -eq 0 ]] && return 0
  err "template placeholder CHANGE-ME remains in .env: ${leftover[*]}"
  err "fix: set real values for those keys in .env and re-run."
  err "  * KEY_ENCRYPTION_KEY / CSRF_SECRET: openssl rand -base64 32"
  err "  * INTERNAL_SERVICE_TOKEN: openssl rand -hex 32"
  err "  * MARIADB_PASSWORD / MARIADB_ROOT_PASSWORD: openssl rand -hex 24"
  err "    (also align the password part in DATABASE_URL / TEST_DATABASE_URL with MARIADB_PASSWORD)"
  die "placeholder secrets (CHANGE-ME) remain in .env"
}

ensure_env_file() {
  if [[ -f "$env_file" ]]; then
    log "using the existing .env (not overwritten)."
    merge_missing_env_keys
    ensure_no_placeholder_secrets
    if [[ -z "$(get_env_var COMPOSE_PROJECT_NAME)" ]]; then
      LEGACY_COMPOSE_PROJECT_NAME="$(legacy_compose_project_name)"
      warn "existing .env has no COMPOSE_PROJECT_NAME; using the legacy Compose project name ($LEGACY_COMPOSE_PROJECT_NAME) to protect existing volumes. To change it, migrate the volumes or reset, then set it explicitly in .env."
    fi
    return 0
  fi
  local seed_example
  seed_example="$(select_env_example)"
  [[ -f "$seed_example" ]] || die "template for generating .env not found: $seed_example"
  command -v openssl >/dev/null 2>&1 || die "openssl not found."
  log "generating a new .env (source: $(basename "$seed_example"); secrets generated randomly)."
  cp "$seed_example" "$env_file"
  local db_password
  db_password="$(openssl rand -hex 24)"
  set_env_var MARIADB_PASSWORD "$db_password"
  set_env_var MARIADB_ROOT_PASSWORD "$(openssl rand -hex 24)"
  set_env_var KEY_ENCRYPTION_KEY "$(openssl rand -base64 32)"
  set_env_var INTERNAL_SERVICE_TOKEN "$(openssl rand -hex 32)"
  set_env_var CSRF_SECRET "$(openssl rand -base64 32)"
  # The template's DATABASE_URL keeps host:port (different for stg/prod); only CHANGE-ME is replaced with a real value.
  fill_change_me DATABASE_URL "$db_password"
  fill_change_me TEST_DATABASE_URL "$db_password"
  set_env_var COMPOSE_PROJECT_NAME "$(default_compose_project_name)"
  chmod 600 "$env_file"
  ensure_no_placeholder_secrets
  log "generated .env (permission 600, Compose project: $(get_env_var COMPOSE_PROJECT_NAME))."
}

load_image_with_progress() {
  local tar="$1" size_human pid waited=0
  size_human="$(du -h "$tar" 2>/dev/null | cut -f1 || true)"
  log "loading image: $tar (${size_human:-unknown size})"
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
    tar="$dist_dir/assay-${svc}.tar"
    actual_id="$(docker image inspect -f '{{.Id}}' "$ref" 2>/dev/null || true)"
    if [[ -z "$actual_id" || ( -n "$expected_id" && "$actual_id" != "$expected_id" ) ]]; then
      [[ -f "$tar" ]] || die "image $ref is missing ($tar missing too). Place the dist/ output by build.sh."
      load_image_with_progress "$tar"
      actual_id="$(docker image inspect -f '{{.Id}}' "$ref" 2>/dev/null || true)"
    fi
    [[ -n "$actual_id" ]] || die "cannot resolve image $ref."
    [[ -z "$expected_id" || "$actual_id" == "$expected_id" ]] || die "image ID of $ref does not match the manifest: $actual_id != $expected_id"
    revision="$(docker image inspect -f '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$ref" 2>/dev/null || true)"
    if [[ -n "$revision" ]]; then
      [[ -z "$first_revision" || "$revision" == "$first_revision" ]] || die "commit labels of api/web/migrate do not match."
      first_revision="$revision"
    fi
    log "image to deploy: service=$svc ref=$ref revision=${revision:-unknown}"
  done
}

health_timeout_secs() {
  local service="$1"
  case "$service" in
    mariadb) printf '%s\n' "${DEPLOY_MARIADB_HEALTH_TIMEOUT_SECS:-600}" ;;
    api|web|proxy) printf '%s\n' "${DEPLOY_APP_HEALTH_TIMEOUT_SECS:-120}" ;;
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
  # If Compose has no definition for the service, `ps -q` keeps returning empty, so it would wait until the timeout and
  # fail with "did not become healthy" (misleading about the cause). Check the definition first and fail immediately.
  # Skip the check where the definition list could not be fetched (wait as before).
  if [[ -n "$COMPOSE_DEFINED_SERVICES" ]] && ! grep -qx "$service" <<<"$COMPOSE_DEFINED_SERVICES"; then
    die "$service is not in the Compose definition (PUBLISH_TOPOLOGY=$PUBLISH_TOPOLOGY / $compose_file)."
  fi
  now="$(date +%s)"
  deadline=$((now + timeout))
  next_log=$((now + 30))
  log "waiting for $service to start... (timeout=${timeout}s)"
  while (( $(date +%s) < deadline )); do
    cid="$("${compose[@]}" ps -q "$service" 2>/dev/null || true)"
    if [[ -n "$cid" ]]; then
      status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null || true)"
      case "$status" in
        healthy|running) log "$service: $status"; return 0 ;;
        exited|dead) compose_diagnostics; die "$service exited abnormally (status=$status)." ;;
        unhealthy|starting|created|restarting|*)
          now="$(date +%s)"
          if (( now >= next_log )); then
            log "$service: ${status:-unknown}, continuing to wait (remaining=$((deadline - now))s)"
            next_log=$((now + 30))
          fi
          ;;
      esac
    fi
    sleep "$interval"
  done
  compose_diagnostics
  die "$service did not become healthy (${timeout}s timeout)."
}

# sqlx aborts applying when the content of an applied migration changes ("migration <n> was previously applied but has
# been modified"; protection against history tampering). This is a deterministic failure; retrying always gives
# the same result. On the MariaDB side only a seemingly unrelated warning remains when the failed migrate process
# disconnects ("Aborted connection ... Got an error reading communication packets"), burying the real cause.
# Detect it here and stop immediately with an actionable message, without retrying (fail-fast).
migration_checksum_mismatch_guidance() {
  local out="$1" ver db_name compose_cli
  # Show the guidance even if the version cannot be read (best-effort so set -e + pipefail do not abort).
  ver="$(printf '%s' "$out" | grep -oiE 'migration [0-9]+ was previously applied' \
    | grep -oE '[0-9]+' | head -n1 || true)"
  # The DB name is the same effective value as preflight_db_auth (Compose's resolution) (so another DB is never dumped by mistake).
  db_name="${DB_NAME:-${MARIADB_DATABASE:-$(get_env_var MARIADB_DATABASE)}}"; db_name="${db_name:-idp}"
  # Do not build the container name directly (Compose v2 names it project-mariadb-1, v1 project_mariadb_1).
  # Let the initialized compose command resolve the service name mariadb.
  compose_cli="${compose[*]:-docker compose}"
  # Put the conclusion (initialization needed) first so the fix is seen first, with concrete commands alongside.
  err "════════════════════════════════════════════════════════════════════"
  err "▶ Required action: the DB must be initialized (recreated)."
  err "════════════════════════════════════════════════════════════════════"
  err "An applied migration${ver:+ (version $ver)} has changed from what is recorded in this DB."
  err "sqlx aborts applying when it detects a modified applied migration (protection against history tampering)."
  err "This DB is incompatible with the current image's migration history and cannot be updated as is."
  err "(e.g. pinning the root tenant UUID = the one-time seed revision of ADR-0011 / ADR-0009 §11)"
  err ""
  err "Fix A: if this DB may be recreated (initial setup, staging, seed only, etc.) — recommended"
  err "  1) Back up (optional, recommended; runs in one line):"
  err "     ${compose_cli} exec -T mariadb sh -c 'exec mariadb-dump -uroot -p\"\$MARIADB_ROOT_PASSWORD\" --single-transaction ${db_name}' > backup.sql"
  err "  2) Initialize and redeploy (note: all existing data is erased):"
  err "     ./deploy.sh reset"
  err ""
  err "Fix B: if existing data must be kept / the modification was not intended"
  err "  - Modification not intended -> restore the migration file to its original content and redeploy."
  err "  - Apply while keeping data -> do not edit applied files; use a new, additive migration instead."
  err "  Steps: docs/OPERATIONS.md \"When you want to recreate the DB\" / migrations/README.md."
  err "════════════════════════════════════════════════════════════════════"
}

run_migrations_with_retry() {
  local attempt status out
  for attempt in 1 2 3; do
    # Capture migrate's output (masking sensitive values) while also streaming it to the screen, so the sqlx error text
    # can be inspected to identify deterministic failures (checksum mismatch). -T disables the pseudo TTY for clean capture.
    # Evaluate the command substitution in an if condition and save the exit code, so set -e does not stop before capturing.
    if out="$("${compose[@]}" run --rm -T migrate 2>&1)"; then status=0; else status=$?; fi
    printf '%s\n' "$out" | mask_secrets
    [[ $status -eq 0 ]] && return 0

    # Retrying a checksum mismatch is pointless. State the cause (modification of an applied migration) and stop immediately.
    # MariaDB's container logs (compose_diagnostics_for) are noise unrelated to the cause and would bury the essential
    # guidance. Do not print them here; show the guidance last so it is the first thing the operator sees.
    if printf '%s' "$out" | grep -qiE 'was previously applied but has been modified'; then
      migration_checksum_mismatch_guidance "$out"
      die "DB migration aborted: checksum mismatch of an applied migration. Follow the \"the DB must be initialized\" steps above."
    fi

    warn "DB migration failed (attempt $attempt/3, exit=$status); dumping Docker logs"
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
  # Credentials use the effective values settled by preflight_db_auth (start_database). If not settled, resolve before reading.
  [[ -n "$DB_USER" ]] || resolve_db_credentials
  "${compose[@]}" exec -T mariadb mariadb -u"$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" -N -B \
    -e 'SELECT id FROM tenants WHERE parent_tenant_id IS NULL' 2>/dev/null || true
}

# Safely embed values into SQL string literals / identifiers. Even secrets with symbols (backslashes, quotes)
# must not break the syntax or produce unintended SQL.
sql_string_literal() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\'/\\\'}"
  printf "'%s'" "$s"
}

sql_identifier() {
  local s="$1"
  s="${s//\`/\`\`}"
  printf '`%s`' "$s"
}

APP_DB_AUTH_ERROR=""

# Read the environment variables the running container actually has. Parsing `.env` (quotes, inline comments,
# variable expansion, escapes) is defined solely by Compose's dotenv implementation; if deploy.sh reimplemented it,
# it would inevitably diverge somewhere. `up -d mariadb` always recreates the container when `.env` changes, so the container's
# environment = the current `.env` as resolved by Compose = the values passed to api / migrate. Password sync
# rewrites the DB, so only this effective value is used, never a guessed one.
container_env_value() {
  local service="$1" name="$2"
  "${compose[@]}" exec -T "$service" sh -c "printf %s \"\${${name}-}\"" 2>/dev/null || true
}

# Settle DB credentials. Compose's resolution (the mariadb container's environment) takes top priority; only if it
# cannot be obtained, fall back to ENV > .env > default as before (so diagnostics can still be shown without a running container).
resolve_db_credentials() {
  local from_container
  from_container="$(container_env_value mariadb MARIADB_USER)"
  DB_USER="${from_container:-${MARIADB_USER:-$(get_env_var MARIADB_USER)}}"; DB_USER="${DB_USER:-idp}"
  from_container="$(container_env_value mariadb MARIADB_DATABASE)"
  DB_NAME="${from_container:-${MARIADB_DATABASE:-$(get_env_var MARIADB_DATABASE)}}"; DB_NAME="${DB_NAME:-idp}"
  from_container="$(container_env_value mariadb MARIADB_PASSWORD)"
  DB_PASSWORD="${from_container:-${MARIADB_PASSWORD:-$(get_env_var MARIADB_PASSWORD)}}"
  from_container="$(container_env_value mariadb MARIADB_ROOT_PASSWORD)"
  DB_ROOT_PASSWORD="${from_container:-${MARIADB_ROOT_PASSWORD:-$(get_env_var MARIADB_ROOT_PASSWORD)}}"
  EXTRA_MASK_VALUES=("$DB_PASSWORD" "$DB_ROOT_PASSWORD")
}

# Treat only "password mismatch" as drift. MariaDB returns 1044 (ER_DBACCESS_DENIED_ERROR) with the same
# "Access denied for user ..." text when credentials are correct but there is no access to the DB, so
# judging by text alone would mistake missing privileges for drift and widen privileges deliberately narrowed by GRANT.
# Restrict to the authentication-specific error code 1045 (ER_ACCESS_DENIED_ERROR).
is_password_mismatch_error() {
  printf '%s' "$1" | grep -qE 'ERROR 1045[[:space:]]*\('
}

# Try once whether the app DB user can actually connect. Uses the same TCP path as migrate
# (-h mariadb connects from the container IP = matches the '%' host definition). With the socket (no -h = localhost),
# environments with a host-specific account ('user'@'localhost') would verify a different account from migrate.
try_app_db_auth() {
  local db_user="$1" db_name="$2" db_password="$3"
  APP_DB_AUTH_ERROR="$("${compose[@]}" exec -T mariadb \
    mariadb -h mariadb -u"$db_user" -p"$db_password" "$db_name" -N -B -e 'SELECT 1' 2>&1)"
}

# Resolve a password mismatch while keeping existing data. MariaDB fixes the password at the data volume's first
# creation and ignores later .env changes, so align the DB-side account with `.env` as the SSOT
# (api/migrate can only use the .env values via Compose; aligning the DB side is the only way to make them match).
# Done only when the root credentials are valid. If even root cannot authenticate, the `.env` as a whole is different (= KEY_ENCRYPTION_KEY
# differs too and the existing DB's encrypted data cannot be decrypted), so do not touch it; leave it to the caller.
# Return value: 0 = synced / 2 = root cannot authenticate either / 1 = could not sync for another reason
sync_app_db_password() {
  local db_user="$1" db_name="$2" db_password="$3" root_password="$4" out sql
  if [[ -z "$root_password" ]]; then
    warn "MARIADB_ROOT_PASSWORD is not set; skipping automatic password sync."
    return 1
  fi
  # Check root via the in-container socket (= 'root'@'localhost'). 'root'@'%' may not exist depending on the
  # image settings, and trying via TCP would misjudge "syncable" as "not possible".
  if ! out="$("${compose[@]}" exec -T mariadb mariadb -uroot -p"$root_password" -N -B -e 'SELECT 1' 2>&1)"; then
    if is_password_mismatch_error "$out"; then return 2; fi
    printf '%s\n' "$out" | mask_secrets >&2
    return 1
  fi
  log "authenticated as root. Applying .env's MARIADB_PASSWORD to the existing DB user '$db_user' (data is kept)."
  # Go through CREATE -> ALTER -> GRANT so it also recovers when the user is gone (volume touched by hand etc.).
  sql="CREATE USER IF NOT EXISTS $(sql_string_literal "$db_user")@'%' IDENTIFIED BY $(sql_string_literal "$db_password");
ALTER USER $(sql_string_literal "$db_user")@'%' IDENTIFIED BY $(sql_string_literal "$db_password");
GRANT ALL PRIVILEGES ON $(sql_identifier "$db_name").* TO $(sql_string_literal "$db_user")@'%';
FLUSH PRIVILEGES;"
  if ! out="$("${compose[@]}" exec -T mariadb mariadb -uroot -p"$root_password" -e "$sql" 2>&1)"; then
    warn "failed to sync the password of DB user '$db_user'."
    printf '%s\n' "$out" | mask_secrets >&2
    return 1
  fi
  return 0
}

# The official MariaDB image fixes the data volume at "the MARIADB_PASSWORD at first initialization", and later changes to
# the .env password are not applied to the idp user in the existing volume. migrate/api then connect with the new password
# and fail with "Access denied for user 'idp'". The healthcheck only checks the server is up via root/socket, so
# this mismatch goes undetected and ends in 3 pointless migrate retries. Before migrations, check that the app user
# can actually authenticate; on mismatch, align the DB side with .env via root (data kept).
# Only if it cannot be aligned, state the cause and fix and stop immediately (fail-fast).
preflight_db_auth() {
  local db_user db_name db_password root_password attempt auth_denied=0 sync_status=0
  resolve_db_credentials
  db_user="$DB_USER"; db_name="$DB_NAME"; db_password="$DB_PASSWORD"; root_password="$DB_ROOT_PASSWORD"
  log "running DB authentication preflight (app user $db_user)..."
  for attempt in 1 2 3; do
    # A password mismatch (1045) is deterministic, so decide immediately without retrying. Anything else (missing privilege 1044, missing DB,
    # transient network failure etc.) is not drift, so retry briefly and then report as a generic error.
    if try_app_db_auth "$db_user" "$db_name" "$db_password"; then
      log "DB authentication preflight OK (user $db_user)."
      return 0
    fi
    if is_password_mismatch_error "$APP_DB_AUTH_ERROR"; then auth_denied=1; break; fi
    auth_denied=0
    [[ $attempt -lt 3 ]] && sleep 2
  done
  # Only for authentication failure (password drift), first try auto-sync, and if that fails suggest the destructive reset.
  # Recommending reset for non-authentication causes (missing DB, privileges, network failure etc.) could erase existing data by mistake,
  # so the diagnostics are separated.
  if [[ $auth_denied -eq 1 ]]; then
    warn "cannot authenticate as app DB user '$db_user' (.env's MARIADB_PASSWORD does not match the existing DB volume)."
    warn "MariaDB fixes the data volume at the password from its first creation and ignores later .env changes."
    warn "trying to align the DB side with .env using the root credentials..."
    sync_app_db_password "$db_user" "$db_name" "$db_password" "$root_password" || sync_status=$?
    if [[ $sync_status -eq 0 ]] && try_app_db_auth "$db_user" "$db_name" "$db_password"; then
      log "synced the password of DB user '$db_user' to the .env value. DB authentication preflight OK."
      return 0
    fi
    compose_diagnostics_for mariadb
    if [[ $sync_status -eq 2 ]]; then
      err "cannot authenticate as app DB user '$db_user' nor as root (.env's secrets differ from the existing DB volume)."
      err "if .env was recreated or brought from another environment, KEY_ENCRYPTION_KEY has changed too, so"
      err "signing keys stored in the existing DB cannot be decrypted without the original .env."
      err "one of the following fixes:"
      err "  * to keep the data: restore the original .env (backup) and redeploy"
      err "  * if the data may be discarded (initial setup, staging, etc.): recreate the DB volume with ./deploy.sh reset (existing data is lost)"
      die "DB authentication preflight failed"
    fi
    err "cannot authenticate as app DB user '$db_user', and password sync via root also failed."
    err "one of the following fixes:"
    err "  * restore .env's MARIADB_ROOT_PASSWORD to the value at volume creation and redeploy to auto-sync"
    err "  * run manually as root: ALTER USER '$db_user'@'%' IDENTIFIED BY '<MARIADB_PASSWORD from .env>'; FLUSH PRIVILEGES;"
    err "  * if the data may be discarded (initial setup, staging, etc.): recreate the DB volume with ./deploy.sh reset (existing data is lost)"
    die "DB authentication preflight failed"
  fi
  err "DB authentication preflight failed for a reason other than authentication (user '$db_user', DB '$db_name')."
  err "check the connection path, DB existence, privileges and transient network failures (details in the mariadb logs above and the output below)."
  printf '%s\n' "$APP_DB_AUTH_ERROR" | mask_secrets >&2
  die "DB preflight failed (non-authentication error)"
}

start_database() {
  log "starting MariaDB..."
  "${compose[@]}" up -d mariadb
  wait_healthy mariadb
  preflight_db_auth
}

remove_stale_renamed_containers() {
  # When docker compose replaces with --force-recreate, it temporarily renames the old container to
  # "<first 12 chars of old container ID>_<container name>" before creating the new one.
  # If the previous deployment was interrupted midway, this renamed container remains and the next replacement
  # fails with "Conflict. The container name ... is already in use", so delete it beforehand.
  # Filter by Compose's project label so other projects are never deleted by mistake, and
  # accept both v2 (-) and v1 / compatibility mode (_) as the container name separator.
  local cid name
  while read -r cid name; do
    [[ -n "$cid" ]] || continue
    warn "deleting a temporary container left by the previous replacement: $name"
    docker rm -f "$cid" >/dev/null || warn "failed to delete temporary container $name (id=$cid)."
  done < <(docker ps -a --filter "label=com.docker.compose.project=${COMPOSE_PROJECT}" \
      --format '{{.ID}} {{.Names}}' 2>/dev/null \
    | grep -E "^[0-9a-f]+ [0-9a-f]{12}_${COMPOSE_PROJECT}[-_][a-z]+[-_][0-9]+$" || true)
}

# Host to connect to for hitting the published ports (returned in a form usable as a URL host).
# When the bind is a wildcard or unset, map it to the loopback of the same protocol. Mapping the IPv6
# wildcard (::) to the IPv4 loopback would not reach ports listening on IPv6 only and readiness
# would time out, so keep the protocol.
# IPv6 literals are bracketed because colons collide with the port separator (RFC 3986).
probe_host() {
  local bind_host="$1"
  case "$bind_host" in
    ""|0.0.0.0) printf '127.0.0.1\n' ;;      # unset (default 127.0.0.1), IPv4 wildcard
    "::"|"[::]") printf '[::1]\n' ;;         # IPv6 wildcard
    \[*\]) printf '%s\n' "$bind_host" ;;     # bracketed IPv6 literals as is
    *:*) printf '[%s]\n' "$bind_host" ;;     # bare IPv6 literals (e.g. ::1) get brackets
    *) printf '%s\n' "$bind_host" ;;         # IPv4 addresses, host names
  esac
}

replace_app_containers() {
  local web_port api_port web_host api_host issuer web_base root
  local -a ready_urls=()
  log "starting api, web and proxy (--force-recreate always replaces the app containers in every mode)..."
  remove_stale_renamed_containers
  "${compose[@]}" up -d --force-recreate --remove-orphans "${APP_SERVICES[@]}"
  wait_healthy api
  wait_healthy web
  wait_healthy proxy
  web_port="$(get_env_var WEB_PORT)"; web_port="${web_port:-8060}"
  web_host="$(probe_host "$(get_env_var WEB_BIND_HOST)")"
  issuer="$(get_env_var ISSUER)"; issuer="${issuer:-http://localhost:${web_port}}"
  # web returns the screens (/{tenant}/login, /{tenant}/admin), so the summary is based on web's
  # public origin. In single-origin setups PUBLIC_WEB_BASE_URL = ISSUER, so behaviour does not change.
  web_base="$(get_env_var PUBLIC_WEB_BASE_URL)"; web_base="${web_base:-$issuer}"
  ready_urls=("http://${web_host}:${web_port}/readyz")
  if [[ "$PUBLISH_TOPOLOGY" == "domain-split" ]]; then
    # In domain-split, web and api are published on separate ports, so check readiness of both.
    api_port="$(get_env_var API_PORT)"; api_port="${api_port:-8070}"
    api_host="$(probe_host "$(get_env_var API_BIND_HOST)")"
    ready_urls+=("http://${api_host}:${api_port}/readyz")
  fi
  log "checking readiness: ${ready_urls[*]}"
  for _ in $(seq 1 30); do
    if all_ready "${ready_urls[@]}"; then
      root="$(root_tenant_id)"; root="${root:-<root-tenant-id>}"
      # Keep the root tenant URLs to show in the summary at the end of deployment (end of the script).
      ROOT_LOGIN_URL="${web_base%/}/${root}/login"
      ROOT_ADMIN_URL="${web_base%/}/${root}/admin"
      log "readyz OK. Deployment completed."
      log "Login URL: $ROOT_LOGIN_URL"
      return 0
    fi
    sleep 2
  done
  compose_diagnostics
  die "readyz did not become OK (${ready_urls[*]})."
}

# Returns 0 if all given readiness URLs are OK.
all_ready() {
  local url
  for url in "$@"; do
    curl -fsS "$url" >/dev/null 2>&1 || return 1
  done
  return 0
}

# Show the root tenant URLs together at the end of deployment (so the operator can jump straight there).
# Uses the values settled by replace_app_containers when readyz was OK. Not shown if unsettled (early return etc.).
print_root_urls() {
  [[ -n "$ROOT_ADMIN_URL" || -n "$ROOT_LOGIN_URL" ]] || return 0
  log "──────────────────────────────────────────────"
  log "Root tenant URLs:"
  [[ -n "$ROOT_ADMIN_URL" ]] && log "  Admin console: $ROOT_ADMIN_URL"
  [[ -n "$ROOT_LOGIN_URL" ]] && log "  Login:         $ROOT_LOGIN_URL"
  log "──────────────────────────────────────────────"
}

phase_begin "env"; ensure_env_file; phase_end
init_compose_command
phase_begin "images"; ensure_images; phase_end

case "$mode" in
  reset)
    phase_begin "reset"
    warn "deleting the DB volume (.env is kept)."
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
print_root_urls
