#!/usr/bin/env bash
# scripts/test_deploy.sh — verifies deploy.sh's CLI and error handling with a stub docker (for CI).
set -Eeuo pipefail

# Most assertions are bare `grep -q` (no message), and on failure set -e exits without printing anything.
# No clue would remain in the CI log and the cause would be unknown until reproduced locally, so record the last failing line
# and expression and print them only on abnormal exit. ERR also fires in cases that verify deployment failure itself
# (intentional failures in set +e sections), so only record it there without printing.
LAST_ERR=""
trap 'LAST_ERR="line $LINENO: $BASH_COMMAND"' ERR

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Per-run work area. Copies of the deployment, stubs, deploy.sh output (*.out) and stub records all live under here.
# ⚠ Do not use a fixed /tmp/<name>. Running two at once in the same container, one greps the output while
#   the other is rewriting it, failing on a different line every time (https://task.nolumia.com/tasks/86).
TMP="$(mktemp -d)"
# Only one EXIT trap can be held, so cleanup and failure reporting are done together.
# On success, clean up. On failure, keep the intermediate output for inspection and print its location (the "$TMP/…" in LAST_ERR is
# the unexpanded text, so the actual location is known from here). Each run uses a different location, so keeping it never collides with the next.
on_exit() {
  local status=$?
  if [[ $status -eq 0 ]]; then
    rm -rf "$TMP"
    return
  fi
  [[ -z "$LAST_ERR" ]] ||
    echo "[test_deploy] FAILED (exit $status); last failing command was $LAST_ERR" >&2
  echo "[test_deploy] intermediate outputs kept in $TMP" >&2
}
trap on_exit EXIT

# --- Repository layout (scripts/deploy.sh + docker-compose.deploy.yml at the root) ---
mkdir -p "$TMP/repo/scripts" "$TMP/repo/docker" "$TMP/bin"
cp "$ROOT/scripts/deploy.sh" "$TMP/repo/scripts/"
cp "$ROOT/.env.example" "$ROOT/docker-compose.deploy.yml" "$ROOT/docker-compose.domain-split.yml" "$TMP/repo/"
cp "$ROOT/docker/nginx.conf" "$ROOT/docker/nginx.domain-split.conf" "$TMP/repo/docker/"

cat > "$TMP/bin/openssl" <<'STUB'
#!/usr/bin/env bash
case "${3:-$2}" in
  24) printf '0123456789abcdef0123456789abcdef0123456789abcdef' ;;
  32) printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' ;;
  *) printf 'stub-secret' ;;
esac
STUB
chmod +x "$TMP/bin/openssl"

cat > "$TMP/bin/curl" <<'STUB'
#!/usr/bin/env bash
# Record calls so the readiness probe targets can be verified (always succeeds).
if [[ -n "${CURL_STUB_LOG:-}" ]]; then printf 'curl %s\n' "$*" >>"$CURL_STUB_LOG"; fi
exit 0
STUB
chmod +x "$TMP/bin/curl"

cat > "$TMP/bin/docker" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
log="${DOCKER_STUB_LOG:?}"
printf 'docker %s\n' "$*" >>"$log"
if [[ "${1:-}" == "compose" ]]; then
  shift
  if [[ "${1:-}" == "version" ]]; then exit 0; fi
  while [[ "${1:-}" == "-f" || "${1:-}" == "--project-name" ]]; do shift 2; done
  case "${1:-}" in
    up) if [[ "${DOCKER_STUB_FAIL_UP:-0}" == "1" ]]; then echo "up failed with ${MARIADB_PASSWORD:-secret}" >&2; exit 42; fi; exit 0 ;;
    run)
      if [[ "${DOCKER_STUB_MIGRATE_CHECKSUM_MISMATCH:-0}" == "1" && "$*" == *"migrate"* ]]; then
        # When sqlx detects a modified applied migration, it aborts applying with this text.
        echo "error: migration 2 was previously applied but has been modified" >&2
        exit 1
      fi
      if [[ "${DOCKER_STUB_FAIL_MIGRATE:-0}" == "1" && "$*" == *"migrate"* ]]; then
        echo "migrate failed with ${MARIADB_PASSWORD:-secret}" >&2
        exit 17
      fi
      exit 0 ;;
    down) exit 0 ;;
    ps) printf 'cid-%s\n' "${3:-svc}"; exit 0 ;;
    exec)
      # Reading container environment variables (deploy.sh does not parse .env itself but reads Compose's resolution).
      # DOCKER_STUB_CONTAINER_ENV_FILE lets "the environment variables the container has" be replaced,
      # so cases where the .env text and the effective value differ (quotes, inline comments) can be verified.
      if [[ "$*" == *"printf %s"* ]]; then
        var="$(printf '%s' "$*" | grep -oE '\$\{[A-Za-z_]+' | tail -n1 | tr -d '${')"
        if [[ -n "${DOCKER_STUB_CONTAINER_ENV_FILE:-}" && -f "${DOCKER_STUB_CONTAINER_ENV_FILE}" && -n "$var" ]]; then
          line="$(grep -E "^${var}=" "$DOCKER_STUB_CONTAINER_ENV_FILE" | tail -n1 || true)"
          [[ -n "$line" ]] && printf '%s' "${line#*=}"
        fi
        exit 0
      fi
      # Password sync (ALTER USER as root). On success, record "synced" in a marker file so that afterwards
      # the app user's authentication also passes (mimics real DB behaviour).
      if [[ "$*" == *"ALTER USER"* ]]; then
        if [[ "${DOCKER_STUB_ROOT_AUTH_OK:-0}" == "1" ]]; then
          [[ -n "${DOCKER_STUB_SYNCED_MARKER:-}" ]] && : >"$DOCKER_STUB_SYNCED_MARKER"
          exit 0
        fi
        echo "ERROR 1045 (28000): Access denied for user 'root'@'localhost' (using password: YES)" >&2
        exit 1
      fi
      if [[ "$*" == *"SELECT 1"* ]]; then
        if [[ "$*" == *"-uroot"* ]]; then
          [[ "${DOCKER_STUB_ROOT_AUTH_OK:-0}" == "1" ]] && exit 0
          echo "ERROR 1045 (28000): Access denied for user 'root'@'localhost' (using password: YES)" >&2
          exit 1
        fi
        if [[ "${DOCKER_STUB_FAIL_DB_AUTH:-0}" == "1" ]]; then
          if [[ -n "${DOCKER_STUB_SYNCED_MARKER:-}" && -f "${DOCKER_STUB_SYNCED_MARKER}" ]]; then exit 0; fi
          echo "ERROR 1045 (28000): Access denied for user 'idp'@'172.27.0.6' (using password: YES)" >&2
          exit 1
        fi
        if [[ "${DOCKER_STUB_FAIL_DB_CONN:-0}" == "1" ]]; then
          echo "ERROR 1049 (42000): Unknown database 'idp'" >&2
          exit 1
        fi
        # Credentials are correct but there is no access to the DB. Starts with the same "Access denied for user"
        # as 1045, but it is not a password mismatch (error code 1044).
        if [[ "${DOCKER_STUB_FAIL_DB_PRIV:-0}" == "1" ]]; then
          echo "ERROR 1044 (42000): Access denied for user 'idp'@'%' to database 'idp'" >&2
          exit 1
        fi
      fi
      if [[ "$*" == *"SELECT id FROM tenants"* ]]; then printf '01970000-0000-7000-8000-000000000001\n'; fi
      exit 0 ;;
    logs) echo "stub docker logs for ${*: -1}: ${MARIADB_PASSWORD:-secret}"; exit 0 ;;
    # deploy.sh uses `config --services` to prevent the accident of "waiting forever for a service not in the definition".
    # DOCKER_STUB_SERVICES lets the definition list be replaced so that branch can be verified.
    config) tr ' ' '\n' <<<"${DOCKER_STUB_SERVICES:-api mariadb migrate proxy web}"; exit 0 ;;
  esac
fi
case "${1:-}" in
  image)
    if [[ "${2:-}" == "inspect" ]]; then
      if [[ "$*" == *"org.opencontainers.image.revision"* ]]; then printf 'stub-revision\n';
      elif [[ "$*" == *".Id"* ]]; then printf 'sha256:stub-image-id\n';
      fi
    fi
    exit 0 ;;
  load) exit 0 ;;
  inspect) printf 'healthy\n'; exit 0 ;;
  *) exit 0 ;;
esac
STUB
chmod +x "$TMP/bin/docker"

export PATH="$TMP/bin:$PATH"
export DOCKER_STUB_LOG="$TMP/docker.log"
cd "$TMP/repo"

if ./scripts/deploy.sh unknown >"$TMP/deploy-unknown.out" 2>&1; then
  echo "deploy.sh unknown mode must fail" >&2
  exit 1
fi
./scripts/deploy.sh migrate >"$TMP/deploy-migrate.out" 2>&1
[[ -f .env ]] || { echo ".env was not generated" >&2; exit 1; }
shopt -s nullglob
deploy_logs=(deploy-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9].log)
[[ ${#deploy_logs[@]} -ge 1 ]] || { echo "timestamped deploy log was not generated" >&2; exit 1; }
grep -q 'log file:' "${deploy_logs[0]}"
grep -q '^CSRF_SECRET=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=$' .env
before="$(grep '^MARIADB_PASSWORD=' .env)"
: >"$DOCKER_STUB_LOG"
./scripts/deploy.sh app >"$TMP/deploy-app.out" 2>&1
after="$(grep '^MARIADB_PASSWORD=' .env)"
[[ "$before" == "$after" ]] || { echo "existing .env was overwritten" >&2; exit 1; }
grep -q 'Login URL:' "$TMP/deploy-app.out"
# The root tenant URL summary at the end of deployment (including the admin console URL) is shown.
grep -q 'Root tenant URLs:' "$TMP/deploy-app.out"
grep -q 'Admin console: .*/admin' "$TMP/deploy-app.out"
grep -q -- '--project-name idp-repo -f docker-compose.deploy.yml' "$DOCKER_STUB_LOG"
grep -q 'run --rm -T migrate' "$DOCKER_STUB_LOG"

sed -i '/^COMPOSE_PROJECT_NAME=/d' .env
: >"$DOCKER_STUB_LOG"
./scripts/deploy.sh app >"$TMP/deploy-legacy-project.out" 2>&1
grep -q 'using the legacy Compose project name (repo) to protect existing volumes' "$TMP/deploy-legacy-project.out"
grep -q -- '--project-name repo -f docker-compose.deploy.yml' "$DOCKER_STUB_LOG"
if grep -q '^COMPOSE_PROJECT_NAME=' .env; then
  echo "existing legacy .env should not be backfilled automatically" >&2
  exit 1
fi

# "Setting keys (non-secret)" added by version updates are appended to the existing .env automatically (secrets and existing values unchanged).
sed -i '/^LOG_FORMAT=/d' .env
: >"$DOCKER_STUB_LOG"
./scripts/deploy.sh app >"$TMP/deploy-merge.out" 2>&1
grep -q '^LOG_FORMAT=pretty$' .env || { echo "missing non-secret key should be appended from .env.example" >&2; exit 1; }
# Placeholder (CHANGE-ME) secret values must not sneak in as assignment lines via append (words in comments are ignored).
if grep -qE '^[A-Za-z_][A-Za-z0-9_]*=.*CHANGE-ME' .env; then
  echo "merge must not inject CHANGE-ME placeholder values into .env" >&2
  exit 1
fi

# Even with a (hand-edited) .env without a trailing newline, append without breaking the last line's value (boundary normalization).
sed -i '/^LOG_FORMAT=/d' .env
printf 'SENTINEL_KEEP=keepme' >>.env   # make a last line without a trailing newline
: >"$DOCKER_STUB_LOG"
./scripts/deploy.sh app >"$TMP/deploy-nonl.out" 2>&1
grep -q '^SENTINEL_KEEP=keepme$' .env || { echo "last line without trailing newline was corrupted by append" >&2; exit 1; }
grep -q '^LOG_FORMAT=pretty$' .env || { echo "key not appended after newline normalization" >&2; exit 1; }

# Appending must not silently change an existing deployment's "public target / publish topology" (migration for ADR-0016's default change).
# Production-like: ISSUER is the public domain; PUBLIC_WEB_BASE_URL and PUBLISH_TOPOLOGY are absent from the .env of that time.
sed -i 's|^ISSUER=.*|ISSUER=https://idp.example.com|' .env
sed -i '/^PUBLIC_WEB_BASE_URL=/d' .env
sed -i '/^PUBLISH_TOPOLOGY=/d' .env
: >"$DOCKER_STUB_LOG"; : >"${CURL_STUB_LOG:-/dev/null}"
./scripts/deploy.sh app >"$TMP/deploy-migrate-topology.out" 2>&1
# PUBLIC_WEB_BASE_URL is not appended (unset = ISSUER fallback = previous behaviour). Writing localhost into
# a production .env would send only login, invitation and reset redirects to localhost.
if grep -q '^PUBLIC_WEB_BASE_URL=' .env; then
  echo "PUBLIC_WEB_BASE_URL must not be backfilled into an existing .env" >&2
  grep '^PUBLIC_WEB_BASE_URL=' .env >&2
  exit 1
fi
grep -q 'Login URL: https://idp.example.com/' "$TMP/deploy-migrate-topology.out" ||
  { echo "existing deployment must keep redirecting to its own ISSUER origin" >&2; exit 1; }
# A .env without PUBLISH_TOPOLOGY is a pre-ADR-0016 deployment = single origin, so keep that meaning.
grep -q '^PUBLISH_TOPOLOGY=single-origin$' .env ||
  { echo "missing PUBLISH_TOPOLOGY must be backfilled as single-origin, not the new default" >&2; exit 1; }
grep -q 'publish topology: single-origin' "$TMP/deploy-migrate-topology.out" ||
  { echo "existing deployment must keep the single-origin topology" >&2; exit 1; }
# Revert the values rewritten for the migration check to .env.example's defaults (precondition for the topology tests below).
sed -i 's|^ISSUER=.*|ISSUER=http://localhost:8070|' .env
sed -i 's/^PUBLISH_TOPOLOGY=.*/PUBLISH_TOPOLOGY=domain-split/' .env
printf 'PUBLIC_WEB_BASE_URL=http://localhost:8060\n' >>.env

# --- Publish topology (ADR-0015, ADR-0016; default domain-split / explicit single-origin) ---
export CURL_STUB_LOG="$TMP/curl.log"

# By default (.env.example's PUBLISH_TOPOLOGY=domain-split; ADR-0016) the override is layered and
# readiness of both web (WEB_PORT) and api (API_PORT) is checked.
: >"$DOCKER_STUB_LOG"; : >"$CURL_STUB_LOG"
./scripts/deploy.sh app >"$TMP/deploy-default-topology.out" 2>&1
grep -q 'publish topology: domain-split' "$TMP/deploy-default-topology.out" ||
  { echo "default topology must be domain-split" >&2; cat "$TMP/deploy-default-topology.out" >&2; exit 1; }
grep -q -- '-f docker-compose.deploy.yml -f docker-compose.domain-split.yml' "$DOCKER_STUB_LOG" ||
  { echo "default topology must overlay docker-compose.domain-split.yml" >&2; cat "$DOCKER_STUB_LOG" >&2; exit 1; }
grep -q 'http://127.0.0.1:8060/readyz' "$CURL_STUB_LOG" ||
  { echo "default topology must probe the web readiness endpoint" >&2; cat "$CURL_STUB_LOG" >&2; exit 1; }
grep -q 'http://127.0.0.1:8070/readyz' "$CURL_STUB_LOG" ||
  { echo "default topology must probe the api readiness endpoint" >&2; cat "$CURL_STUB_LOG" >&2; exit 1; }

# Even an empty PUBLISH_TOPOLOGY (no value) falls back to the default domain-split.
sed -i 's/^PUBLISH_TOPOLOGY=.*/PUBLISH_TOPOLOGY=/' .env
: >"$DOCKER_STUB_LOG"; : >"$CURL_STUB_LOG"
./scripts/deploy.sh app >"$TMP/deploy-topology-empty.out" 2>&1
grep -q 'publish topology: domain-split' "$TMP/deploy-topology-empty.out" ||
  { echo "empty PUBLISH_TOPOLOGY must fall back to domain-split" >&2; exit 1; }
sed -i 's/^PUBLISH_TOPOLOGY=.*/PUBLISH_TOPOLOGY=domain-split/' .env

# Publishing on a real domain takes the same path. Only the summary URLs switch to the public origin.
sed -i 's|^ISSUER=.*|ISSUER=https://api.example.com|' .env
sed -i 's|^PUBLIC_WEB_BASE_URL=.*|PUBLIC_WEB_BASE_URL=https://id.example.com|' .env
: >"$DOCKER_STUB_LOG"; : >"$CURL_STUB_LOG"
./scripts/deploy.sh app >"$TMP/deploy-domain-split.out" 2>&1
grep -q 'publish topology: domain-split' "$TMP/deploy-domain-split.out"
grep -q -- '-f docker-compose.deploy.yml -f docker-compose.domain-split.yml' "$DOCKER_STUB_LOG" ||
  { echo "domain-split must overlay docker-compose.domain-split.yml" >&2; cat "$DOCKER_STUB_LOG" >&2; exit 1; }
grep -q 'http://127.0.0.1:8060/readyz' "$CURL_STUB_LOG" ||
  { echo "domain-split must probe the web readiness endpoint" >&2; cat "$CURL_STUB_LOG" >&2; exit 1; }
grep -q 'http://127.0.0.1:8070/readyz' "$CURL_STUB_LOG" ||
  { echo "domain-split must probe the api readiness endpoint" >&2; cat "$CURL_STUB_LOG" >&2; exit 1; }
# web returns the screens (/login, /admin), so the summary URLs are based on PUBLIC_WEB_BASE_URL.
grep -q 'Login URL: https://id.example.com/' "$TMP/deploy-domain-split.out" ||
  { echo "login URL must be based on PUBLIC_WEB_BASE_URL, not ISSUER" >&2; cat "$TMP/deploy-domain-split.out" >&2; exit 1; }
grep -q 'Admin console: https://id.example.com/.*/admin' "$TMP/deploy-domain-split.out" ||
  { echo "admin URL must be based on PUBLIC_WEB_BASE_URL, not ISSUER" >&2; exit 1; }

# With an IPv6 bind, probe in a form usable as a URL host (bracketed).
# The wildcard (::) maps to the IPv6 loopback, not the IPv4 loopback
# (otherwise ports listening on IPv6 only are unreachable and readiness times out).
sed -i 's/^WEB_BIND_HOST=.*/WEB_BIND_HOST=::/' .env
sed -i 's/^API_BIND_HOST=.*/API_BIND_HOST=::1/' .env
: >"$DOCKER_STUB_LOG"; : >"$CURL_STUB_LOG"
./scripts/deploy.sh app >"$TMP/deploy-ipv6.out" 2>&1
grep -q 'http://\[::1\]:8060/readyz' "$CURL_STUB_LOG" ||
  { echo "IPv6 wildcard bind must probe the bracketed IPv6 loopback" >&2; cat "$CURL_STUB_LOG" >&2; exit 1; }
grep -q 'http://\[::1\]:8070/readyz' "$CURL_STUB_LOG" ||
  { echo "IPv6 literal bind must be bracketed in the probe URL" >&2; cat "$CURL_STUB_LOG" >&2; exit 1; }
sed -i 's/^WEB_BIND_HOST=.*/WEB_BIND_HOST=127.0.0.1/' .env
sed -i 's/^API_BIND_HOST=.*/API_BIND_HOST=127.0.0.1/' .env

# Specifying domain-split on a deployment without the override file fails fast.
mv docker-compose.domain-split.yml "$TMP/domain-split.yml.bak"
set +e
./scripts/deploy.sh app >"$TMP/deploy-domain-split-missing.out" 2>&1
status=$?
set -e
[[ $status -ne 0 ]] || { echo "domain-split without the overlay file must fail" >&2; exit 1; }
grep -q 'docker-compose.domain-split.yml is missing' "$TMP/deploy-domain-split-missing.out"
mv "$TMP/domain-split.yml.bak" docker-compose.domain-split.yml

# Unknown topology values fail fast instead of starting with a typo.
sed -i 's/^PUBLISH_TOPOLOGY=.*/PUBLISH_TOPOLOGY=split-domain/' .env
set +e
./scripts/deploy.sh app >"$TMP/deploy-topology-typo.out" 2>&1
status=$?
set -e
[[ $status -ne 0 ]] || { echo "unknown PUBLISH_TOPOLOGY must fail" >&2; exit 1; }
grep -q "invalid PUBLISH_TOPOLOGY: 'split-domain'" "$TMP/deploy-topology-typo.out"

# Only when single-origin is stated is the override not layered, and readiness checks just WEB_PORT.
sed -i 's/^PUBLISH_TOPOLOGY=.*/PUBLISH_TOPOLOGY=single-origin/' .env
sed -i 's|^ISSUER=.*|ISSUER=http://localhost:8060|' .env
# In single-origin, api and web are aligned to the same origin (= WEB_PORT).
sed -i 's|^PUBLIC_WEB_BASE_URL=.*|PUBLIC_WEB_BASE_URL=http://localhost:8060|' .env
: >"$DOCKER_STUB_LOG"; : >"$CURL_STUB_LOG"
./scripts/deploy.sh app >"$TMP/deploy-single-origin.out" 2>&1
grep -q 'publish topology: single-origin' "$TMP/deploy-single-origin.out"
if grep -q -- '-f docker-compose.domain-split.yml' "$DOCKER_STUB_LOG"; then
  echo "single-origin must not overlay the domain-split compose file" >&2
  exit 1
fi
grep -q 'http://127.0.0.1:8060/readyz' "$CURL_STUB_LOG" ||
  { echo "single-origin must probe the WEB_PORT readiness endpoint" >&2; cat "$CURL_STUB_LOG" >&2; exit 1; }
if grep -q 'http://127.0.0.1:8070/readyz' "$CURL_STUB_LOG"; then
  echo "single-origin must not probe the API_PORT readiness endpoint" >&2
  exit 1
fi
# In single-origin setups ISSUER and PUBLIC_WEB_BASE_URL are the same origin, so the summary URL is the same too.
grep -q 'Login URL: http://localhost:8060/' "$TMP/deploy-single-origin.out" ||
  { echo "single-origin login URL must stay on the WEB_PORT origin" >&2; exit 1; }

# A service not in the Compose definition fails immediately with the cause, not with a wait timeout.
set +e
DOCKER_STUB_SERVICES="api mariadb migrate web" ./scripts/deploy.sh app >"$TMP/deploy-missing-service.out" 2>&1
status=$?
set -e
[[ $status -ne 0 ]] || { echo "missing compose service must fail" >&2; exit 1; }
grep -q 'proxy is not in the Compose definition' "$TMP/deploy-missing-service.out"
unset CURL_STUB_LOG

set +e
DOCKER_STUB_FAIL_MIGRATE=1 ./scripts/deploy.sh migrate >"$TMP/deploy-migrate-fail.out" 2>&1
status=$?
set -e
[[ $status -eq 1 ]] || { echo "deploy migrate failure should exit with diagnostics" >&2; cat "$TMP/deploy-migrate-fail.out" >&2; exit 1; }
grep -q 'dumping Docker logs' "$TMP/deploy-migrate-fail.out"
grep -q '\[idp\]\[diagnostic\] logs tail: migrate' "$TMP/deploy-migrate-fail.out"
grep -q '\[idp\]\[diagnostic\] logs tail: mariadb' "$TMP/deploy-migrate-fail.out"
if grep -q "$(grep '^MARIADB_PASSWORD=' .env | cut -d= -f2-)" "$TMP/deploy-migrate-fail.out"; then
  echo "secret was not masked in migration diagnostics" >&2
  exit 1
fi

# A checksum mismatch of an applied migration (sqlx's "previously applied but has been modified") is a
# deterministic failure. Stop immediately without retrying and present the cause (modified applied file) and the fix (reset etc.).
: >"$DOCKER_STUB_LOG"
set +e
DOCKER_STUB_MIGRATE_CHECKSUM_MISMATCH=1 ./scripts/deploy.sh migrate >"$TMP/deploy-checksum-fail.out" 2>&1
status=$?
set -e
[[ $status -eq 1 ]] || { echo "deploy must fail fast on migration checksum mismatch" >&2; cat "$TMP/deploy-checksum-fail.out" >&2; exit 1; }
grep -q 'checksum' "$TMP/deploy-checksum-fail.out" ||
  { echo "checksum mismatch guidance must explain the checksum error" >&2; exit 1; }
grep -q 'version 2' "$TMP/deploy-checksum-fail.out" ||
  { echo "checksum mismatch guidance must name the affected migration version" >&2; exit 1; }
grep -q './deploy.sh reset' "$TMP/deploy-checksum-fail.out" ||
  { echo "checksum mismatch guidance must offer the reset remedy" >&2; exit 1; }
# State the conclusion (initialization needed) explicitly.
grep -q 'must be initialized' "$TMP/deploy-checksum-fail.out" ||
  { echo "checksum mismatch guidance must state that DB re-initialization is required" >&2; exit 1; }
# The backup command resolves via compose's service (mariadb) (robust to v1/v2 naming differences).
grep -q 'exec -T mariadb sh -c' "$TMP/deploy-checksum-fail.out" ||
  { echo "backup command must resolve the mariadb service via compose (v1/v2 safe)" >&2; exit 1; }
# Do not hard-code the Compose v2 container name (project-mariadb-1) (v1 uses project_mariadb_1).
if grep -qE 'docker exec [^ ]*-mariadb-1' "$TMP/deploy-checksum-fail.out"; then
  echo "backup command must not hardcode a compose-v2 container name" >&2
  exit 1
fi
# Do not bury the guidance in MariaDB's container logs (unrelated noise).
if grep -q '\[idp\]\[diagnostic\] logs tail: mariadb' "$TMP/deploy-checksum-fail.out"; then
  echo "checksum mismatch must not bury guidance under mariadb container logs" >&2
  exit 1
fi

# The DB name to back up resolves in the order ENV > .env (if MARIADB_DATABASE is overridden in the environment,
# the command dumps that DB rather than the default idp).
: >"$DOCKER_STUB_LOG"
set +e
MARIADB_DATABASE=tenantdb DOCKER_STUB_MIGRATE_CHECKSUM_MISMATCH=1 ./scripts/deploy.sh migrate >"$TMP/deploy-checksum-dbname.out" 2>&1
set -e
grep -q -- '--single-transaction tenantdb' "$TMP/deploy-checksum-dbname.out" ||
  { echo "backup command must honor MARIADB_DATABASE env override (env > .env)" >&2; cat "$TMP/deploy-checksum-dbname.out" >&2; exit 1; }
# Deterministic failures are not retried (migrate runs only once).
if [[ "$(grep -c 'run --rm -T migrate' "$DOCKER_STUB_LOG")" -ne 1 ]]; then
  echo "checksum mismatch must not be retried (migrate should run exactly once)" >&2
  cat "$DOCKER_STUB_LOG" >&2
  exit 1
fi
if grep -q 'DB migration failed after 3 attempts' "$TMP/deploy-checksum-fail.out"; then
  echo "checksum mismatch must fail fast, not exhaust retries" >&2
  exit 1
fi

# mask_secrets must not break even if secret values contain sed metacharacters ([ . * ^ $ | etc.). Masking runs
# on every successful migrate too, so a failure here would abort even successful deployments via pipefail.
orig_pw_line="$(grep '^MARIADB_PASSWORD=' .env)"
: >"$DOCKER_STUB_LOG"
sed -i 's|^MARIADB_PASSWORD=.*|MARIADB_PASSWORD=p[a.s*s^d$x|' .env
set +e
./scripts/deploy.sh app >"$TMP/deploy-metachar-secret.out" 2>&1
status=$?
set -e
[[ $status -eq 0 ]] || { echo "metacharacter secret must not abort a successful deploy" >&2; cat "$TMP/deploy-metachar-secret.out" >&2; exit 1; }
if grep -qF 'p[a.s*s^d$x' "$TMP/deploy-metachar-secret.out"; then
  echo "metacharacter secret must be masked (not leaked) in deploy output" >&2
  exit 1
fi
# Restore .env to the original password so later tests are not affected.
sed -i "s|^MARIADB_PASSWORD=.*|${orig_pw_line}|" .env

# Short values (MARIADB_PASSWORD=idp etc. used in development and CI) must not be masked. Masking is a simple
# substring replacement on log text, so mangling `idp` would also erase `[idp][diagnostic]`, making diagnostics unreadable.
: >"$DOCKER_STUB_LOG"
set +e
MARIADB_PASSWORD=idp MARIADB_ROOT_PASSWORD=root DOCKER_STUB_FAIL_UP=1 \
  ./scripts/deploy.sh app >"$TMP/deploy-short-secret.out" 2>&1
status=$?
set -e
[[ $status -eq 42 ]] || { echo "deploy failure should preserve failing exit code" >&2; cat "$TMP/deploy-short-secret.out" >&2; exit 1; }
grep -q '\[idp\]\[diagnostic\] compose ps' "$TMP/deploy-short-secret.out" ||
  { echo "short secret values must not be masked (diagnostics became unreadable)" >&2; cat "$TMP/deploy-short-secret.out" >&2; exit 1; }

# DB credentials use the effective value resolved by Compose (the mariadb container's environment), not the .env text.
# Reimplementing `.env`'s dotenv syntax (quotes, inline comments, variable expansion) in deploy.sh always
# diverges, and password sync would write a wrong value into the DB.
: >"$DOCKER_STUB_LOG"
export DOCKER_STUB_CONTAINER_ENV_FILE="$TMP/container-env"
cat > "$DOCKER_STUB_CONTAINER_ENV_FILE" <<'ENVEOF'
MARIADB_USER=idp
MARIADB_DATABASE=idp
MARIADB_PASSWORD=resolved-secret
MARIADB_ROOT_PASSWORD=resolved-root-secret
ENVEOF
# Put in .env a form (quotes + inline comment) that Compose resolves to `resolved-secret`.
sed -i 's|^MARIADB_PASSWORD=.*|MARIADB_PASSWORD="resolved-secret" # rotated|' .env
./scripts/deploy.sh migrate >"$TMP/deploy-resolved-secret.out" 2>&1
grep -qF -- '-presolved-secret' "$DOCKER_STUB_LOG" ||
  { echo "DB credentials must come from the Compose-resolved container environment" >&2; cat "$DOCKER_STUB_LOG" >&2; exit 1; }
if grep -qF -- '-p"resolved-secret"' "$DOCKER_STUB_LOG"; then
  echo "raw .env text must not be passed through to the DB client" >&2
  exit 1
fi
# The effective value is masked even if it does not match the .env text (prevents leaks via diagnostic output).
if grep -qF 'resolved-secret' "$TMP/deploy-resolved-secret.out"; then
  echo "Compose-resolved secret must be masked in deploy output" >&2
  exit 1
fi
sed -i "s|^MARIADB_PASSWORD=.*|${orig_pw_line}|" .env
rm -f "$DOCKER_STUB_CONTAINER_ENV_FILE"
unset DOCKER_STUB_CONTAINER_ENV_FILE

# Correct credentials without access to the DB (1044) are not a password mismatch (1045).
# Report it as a generic error that neither widens privileges via GRANT nor recommends the destructive reset.
: >"$DOCKER_STUB_LOG"
set +e
DOCKER_STUB_FAIL_DB_PRIV=1 DOCKER_STUB_ROOT_AUTH_OK=1 \
  ./scripts/deploy.sh migrate >"$TMP/deploy-db-priv-fail.out" 2>&1
status=$?
set -e
[[ $status -eq 1 ]] || { echo "deploy must fail fast on a privilege error" >&2; cat "$TMP/deploy-db-priv-fail.out" >&2; exit 1; }
grep -q 'DB preflight failed (non-authentication error)' "$TMP/deploy-db-priv-fail.out" ||
  { echo "privilege error must not be reported as password drift" >&2; cat "$TMP/deploy-db-priv-fail.out" >&2; exit 1; }
if grep -q 'ALTER USER\|GRANT ALL' "$DOCKER_STUB_LOG"; then
  echo "privilege error must not trigger password sync / GRANT" >&2
  cat "$DOCKER_STUB_LOG" >&2
  exit 1
fi
if grep -q './deploy.sh reset' "$TMP/deploy-db-priv-fail.out"; then
  echo "privilege error must NOT recommend destructive reset" >&2
  exit 1
fi

# If the app user's authentication fails but root is valid, align the DB-side password with .env to recover
# and continue deploying (resolving drift while keeping existing data).
: >"$DOCKER_STUB_LOG"
export DOCKER_STUB_SYNCED_MARKER="$TMP/db-password-synced"
rm -f "$DOCKER_STUB_SYNCED_MARKER"
set +e
DOCKER_STUB_FAIL_DB_AUTH=1 DOCKER_STUB_ROOT_AUTH_OK=1 \
  ./scripts/deploy.sh migrate >"$TMP/deploy-db-auth-sync.out" 2>&1
status=$?
set -e
[[ $status -eq 0 ]] || {
  echo "deploy must recover from password drift when root credentials are valid" >&2
  cat "$TMP/deploy-db-auth-sync.out" >&2; exit 1
}
grep -q 'ALTER USER' "$DOCKER_STUB_LOG" ||
  { echo "password drift must be repaired via ALTER USER" >&2; cat "$DOCKER_STUB_LOG" >&2; exit 1; }
grep -q 'run --rm -T migrate' "$DOCKER_STUB_LOG" ||
  { echo "migrate must run after the password was synced" >&2; exit 1; }
if grep -q "$(grep '^MARIADB_PASSWORD=' .env | cut -d= -f2-)" "$TMP/deploy-db-auth-sync.out"; then
  echo "secret was not masked while syncing the DB password" >&2
  exit 1
fi
rm -f "$DOCKER_STUB_SYNCED_MARKER"
unset DOCKER_STUB_SYNCED_MARKER

# When neither the app user nor root can authenticate (= the .env as a whole differs), stop immediately in the preflight
# instead of pointless migrate retries, and present the cause and fix.
: >"$DOCKER_STUB_LOG"
set +e
DOCKER_STUB_FAIL_DB_AUTH=1 ./scripts/deploy.sh migrate >"$TMP/deploy-db-auth-fail.out" 2>&1
status=$?
set -e
[[ $status -eq 1 ]] || { echo "deploy must fail fast when app DB user auth fails" >&2; cat "$TMP/deploy-db-auth-fail.out" >&2; exit 1; }
grep -q 'DB authentication preflight failed' "$TMP/deploy-db-auth-fail.out" ||
  { echo "preflight failure diagnostic missing" >&2; exit 1; }
grep -q 'MARIADB_PASSWORD' "$TMP/deploy-db-auth-fail.out" ||
  { echo "preflight diagnostic must mention MARIADB_PASSWORD mismatch" >&2; exit 1; }
grep -q './deploy.sh reset' "$TMP/deploy-db-auth-fail.out" ||
  { echo "preflight diagnostic must suggest reset remedy" >&2; exit 1; }
if grep -q 'run --rm -T migrate' "$DOCKER_STUB_LOG"; then
  echo "migrate must not run when DB auth preflight fails" >&2
  exit 1
fi
if grep -q 'ALTER USER' "$DOCKER_STUB_LOG"; then
  echo "password must not be altered when root credentials are invalid too" >&2
  exit 1
fi
if grep -q "$(grep '^MARIADB_PASSWORD=' .env | cut -d= -f2-)" "$TMP/deploy-db-auth-fail.out"; then
  echo "secret was not masked in preflight diagnostics" >&2
  exit 1
fi

# When the preflight fails for non-authentication reasons (e.g. missing DB), report it as a generic connection/query failure,
# not the password-drift diagnosis recommending the destructive reset (do not lead to data deletion by mistake).
: >"$DOCKER_STUB_LOG"
set +e
DOCKER_STUB_FAIL_DB_CONN=1 ./scripts/deploy.sh migrate >"$TMP/deploy-db-conn-fail.out" 2>&1
status=$?
set -e
[[ $status -eq 1 ]] || { echo "deploy must fail fast on non-auth preflight error" >&2; cat "$TMP/deploy-db-conn-fail.out" >&2; exit 1; }
grep -q 'DB preflight failed (non-authentication error)' "$TMP/deploy-db-conn-fail.out" ||
  { echo "non-auth preflight failure must be reported distinctly" >&2; exit 1; }
if grep -q './deploy.sh reset' "$TMP/deploy-db-conn-fail.out"; then
  echo "non-auth preflight failure must NOT recommend destructive reset" >&2
  exit 1
fi
if grep -q 'run --rm -T migrate' "$DOCKER_STUB_LOG"; then
  echo "migrate must not run when DB preflight fails" >&2
  exit 1
fi

./scripts/deploy.sh reset >"$TMP/deploy-reset.out" 2>&1
grep -q 'down -v --remove-orphans' "$DOCKER_STUB_LOG"

set +e
DOCKER_STUB_FAIL_UP=1 ./scripts/deploy.sh app >"$TMP/deploy-fail.out" 2>&1
status=$?
set -e
[[ $status -eq 42 ]] || { echo "deploy failure should preserve failing exit code" >&2; cat "$TMP/deploy-fail.out" >&2; exit 1; }
grep -q '\[idp\]\[diagnostic\] compose ps' "$TMP/deploy-fail.out"
if grep -q "$(grep '^MARIADB_PASSWORD=' .env | cut -d= -f2-)" "$TMP/deploy-fail.out"; then
  echo "secret was not masked in diagnostics" >&2
  exit 1
fi

# --- Bundle layout (equivalent to build.sh's dist/ output; compose and tars next to deploy.sh) ---
mkdir -p "$TMP/bundle/docker"
cp "$ROOT/scripts/deploy.sh" "$TMP/bundle/"
cp "$ROOT/docker-compose.deploy.yml" "$TMP/bundle/docker-compose.yml"
cp "$ROOT/.env.example" "$TMP/bundle/"
cp "$ROOT/docker/nginx.conf" "$TMP/bundle/docker/"
# build.sh always bundles the override set for the default topology (domain-split) too.
cp "$ROOT/docker-compose.domain-split.yml" "$TMP/bundle/"
cp "$ROOT/docker/nginx.domain-split.conf" "$TMP/bundle/docker/"
for svc in api web migrate; do
  touch "$TMP/bundle/assay-${svc}.tar"
  printf '%s_ref=idp/%s:latest\n%s_image_id=sha256:stub-image-id\n' "$svc" "$svc" "$svc"
done >"$TMP/bundle/manifest.env"
cd "$TMP/bundle"

: >"$DOCKER_STUB_LOG"
./deploy.sh app >"$TMP/deploy-bundle.out" 2>&1
grep -q 'Login URL:' "$TMP/deploy-bundle.out"
grep -q -- '--project-name idp-bundle -f docker-compose.yml' "$DOCKER_STUB_LOG"

# When the manifest and the image ID disagree, load the tar, and fail if they still disagree.
sed -i 's/^api_image_id=.*/api_image_id=sha256:expected-other-id/' manifest.env
: >"$DOCKER_STUB_LOG"
if ./deploy.sh app >"$TMP/deploy-bundle-mismatch.out" 2>&1; then
  echo "deploy.sh must fail when image ID mismatches manifest" >&2
  exit 1
fi
grep -q 'load -i' "$DOCKER_STUB_LOG"
grep -q 'does not match the manifest' "$TMP/deploy-bundle-mismatch.out"

# --- In a stg directory the first .env is generated from .env.staging.example (environment decided by directory name) ---
mkdir -p "$TMP/stg/docker"
cp "$ROOT/scripts/deploy.sh" "$TMP/stg/"
cp "$ROOT/docker-compose.deploy.yml" "$TMP/stg/docker-compose.yml"
cp "$ROOT/.env.example" "$ROOT/.env.staging.example" "$TMP/stg/"
cp "$ROOT/docker/nginx.conf" "$TMP/stg/docker/"
cp "$ROOT/docker-compose.domain-split.yml" "$TMP/stg/"
cp "$ROOT/docker/nginx.domain-split.conf" "$TMP/stg/docker/"
for svc in api web migrate; do
  touch "$TMP/stg/assay-${svc}.tar"
  printf '%s_ref=idp/%s:stg\n%s_image_id=sha256:stub-image-id\n' "$svc" "$svc" "$svc"
done >"$TMP/stg/manifest.env"
cd "$TMP/stg"

: >"$DOCKER_STUB_LOG"
./deploy.sh migrate >"$TMP/deploy-stg.out" 2>&1
grep -q 'source: .env.staging.example' "$TMP/deploy-stg.out" ||
  { echo "stg dir must seed .env from .env.staging.example" >&2; cat "$TMP/deploy-stg.out" >&2; exit 1; }
grep -q '^WEB_PORT=10010$' .env || { echo "stg .env must use staging WEB_PORT (10010)" >&2; exit 1; }
grep -q '^IMAGE_TAG=stg$' .env || { echo "stg .env must use staging IMAGE_TAG (stg)" >&2; exit 1; }
grep -q '^COMPOSE_PROJECT_NAME=idp-stg$' .env || { echo "stg .env must use idp-stg project name" >&2; exit 1; }
# DATABASE_URL keeps the template's :3307 while replacing CHANGE-ME with the real password.
grep -qE '^DATABASE_URL=mysql://idp:[0-9a-f]+@127\.0\.0\.1:3307/idp$' .env ||
  { echo "stg DATABASE_URL must keep :3307 and fill the password" >&2; cat .env >&2; exit 1; }
if grep -qE '^[A-Za-z_][A-Za-z0-9_]*=.*CHANGE-ME' .env; then
  echo "generated stg .env must not keep CHANGE-ME secrets" >&2
  exit 1
fi
grep -q -- '--project-name idp-stg -f docker-compose.yml' "$DOCKER_STUB_LOG"
grep -q '^API_PORT=10011$' .env || { echo "stg .env must use staging API_PORT (10011)" >&2; exit 1; }
# ADR-0018 decision 4: the session Cookie is host-only. COOKIE_DOMAIN is not set by default
# (enabled only temporarily for migration cleanup from the old setup).
if grep -qE '^COOKIE_DOMAIN=' .env; then
  echo "stg .env must not set COOKIE_DOMAIN by default (ADR-0018)" >&2; exit 1
fi

# --- If placeholder CHANGE-ME remains in an existing .env, fail fast before starting containers ---
# (If `.env.*.example` is copied by hand and not replaced, the api cannot decode KEY_ENCRYPTION_KEY as base64
#   and crash-loops. deploy.sh must stop, naming the offending key and the generation command.)
sed -i 's|^KEY_ENCRYPTION_KEY=.*|KEY_ENCRYPTION_KEY=CHANGE-ME|' .env
: >"$DOCKER_STUB_LOG"
set +e
./deploy.sh app >"$TMP/deploy-placeholder.out" 2>&1
status=$?
set -e
[[ $status -eq 1 ]] || { echo "deploy must fail fast when CHANGE-ME remains in .env" >&2; cat "$TMP/deploy-placeholder.out" >&2; exit 1; }
grep -q 'CHANGE-ME remains in .env: KEY_ENCRYPTION_KEY' "$TMP/deploy-placeholder.out" ||
  { echo "placeholder diagnostic must name the offending key" >&2; cat "$TMP/deploy-placeholder.out" >&2; exit 1; }
grep -q 'openssl rand -base64 32' "$TMP/deploy-placeholder.out" ||
  { echo "placeholder diagnostic must include the generation command" >&2; exit 1; }
if grep -q 'up -d' "$DOCKER_STUB_LOG"; then
  echo "containers must not start when placeholder secrets remain" >&2
  exit 1
fi

echo "deploy script tests passed"
