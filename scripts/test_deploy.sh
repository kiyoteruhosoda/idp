#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/repo/scripts" "$TMP/repo/docker" "$TMP/bin"
cp "$ROOT/scripts/deploy.sh" "$ROOT/scripts/init.sh" "$ROOT/scripts/lib.sh" "$TMP/repo/scripts/"
cp "$ROOT/.env.example" "$ROOT/docker-compose.deploy.yml" "$TMP/repo/"
cp "$ROOT/docker/nginx.conf" "$TMP/repo/docker/"

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
  while [[ "${1:-}" == "-f" ]]; do shift 2; done
  case "${1:-}" in
    up) if [[ "${DOCKER_STUB_FAIL_UP:-0}" == "1" ]]; then echo "up failed with ${MARIADB_PASSWORD:-secret}" >&2; exit 42; fi; exit 0 ;;
    run|down) exit 0 ;;
    ps) printf 'cid-%s\n' "${3:-svc}"; exit 0 ;;
    exec)
      if [[ "$*" == *"SELECT id FROM tenants"* ]]; then printf '01970000-0000-7000-8000-000000000001\n'; fi
      exit 0 ;;
    config)
      if [[ "${2:-}" == "--format" ]]; then printf '{"name":"idp-test"}\n'; else printf 'services: {}\n'; fi
      exit 0 ;;
    logs) exit 0 ;;
  esac
fi
case "${1:-}" in
  image) exit 0 ;;
  pull) exit 0 ;;
  inspect) printf 'healthy\n'; exit 0 ;;
  *) exit 0 ;;
esac
STUB
chmod +x "$TMP/bin/docker"

export PATH="$TMP/bin:$PATH"
export DOCKER_STUB_LOG="$TMP/docker.log"
cd "$TMP/repo"

if ./scripts/deploy.sh >/tmp/deploy-usage.out 2>&1; then
  echo "deploy.sh without args must fail" >&2
  exit 1
fi
if ./scripts/deploy.sh unknown >/tmp/deploy-unknown.out 2>&1; then
  echo "deploy.sh unknown mode must fail" >&2
  exit 1
fi
if ./scripts/deploy.sh reset >/tmp/deploy-reset-no.out 2>&1; then
  echo "deploy.sh reset without --yes must fail" >&2
  exit 1
fi

./scripts/deploy.sh migration >/tmp/deploy-migration.out 2>&1
[[ -f .env ]] || { echo ".env was not generated" >&2; exit 1; }
grep -q '^CSRF_SECRET=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=$' .env
before="$(grep '^MARIADB_PASSWORD=' .env)"
./scripts/deploy.sh app >/tmp/deploy-app.out 2>&1
after="$(grep '^MARIADB_PASSWORD=' .env)"
[[ "$before" == "$after" ]] || { echo "existing .env was overwritten" >&2; exit 1; }
grep -q 'ログイン URL:' /tmp/deploy-app.out
./scripts/deploy.sh reset --yes >/tmp/deploy-reset.out 2>&1
grep -q 'down -v --remove-orphans' "$DOCKER_STUB_LOG"

set +e
DOCKER_STUB_FAIL_UP=1 ./scripts/deploy.sh app >/tmp/deploy-fail.out 2>&1
status=$?
set -e
[[ $status -eq 42 ]] || { echo "deploy failure should preserve failing exit code" >&2; cat /tmp/deploy-fail.out >&2; exit 1; }
grep -q '\[idp\]\[diagnostic\] compose ps' /tmp/deploy-fail.out
grep -q 'logs tail: api' /tmp/deploy-fail.out
if grep -q "$(grep '^MARIADB_PASSWORD=' .env | cut -d= -f2-)" /tmp/deploy-fail.out; then
  echo "secret was not masked in diagnostics" >&2
  exit 1
fi

echo "deploy script tests passed"
