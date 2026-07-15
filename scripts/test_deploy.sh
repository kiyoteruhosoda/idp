#!/usr/bin/env bash
# scripts/test_deploy.sh — deploy.sh の CLI/エラー処理をスタブ docker で検証する（CI 用）。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# --- リポジトリ配置（scripts/deploy.sh ＋ ルートの docker-compose.deploy.yml） ---
mkdir -p "$TMP/repo/scripts" "$TMP/repo/docker" "$TMP/bin"
cp "$ROOT/scripts/deploy.sh" "$TMP/repo/scripts/"
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
    run)
      if [[ "${DOCKER_STUB_FAIL_MIGRATE:-0}" == "1" && "$*" == *"migrate"* ]]; then
        echo "migrate failed with ${MARIADB_PASSWORD:-secret}" >&2
        exit 17
      fi
      exit 0 ;;
    down) exit 0 ;;
    ps) printf 'cid-%s\n' "${3:-svc}"; exit 0 ;;
    exec)
      if [[ "$*" == *"SELECT id FROM tenants"* ]]; then printf '01970000-0000-7000-8000-000000000001\n'; fi
      exit 0 ;;
    logs) echo "stub docker logs for ${*: -1}: ${MARIADB_PASSWORD:-secret}"; exit 0 ;;
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

if ./scripts/deploy.sh unknown >/tmp/deploy-unknown.out 2>&1; then
  echo "deploy.sh unknown mode must fail" >&2
  exit 1
fi
./scripts/deploy.sh migrate >/tmp/deploy-migrate.out 2>&1
[[ -f .env ]] || { echo ".env was not generated" >&2; exit 1; }
grep -q '^CSRF_SECRET=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=$' .env
before="$(grep '^MARIADB_PASSWORD=' .env)"
: >"$DOCKER_STUB_LOG"
./scripts/deploy.sh app >/tmp/deploy-app.out 2>&1
after="$(grep '^MARIADB_PASSWORD=' .env)"
[[ "$before" == "$after" ]] || { echo "existing .env was overwritten" >&2; exit 1; }
grep -q 'ログイン URL:' /tmp/deploy-app.out
grep -q '\-f docker-compose.deploy.yml' "$DOCKER_STUB_LOG"
grep -q 'run --rm migrate' "$DOCKER_STUB_LOG"

set +e
DOCKER_STUB_FAIL_MIGRATE=1 ./scripts/deploy.sh migrate >/tmp/deploy-migrate-fail.out 2>&1
status=$?
set -e
[[ $status -eq 1 ]] || { echo "deploy migrate failure should exit with diagnostics" >&2; cat /tmp/deploy-migrate-fail.out >&2; exit 1; }
grep -q 'Docker logs を出力します' /tmp/deploy-migrate-fail.out
grep -q '\[idp\]\[diagnostic\] logs tail: migrate' /tmp/deploy-migrate-fail.out
grep -q '\[idp\]\[diagnostic\] logs tail: mariadb' /tmp/deploy-migrate-fail.out
if grep -q "$(grep '^MARIADB_PASSWORD=' .env | cut -d= -f2-)" /tmp/deploy-migrate-fail.out; then
  echo "secret was not masked in migration diagnostics" >&2
  exit 1
fi

./scripts/deploy.sh reset >/tmp/deploy-reset.out 2>&1
grep -q 'down -v --remove-orphans' "$DOCKER_STUB_LOG"

set +e
DOCKER_STUB_FAIL_UP=1 ./scripts/deploy.sh app >/tmp/deploy-fail.out 2>&1
status=$?
set -e
[[ $status -eq 42 ]] || { echo "deploy failure should preserve failing exit code" >&2; cat /tmp/deploy-fail.out >&2; exit 1; }
grep -q '\[idp\]\[diagnostic\] compose ps' /tmp/deploy-fail.out
if grep -q "$(grep '^MARIADB_PASSWORD=' .env | cut -d= -f2-)" /tmp/deploy-fail.out; then
  echo "secret was not masked in diagnostics" >&2
  exit 1
fi

# --- バンドル配置（build.sh が出力する dist/ 相当。deploy.sh の隣に compose と tar） ---
mkdir -p "$TMP/bundle/docker"
cp "$ROOT/scripts/deploy.sh" "$TMP/bundle/"
cp "$ROOT/docker-compose.deploy.yml" "$TMP/bundle/docker-compose.yml"
cp "$ROOT/.env.example" "$TMP/bundle/"
cp "$ROOT/docker/nginx.conf" "$TMP/bundle/docker/"
for svc in api web migrate; do
  touch "$TMP/bundle/idp-${svc}.tar"
  printf '%s_ref=idp/%s:latest\n%s_image_id=sha256:stub-image-id\n' "$svc" "$svc" "$svc"
done >"$TMP/bundle/manifest.env"
cd "$TMP/bundle"

: >"$DOCKER_STUB_LOG"
./deploy.sh app >/tmp/deploy-bundle.out 2>&1
grep -q 'ログイン URL:' /tmp/deploy-bundle.out
grep -q '\-f docker-compose.yml' "$DOCKER_STUB_LOG"

# manifest と image ID が食い違う場合は tar を読み込み、なお不一致なら失敗する。
sed -i 's/^api_image_id=.*/api_image_id=sha256:expected-other-id/' manifest.env
: >"$DOCKER_STUB_LOG"
if ./deploy.sh app >/tmp/deploy-bundle-mismatch.out 2>&1; then
  echo "deploy.sh must fail when image ID mismatches manifest" >&2
  exit 1
fi
grep -q 'load -i' "$DOCKER_STUB_LOG"
grep -q 'image ID が manifest と不一致' /tmp/deploy-bundle-mismatch.out

echo "deploy script tests passed"
