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
  while [[ "${1:-}" == "-f" || "${1:-}" == "--project-name" ]]; do shift 2; done
  case "${1:-}" in
    up) if [[ "${DOCKER_STUB_FAIL_UP:-0}" == "1" ]]; then echo "up failed with ${MARIADB_PASSWORD:-secret}" >&2; exit 42; fi; exit 0 ;;
    run)
      if [[ "${DOCKER_STUB_MIGRATE_CHECKSUM_MISMATCH:-0}" == "1" && "$*" == *"migrate"* ]]; then
        # sqlx は適用済みマイグレーションの改変を検出すると、この文言で適用を中止する。
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
      if [[ "${DOCKER_STUB_FAIL_DB_AUTH:-0}" == "1" && "$*" == *"SELECT 1"* ]]; then
        echo "ERROR 1045 (28000): Access denied for user 'idp'@'172.27.0.6' (using password: YES)" >&2
        exit 1
      fi
      if [[ "${DOCKER_STUB_FAIL_DB_CONN:-0}" == "1" && "$*" == *"SELECT 1"* ]]; then
        echo "ERROR 1049 (42000): Unknown database 'idp'" >&2
        exit 1
      fi
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
shopt -s nullglob
deploy_logs=(deploy-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9].log)
[[ ${#deploy_logs[@]} -ge 1 ]] || { echo "timestamped deploy log was not generated" >&2; exit 1; }
grep -q 'ログファイル:' "${deploy_logs[0]}"
grep -q '^CSRF_SECRET=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=$' .env
before="$(grep '^MARIADB_PASSWORD=' .env)"
: >"$DOCKER_STUB_LOG"
./scripts/deploy.sh app >/tmp/deploy-app.out 2>&1
after="$(grep '^MARIADB_PASSWORD=' .env)"
[[ "$before" == "$after" ]] || { echo "existing .env was overwritten" >&2; exit 1; }
grep -q 'ログイン URL:' /tmp/deploy-app.out
# デプロイ末尾の root テナント URL まとめ（管理コンソール URL を含む）を表示する。
grep -q 'Root テナント URL:' /tmp/deploy-app.out
grep -q '管理コンソール: .*/admin' /tmp/deploy-app.out
grep -q -- '--project-name idp-repo -f docker-compose.deploy.yml' "$DOCKER_STUB_LOG"
grep -q 'run --rm -T migrate' "$DOCKER_STUB_LOG"

sed -i '/^COMPOSE_PROJECT_NAME=/d' .env
: >"$DOCKER_STUB_LOG"
./scripts/deploy.sh app >/tmp/deploy-legacy-project.out 2>&1
grep -q '既存 volume を保護するため従来の Compose project name (repo) を使用します' /tmp/deploy-legacy-project.out
grep -q -- '--project-name repo -f docker-compose.deploy.yml' "$DOCKER_STUB_LOG"
if grep -q '^COMPOSE_PROJECT_NAME=' .env; then
  echo "existing legacy .env should not be backfilled automatically" >&2
  exit 1
fi

# バージョン更新で増えた「設定キー（非秘密）」は既存 .env へ自動追記される（秘密・既存値は不変）。
sed -i '/^LOG_FORMAT=/d' .env
: >"$DOCKER_STUB_LOG"
./scripts/deploy.sh app >/tmp/deploy-merge.out 2>&1
grep -q '^LOG_FORMAT=pretty$' .env || { echo "missing non-secret key should be appended from .env.example" >&2; exit 1; }
# プレースホルダ（CHANGE-ME）の秘密値が代入行として追記で混入しないこと（コメント中の語は無視）。
if grep -qE '^[A-Za-z_][A-Za-z0-9_]*=.*CHANGE-ME' .env; then
  echo "merge must not inject CHANGE-ME placeholder values into .env" >&2
  exit 1
fi

# 末尾改行の無い（手編集）.env でも、最終行の値を壊さず追記する（境界の正規化）。
sed -i '/^LOG_FORMAT=/d' .env
printf 'SENTINEL_KEEP=keepme' >>.env   # 末尾改行なしの最終行を作る
: >"$DOCKER_STUB_LOG"
./scripts/deploy.sh app >/tmp/deploy-nonl.out 2>&1
grep -q '^SENTINEL_KEEP=keepme$' .env || { echo "last line without trailing newline was corrupted by append" >&2; exit 1; }
grep -q '^LOG_FORMAT=pretty$' .env || { echo "key not appended after newline normalization" >&2; exit 1; }

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

# 適用済みマイグレーションのチェックサム不一致（sqlx の "previously applied but has been modified"）は
# 決定論的な失敗。リトライせず即停止し、原因（適用済みファイルの改変）と対処（reset 等）を提示する。
: >"$DOCKER_STUB_LOG"
set +e
DOCKER_STUB_MIGRATE_CHECKSUM_MISMATCH=1 ./scripts/deploy.sh migrate >/tmp/deploy-checksum-fail.out 2>&1
status=$?
set -e
[[ $status -eq 1 ]] || { echo "deploy must fail fast on migration checksum mismatch" >&2; cat /tmp/deploy-checksum-fail.out >&2; exit 1; }
grep -q 'チェックサム' /tmp/deploy-checksum-fail.out ||
  { echo "checksum mismatch guidance must explain the checksum error" >&2; exit 1; }
grep -q 'version 2' /tmp/deploy-checksum-fail.out ||
  { echo "checksum mismatch guidance must name the affected migration version" >&2; exit 1; }
grep -q './deploy.sh reset' /tmp/deploy-checksum-fail.out ||
  { echo "checksum mismatch guidance must offer the reset remedy" >&2; exit 1; }
# 決定論的な失敗はリトライしない（migrate は 1 回だけ実行される）。
if [[ "$(grep -c 'run --rm -T migrate' "$DOCKER_STUB_LOG")" -ne 1 ]]; then
  echo "checksum mismatch must not be retried (migrate should run exactly once)" >&2
  cat "$DOCKER_STUB_LOG" >&2
  exit 1
fi
if grep -q 'DB migration failed after 3 attempts' /tmp/deploy-checksum-fail.out; then
  echo "checksum mismatch must fail fast, not exhaust retries" >&2
  exit 1
fi

# 秘密値に sed のメタ文字（[ . * ^ $ | 等）が含まれても mask_secrets が壊れないこと。マスク処理は
# migrate 成功時にも毎回走るため、ここが失敗すると成功デプロイまで pipefail で中断してしまう。
orig_pw_line="$(grep '^MARIADB_PASSWORD=' .env)"
: >"$DOCKER_STUB_LOG"
sed -i 's|^MARIADB_PASSWORD=.*|MARIADB_PASSWORD=p[a.s*s^d$x|' .env
set +e
./scripts/deploy.sh app >/tmp/deploy-metachar-secret.out 2>&1
status=$?
set -e
[[ $status -eq 0 ]] || { echo "metacharacter secret must not abort a successful deploy" >&2; cat /tmp/deploy-metachar-secret.out >&2; exit 1; }
if grep -qF 'p[a.s*s^d$x' /tmp/deploy-metachar-secret.out; then
  echo "metacharacter secret must be masked (not leaked) in deploy output" >&2
  exit 1
fi
# .env を元のパスワードへ戻し、後続テストへ影響させない。
sed -i "s|^MARIADB_PASSWORD=.*|${orig_pw_line}|" .env

# アプリ用 DB ユーザーの認証が失敗する（既存 volume と .env のパスワード不一致）場合は、意味のない
# migrate リトライではなくプリフライトで即座に停止し、原因と対処を提示する。
: >"$DOCKER_STUB_LOG"
set +e
DOCKER_STUB_FAIL_DB_AUTH=1 ./scripts/deploy.sh migrate >/tmp/deploy-db-auth-fail.out 2>&1
status=$?
set -e
[[ $status -eq 1 ]] || { echo "deploy must fail fast when app DB user auth fails" >&2; cat /tmp/deploy-db-auth-fail.out >&2; exit 1; }
grep -q 'DB authentication preflight failed' /tmp/deploy-db-auth-fail.out ||
  { echo "preflight failure diagnostic missing" >&2; exit 1; }
grep -q 'MARIADB_PASSWORD' /tmp/deploy-db-auth-fail.out ||
  { echo "preflight diagnostic must mention MARIADB_PASSWORD mismatch" >&2; exit 1; }
grep -q './deploy.sh reset' /tmp/deploy-db-auth-fail.out ||
  { echo "preflight diagnostic must suggest reset remedy" >&2; exit 1; }
if grep -q 'run --rm -T migrate' "$DOCKER_STUB_LOG"; then
  echo "migrate must not run when DB auth preflight fails" >&2
  exit 1
fi
if grep -q "$(grep '^MARIADB_PASSWORD=' .env | cut -d= -f2-)" /tmp/deploy-db-auth-fail.out; then
  echo "secret was not masked in preflight diagnostics" >&2
  exit 1
fi

# 認証以外（例: DB 不在）でプリフライトが失敗する場合は、破壊的な reset を勧める password-drift
# 診断ではなく、汎用の接続/クエリ失敗として報告する（誤ってデータ削除へ誘導しない）。
: >"$DOCKER_STUB_LOG"
set +e
DOCKER_STUB_FAIL_DB_CONN=1 ./scripts/deploy.sh migrate >/tmp/deploy-db-conn-fail.out 2>&1
status=$?
set -e
[[ $status -eq 1 ]] || { echo "deploy must fail fast on non-auth preflight error" >&2; cat /tmp/deploy-db-conn-fail.out >&2; exit 1; }
grep -q 'DB preflight failed (non-authentication error)' /tmp/deploy-db-conn-fail.out ||
  { echo "non-auth preflight failure must be reported distinctly" >&2; exit 1; }
if grep -q './deploy.sh reset' /tmp/deploy-db-conn-fail.out; then
  echo "non-auth preflight failure must NOT recommend destructive reset" >&2
  exit 1
fi
if grep -q 'run --rm -T migrate' "$DOCKER_STUB_LOG"; then
  echo "migrate must not run when DB preflight fails" >&2
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
grep -q -- '--project-name idp-bundle -f docker-compose.yml' "$DOCKER_STUB_LOG"

# manifest と image ID が食い違う場合は tar を読み込み、なお不一致なら失敗する。
sed -i 's/^api_image_id=.*/api_image_id=sha256:expected-other-id/' manifest.env
: >"$DOCKER_STUB_LOG"
if ./deploy.sh app >/tmp/deploy-bundle-mismatch.out 2>&1; then
  echo "deploy.sh must fail when image ID mismatches manifest" >&2
  exit 1
fi
grep -q 'load -i' "$DOCKER_STUB_LOG"
grep -q 'image ID が manifest と不一致' /tmp/deploy-bundle-mismatch.out

# --- stg ディレクトリでは初回 .env を .env.staging.example から生成する（ディレクトリ名で環境判定） ---
mkdir -p "$TMP/stg/docker"
cp "$ROOT/scripts/deploy.sh" "$TMP/stg/"
cp "$ROOT/docker-compose.deploy.yml" "$TMP/stg/docker-compose.yml"
cp "$ROOT/.env.example" "$ROOT/.env.staging.example" "$TMP/stg/"
cp "$ROOT/docker/nginx.conf" "$TMP/stg/docker/"
for svc in api web migrate; do
  touch "$TMP/stg/idp-${svc}.tar"
  printf '%s_ref=idp/%s:stg\n%s_image_id=sha256:stub-image-id\n' "$svc" "$svc" "$svc"
done >"$TMP/stg/manifest.env"
cd "$TMP/stg"

: >"$DOCKER_STUB_LOG"
./deploy.sh migrate >/tmp/deploy-stg.out 2>&1
grep -q '生成元: .env.staging.example' /tmp/deploy-stg.out ||
  { echo "stg dir must seed .env from .env.staging.example" >&2; cat /tmp/deploy-stg.out >&2; exit 1; }
grep -q '^WEB_PORT=8061$' .env || { echo "stg .env must use staging WEB_PORT (8061)" >&2; exit 1; }
grep -q '^IMAGE_TAG=stg$' .env || { echo "stg .env must use staging IMAGE_TAG (stg)" >&2; exit 1; }
grep -q '^COMPOSE_PROJECT_NAME=idp-stg$' .env || { echo "stg .env must use idp-stg project name" >&2; exit 1; }
# DATABASE_URL はテンプレートの :3307 を保持しつつ CHANGE-ME を実パスワードへ置換する。
grep -qE '^DATABASE_URL=mysql://idp:[0-9a-f]+@127\.0\.0\.1:3307/idp$' .env ||
  { echo "stg DATABASE_URL must keep :3307 and fill the password" >&2; cat .env >&2; exit 1; }
if grep -qE '^[A-Za-z_][A-Za-z0-9_]*=.*CHANGE-ME' .env; then
  echo "generated stg .env must not keep CHANGE-ME secrets" >&2
  exit 1
fi
grep -q -- '--project-name idp-stg -f docker-compose.yml' "$DOCKER_STUB_LOG"

# --- 既存 .env にプレースホルダ CHANGE-ME が残っている場合はコンテナ起動前に fail-fast する ---
# （.env.*.example を手動コピーして置換し忘れると、api が KEY_ENCRYPTION_KEY を base64 として
#   解釈できず crash-loop する。deploy.sh が原因のキー名と生成コマンドを明示して止めること。）
sed -i 's|^KEY_ENCRYPTION_KEY=.*|KEY_ENCRYPTION_KEY=CHANGE-ME|' .env
: >"$DOCKER_STUB_LOG"
set +e
./deploy.sh app >/tmp/deploy-placeholder.out 2>&1
status=$?
set -e
[[ $status -eq 1 ]] || { echo "deploy must fail fast when CHANGE-ME remains in .env" >&2; cat /tmp/deploy-placeholder.out >&2; exit 1; }
grep -q 'CHANGE-ME が残っています: KEY_ENCRYPTION_KEY' /tmp/deploy-placeholder.out ||
  { echo "placeholder diagnostic must name the offending key" >&2; cat /tmp/deploy-placeholder.out >&2; exit 1; }
grep -q 'openssl rand -base64 32' /tmp/deploy-placeholder.out ||
  { echo "placeholder diagnostic must include the generation command" >&2; exit 1; }
if grep -q 'up -d' "$DOCKER_STUB_LOG"; then
  echo "containers must not start when placeholder secrets remain" >&2
  exit 1
fi

echo "deploy script tests passed"
