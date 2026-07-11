#!/usr/bin/env bash
# scripts/e2e.sh — web→api の疎通 E2E（ADR-0007 P5）。
#
# api（DB 直結）と web（HTML 画面・API クライアント）を実際に別プロセスで起動し、ブラウザ相当の
# HTTP でクロスサービスの流れを検証する。単一プロセスの統合テスト（`crates/api/tests/*`）では
# 検証できない「web が api を HTTP 越しに呼ぶ」経路を確認する。
#
# 前提:
#   - MariaDB が起動し、マイグレーション適用済み（`sqlx migrate run` もしくは
#     `docker compose run --rm migrate`）。初期管理ユーザー admin@example.com / ChangeMe!123 が seed 済み。
#   - 環境変数 TEST_DATABASE_URL（既定 mysql://idp:idp@127.0.0.1:3306/idp）。
#
# 使い方:
#   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' ./scripts/e2e.sh
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

DB_URL="${TEST_DATABASE_URL:-mysql://idp:idp@127.0.0.1:3306/idp}"
API_ADDR="127.0.0.1:8080"
WEB_ADDR="127.0.0.1:8081"
# ISSUER には IP でなくホスト名を使う（WebAuthn の RP ID はドメイン必須。localhost は 127.0.0.1 を指す）。
API="http://localhost:8080"
WEB="http://localhost:8081"
TOKEN="e2e-internal-service-token"
CODE_CHALLENGE="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
CODE_VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
REDIRECT_URI="http://localhost:3000/callback"

pass() { printf '  \033[32mok\033[0m   %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; exit 1; }
info() { printf '\033[1m%s\033[0m\n' "$*"; }

api_pid=""; web_pid=""
cleanup() { [[ -n "$web_pid" ]] && kill "$web_pid" 2>/dev/null || true
            [[ -n "$api_pid" ]] && kill "$api_pid" 2>/dev/null || true; }
trap cleanup EXIT

info "1) ビルド"
cargo build -q --bin idp --bin idp-web

info "2) api・web 起動（api=${API_ADDR} / web=${WEB_ADDR}、共有 INTERNAL_SERVICE_TOKEN）"
DATABASE_URL="$DB_URL" ISSUER="$API" BIND_ADDR="$API_ADDR" INTERNAL_SERVICE_TOKEN="$TOKEN" \
  RUST_LOG=error ./target/debug/idp &
api_pid=$!
API_BASE_URL="$API" WEB_BIND_ADDR="$WEB_ADDR" INTERNAL_SERVICE_TOKEN="$TOKEN" ISSUER="$API" \
  RUST_LOG=error ./target/debug/idp-web &
web_pid=$!

for _ in $(seq 1 30); do
  curl -fsS "${API}/healthz" >/dev/null 2>&1 && curl -fsS "${WEB}/readyz" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS "${API}/healthz" >/dev/null 2>&1 || fail "api が起動しません"
curl -fsS "${WEB}/readyz"  >/dev/null 2>&1 || fail "web が api へ到達できません（/readyz）"
pass "api /healthz=200・web /readyz=200（web→api 到達）"

# DB クライアント（docker(idp-test-db) 優先、無ければローカル mariadb/mysql）と root テナント UUID を
# 先に解決する。api の OIDC/管理エンドポイントは /{tenant_id}/... 配下（ADR-0009 §6・MT9）のため、
# ダイレクト呼び出しの URL に root テナント UUID を前置する（root は parent_tenant_id IS NULL の唯一の行）。
if command -v docker >/dev/null 2>&1 && docker exec idp-test-db true 2>/dev/null; then
  mariadb_exec() { docker exec idp-test-db mariadb -uidp -pidp idp -N -e "$1" 2>/dev/null; }
elif command -v mariadb >/dev/null 2>&1; then
  mariadb_exec() { mariadb -h127.0.0.1 -uidp -pidp idp -N -e "$1" 2>/dev/null; }
elif command -v mysql >/dev/null 2>&1; then
  mariadb_exec() { mysql -h127.0.0.1 -uidp -pidp idp -N -e "$1" 2>/dev/null; }
else
  fail "テスト用クライアントの投入に docker(idp-test-db) またはローカルの mariadb/mysql クライアントが必要です"
fi
ROOT="$(mariadb_exec "SELECT id FROM tenants WHERE parent_tenant_id IS NULL")"
[[ -n "$ROOT" ]] || fail "root テナントが解決できません（seed 未実行？）"

# ── OIDC 認可コードフロー（web ログイン経由）──────────────────────────────────
info "3) OIDC フロー: /authorize(api) → /{tenant_id}/login(web) → /token(api)"
U="e2e$(date +%s)"; P="correct-horse-battery"
curl -fsS -X POST "${API}/${ROOT}/auth/register" -H 'content-type: application/json' \
  -d "{\"email\":\"${U}@example.com\",\"preferred_username\":\"${U}\",\"password\":\"${P}\"}" >/dev/null
pass "利用者登録"

CJAR="$(mktemp)"
authz="${API}/${ROOT}/authorize?response_type=code&client_id=CLIENT&redirect_uri=$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=""))' "$REDIRECT_URI")&scope=openid%20profile%20email&state=st&nonce=no&code_challenge=${CODE_CHALLENGE}&code_challenge_method=S256"
# クライアントは DB へ直接投入（管理コンソール経由の作成は 4) で検証）。
CID="e2e-cli-$(date +%s)"
# クライアントは root テナントへ帰属させる（ADR-0009 §2。root は parent_tenant_id IS NULL の唯一の行）。
mariadb_exec "SET @root := (SELECT id FROM tenants WHERE parent_tenant_id IS NULL); INSERT INTO clients (id,tenant_id,client_id,client_secret_hash,client_type,client_status,app_name,redirect_uris,grant_types,response_types,scopes,token_endpoint_auth_method,require_pkce) VALUES (UUID(),@root,'${CID}',NULL,'public','ACTIVE','E2E',JSON_ARRAY('${REDIRECT_URI}'),JSON_ARRAY('authorization_code'),JSON_ARRAY('code'),JSON_ARRAY('openid','profile','email'),'none',1);"
authz="${authz/CLIENT/$CID}"
loc="$(curl -fsS -c "$CJAR" -o /dev/null -w '%{redirect_url}' "$authz")"
[[ "$loc" == *"/${ROOT}/login"* ]] || fail "/authorize が /{tenant_id}/login へ誘導しません（$loc）"
pass "/authorize → /{tenant_id}/login 302・auth_session Cookie 発行"

csrf="$(curl -fsS -b "$CJAR" "${WEB}/${ROOT}/login" | grep -oE '[a-f0-9]{64}' | head -1)"
[[ -n "$csrf" ]] || fail "web /{tenant_id}/login がフォーム（CSRF）を返しません"
loc="$(curl -fsS -b "$CJAR" -c "$CJAR" -o /dev/null -w '%{redirect_url}' -X POST "${WEB}/${ROOT}/login" \
  -H 'content-type: application/x-www-form-urlencoded' -H 'X-Forwarded-For: 203.0.113.5' \
  --data-urlencode "username=${U}" --data-urlencode "password=${P}" --data-urlencode "csrf_token=${csrf}")"
# 初回ログインは profile/email が未同意のため同意画面（F3）へ誘導される。
[[ "$loc" == *"/${ROOT}/consent"* ]] || fail "web ログインが同意画面へ誘導しません（$loc）"
pass "web /{tenant_id}/login → api /internal/authenticate → SSO Cookie + /{tenant_id}/consent 誘導（初回は要同意）"

consent_html="$(curl -fsS -b "$CJAR" "${WEB}/${ROOT}/consent")"
ccsrf2="$(printf '%s' "$consent_html" | grep -oE 'name="csrf_token" value="[a-f0-9]{64}"' | grep -oE '[a-f0-9]{64}' | head -1)"
csess="$(printf '%s' "$consent_html" | grep -oE 'name="auth_session_id" value="[a-f0-9]+"' | grep -oE 'value="[a-f0-9]+"' | grep -oE '[a-f0-9]+' | tail -1)"
[[ -n "$ccsrf2" && -n "$csess" ]] || fail "同意画面がフォーム（CSRF・auth_session_id）を返しません"
loc="$(curl -fsS -b "$CJAR" -c "$CJAR" -o /dev/null -w '%{redirect_url}' -X POST "${WEB}/${ROOT}/consent" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode "auth_session_id=${csess}" --data-urlencode "csrf_token=${ccsrf2}" \
  --data-urlencode "action=approve")"
[[ "$loc" == "${REDIRECT_URI}"* ]] || fail "同意承諾が RP へ code リダイレクトしません（$loc）"
code="$(printf '%s' "$loc" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')"
[[ -n "$code" ]] || fail "code が取得できません"
pass "web /consent 承諾 → api /internal/consent/approve → code リダイレクト"

tok="$(curl -fsS -X POST "${API}/${ROOT}/token" -H 'content-type: application/x-www-form-urlencoded' \
  --data "grant_type=authorization_code&code=${code}&redirect_uri=$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=""))' "$REDIRECT_URI")&code_verifier=${CODE_VERIFIER}&client_id=${CID}")"
printf '%s' "$tok" | grep -q '"id_token"' || fail "/token が id_token を返しません"
pass "api /token → id_token 発行（web ログインの code は有効）"

# ── 管理コンソール（web → api JSON 管理 API）──────────────────────────────────
info "4) 管理コンソール: admin ログイン → クライアント作成 → 権限付与 → 状況/監査"
AJAR="$(mktemp)"
acsrf="$(curl -fsS -c "$AJAR" "${WEB}/${ROOT}/admin/login" | grep -oE '[a-f0-9]{64}' | head -1)"
curl -fsS -b "$AJAR" -c "$AJAR" -o /dev/null -X POST "${WEB}/${ROOT}/admin/login" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode "username=admin" --data-urlencode "password=ChangeMe!123" --data-urlencode "csrf_token=${acsrf}"
curl -fsS -b "$AJAR" "${WEB}/${ROOT}/admin" | grep -q "/${ROOT}/admin/clients" || fail "管理ホームが描画されません（whoami 経由）"
pass "admin ログイン → ホーム描画（web→api /admin/whoami）"

ccsrf="$(curl -fsS -b "$AJAR" "${WEB}/${ROOT}/admin/clients/new" | grep -oE 'name="csrf_token" value="[a-f0-9]{64}"' | grep -oE '[a-f0-9]{64}')"
created="$(curl -fsS -b "$AJAR" -X POST "${WEB}/${ROOT}/admin/clients/new" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode "app_name=E2E Console App" --data-urlencode "client_type=confidential" \
  --data-urlencode "redirect_uris=${REDIRECT_URI}" --data-urlencode "scopes=openid" \
  --data-urlencode "csrf_token=${ccsrf}")"
printf '%s' "$created" | grep -qi "secret" || fail "クライアント作成で secret が表示されません"
pass "クライアント作成（web→api POST /admin/clients、secret 一度表示）"

curl -fsS -b "$AJAR" -o /dev/null -w '%{http_code}' "${WEB}/${ROOT}/admin/status"     | grep -q 200 || fail "状況画面が 200 を返しません"
curl -fsS -b "$AJAR" -o /dev/null -w '%{http_code}' "${WEB}/${ROOT}/admin/audit-logs"  | grep -q 200 || fail "監査画面が 200 を返しません"
pass "状況・監査画面（web→api /admin/clients/status・/admin/audit-logs）"

# 利用者検索→権限付与→剥奪。
sr="$(curl -fsS -b "$AJAR" "${WEB}/${ROOT}/admin/users?q=${U}@example.com")"
tid="$(printf '%s' "$sr" | grep -oE '<code>[0-9a-f-]{36}</code>' | head -1 | sed 's/<[^>]*>//g')"
[[ -n "$tid" ]] || fail "利用者検索がヒットしません"
pcsrf="$(curl -fsS -b "$AJAR" "${WEB}/${ROOT}/admin/users/${tid}/permissions" | grep -oE 'name="csrf_token" value="[a-f0-9]{64}"' | grep -oE '[a-f0-9]{64}' | head -1)"
curl -fsS -b "$AJAR" -o /dev/null -X POST "${WEB}/${ROOT}/admin/users/${tid}/permissions/grant" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode "permission_code=idp.tenant.admin" --data-urlencode "csrf_token=${pcsrf}"
[[ "$(mariadb_exec "SELECT COUNT(*) FROM user_permissions WHERE user_id='${tid}' AND permission_code='idp.tenant.admin';")" == "1" ]] \
  || fail "権限付与が DB に反映されません"
pass "利用者検索 → idp.tenant.admin 付与（web→api、DB 反映を確認）"

printf '\n\033[32mE2E OK\033[0m — web→api の疎通が全て通りました。\n'
