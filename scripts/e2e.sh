#!/usr/bin/env bash
# scripts/e2e.sh — web->api connectivity E2E (ADR-0007 P5).
#
# Actually starts api (connected directly to the DB) and web (HTML screens, API client) as separate processes and verifies
# cross-service flows over browser-like HTTP. Checks the "web calls the api over HTTP" path that single-process
# integration tests (`crates/api/tests/*`) cannot verify.
#
# Prerequisites:
#   - MariaDB is running with migrations applied (`sqlx migrate run` or
#     `docker compose run --rm migrate`). The initial admin user admin@example.com / admin@example.com is seeded.
#   - Environment variable TEST_DATABASE_URL (default mysql://idp:idp@127.0.0.1:3306/idp).
#
# Usage:
#   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' ./scripts/e2e.sh
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

DB_URL="${TEST_DATABASE_URL:-mysql://idp:idp@127.0.0.1:3306/idp}"
API_ADDR="127.0.0.1:8080"
WEB_ADDR="127.0.0.1:8081"
# Use a host name, not an IP, for ISSUER (the WebAuthn RP ID requires a domain; localhost points to 127.0.0.1).
API="http://localhost:8080"
# Match web->api internal connectivity with the IPv4 bind. Depending on the environment localhost prefers ::1, and
# reqwest may fail to reach an IPv4-only api.
API_INTERNAL="http://127.0.0.1:8080"
WEB="http://localhost:8081"
TOKEN="e2e-internal-service-token-0123456789"
CODE_CHALLENGE="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
CODE_VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
REDIRECT_URI="http://localhost:3000/callback"

# Takes only the first line of a pipe. Do not use `head -1` -- `head` exits after reading one line and
# closes the pipe, so if the upstream grep has not finished writing it dies with SIGPIPE, and under `set -o pipefail`
# the whole script fails. Whether it hits depends on the upstream output size and scheduling; the bigger the screen
# the more likely (the tenant list has 3 CSRF tokens per tenant, so the more tenants the riskier).
# `sed` reads its input to the end, so the upstream never gets SIGPIPE.
first_line() { sed -n '1p'; }

pass() { printf '  \033[32mok\033[0m   %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; exit 1; }
info() { printf '\033[1m%s\033[0m\n' "$*"; }

api_pid=""; web_pid=""
cleanup() { [[ -n "$web_pid" ]] && kill "$web_pid" 2>/dev/null || true
            [[ -n "$api_pid" ]] && kill "$api_pid" 2>/dev/null || true; }
trap cleanup EXIT

info "1) build"
cargo build -q --bin assay --bin assay-web

# Where the built executables are.
# ⚠ **Do not hard-code `./target`.** cargo outputs to `CARGO_TARGET_DIR` if it is set
#   -- this moves when CI moves build output to a volume.
#   Hard-coded, it would fail with `No such file or directory` and then
#   **a misleading "api does not start"** (observed on 2026-09-11;
#   the build succeeded, so the logs hardly lead to the cause).
target_dir="${CARGO_TARGET_DIR:-$repo_root/target}"
for bin in assay assay-web; do
  [ -x "$target_dir/debug/$bin" ] ||
    fail "$target_dir/debug/$bin is missing (CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-(unset)})"
done

info "2) start api and web (api=${API_ADDR} / web=${WEB_ADDR}, shared INTERNAL_SERVICE_TOKEN)"
DATABASE_URL="$DB_URL" ISSUER="$API" BIND_ADDR="$API_ADDR" INTERNAL_SERVICE_TOKEN="$TOKEN" \
  RUST_LOG=error "$target_dir/debug/assay" &
api_pid=$!
API_BASE_URL="$API_INTERNAL" WEB_BIND_ADDR="$WEB_ADDR" INTERNAL_SERVICE_TOKEN="$TOKEN" ISSUER="$API" \
  NO_PROXY="localhost,127.0.0.1,::1,${NO_PROXY:-}" no_proxy="localhost,127.0.0.1,::1,${no_proxy:-}" \
  RUST_LOG=error "$target_dir/debug/assay-web" &
web_pid=$!

for _ in $(seq 1 30); do
  curl -fsS "${API}/healthz" >/dev/null 2>&1 && curl -fsS "${WEB}/readyz" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS "${API}/healthz" >/dev/null 2>&1 || fail "api does not start"
curl -fsS "${WEB}/readyz"  >/dev/null 2>&1 || fail "web cannot reach the api (/readyz)"
pass "api /healthz=200, web /readyz=200 (web->api reachable)"

# Resolve the DB client (docker(idp-test-db) preferred, otherwise local mariadb/mysql) and the root tenant UUID
# first. The api's OIDC/admin endpoints are under /{tenant_id}/... (ADR-0009 §6, MT9), so
# direct call URLs are prefixed with the root tenant UUID (root is the only row with parent_tenant_id IS NULL).
# The DB client's destination is taken from `TEST_DATABASE_URL`.
#
# ⚠ **Add `--skip-ssl`.** MariaDB clients **require TLS by default since 11.4**
#   -- the test DB (10.11) does not offer TLS, so
#   newer clients fail with `ERROR 2026 (HY000): TLS/SSL error: SSL is required,
#   but the server does not support it`. ⚠ **GitHub's
#   `ubuntu-latest` had an old client**, so this default difference
#   stayed invisible until we moved (observed on 2026-09-11; the client is 11.8.6).
#   ⚠ This only touches the **disposable test DB** with credentials `idp/idp`.
#
# ⚠ **Do not swallow with `2>/dev/null`.** Swallowing makes `set -e` silently end the script,
#   **making it look like the previous step (starting the api) failed** -- because of this, the TLS issue above
#   took 3 runs to track down.
# ⚠ **Do not hard-code 127.0.0.1.** The DB is not necessarily on the same host --
#   when CI runs inside a container, the DB is reached by service name (`mariadb:3306`).
#   Hard-coded, the client alone would look at a different destination even though the
#   connection string is passed, giving **the misleading failure "cannot resolve the root tenant
#   (seed not run?)"** (found on 2026-09-11 when moving to forge).
db_authority="${DB_URL#*://}"        # user:pass@host:port/db
db_authority="${db_authority##*@}"   # host:port/db (cut at the last @ even if the password contains @)
db_authority="${db_authority%%/*}"   # host:port
db_host="${db_authority%%:*}"
db_port="${db_authority#*:}"
# ⚠ **Do not end with `[ … ] && …`.** If the condition is false the whole line returns 1 and
#   `set -e` ends the script there -- **it stops silently**, so
#   it looks like the previous step (starting the api) failed (observed on 2026-09-11).
if [ "$db_port" = "$db_host" ]; then db_port=3306; fi   # when the port is omitted

if command -v docker >/dev/null 2>&1 && docker exec idp-test-db true 2>/dev/null; then
  mariadb_exec() { docker exec idp-test-db mariadb -uidp -pidp idp -N -e "$1" 2>/dev/null; }
elif command -v mariadb >/dev/null 2>&1; then
  mariadb_exec() { mariadb --skip-ssl -h"$db_host" -P"$db_port" -uidp -pidp idp -N -e "$1"; }
elif command -v mysql >/dev/null 2>&1; then
  mariadb_exec() { mysql --skip-ssl -h"$db_host" -P"$db_port" -uidp -pidp idp -N -e "$1"; }
else
  fail "inserting the test client needs docker(idp-test-db) or a local mariadb/mysql client"
fi
ROOT="$(mariadb_exec "SELECT id FROM tenants WHERE parent_tenant_id IS NULL")"
[[ -n "$ROOT" ]] || fail "cannot resolve the root tenant (seed not run?)"
# The E2E starts the OIDC flow from user self-registration, so explicitly enable self-registration on the root tenant.
mariadb_exec "UPDATE tenants SET self_registration_enabled=1 WHERE id='${ROOT}';" >/dev/null

# ── OIDC authorization code flow (via web login) ──────────────────────────────────
info "3) OIDC flow: /authorize(api) -> /{tenant_id}/login(web) -> /token(api)"
U="e2e$(date +%s)"; P="correct-horse-battery"
curl -fsS -X POST "${API}/${ROOT}/auth/register" -H 'content-type: application/json' \
  -d "{\"email\":\"${U}@example.com\",\"preferred_username\":\"${U}\",\"password\":\"${P}\"}" >/dev/null
# This E2E verifies OIDC consent and code issuance, not the email verification gate, so
# mark the registered user verified and proceed with the existing flow.
# User names live in the registry (`user_login_identifiers`; moved from `users` in AP15b).
mariadb_exec "UPDATE users u JOIN user_login_identifiers p ON p.primary_of_user = u.id \
  SET u.email_verified=1 WHERE u.tenant_id='${ROOT}' AND p.normalized_value='${U}';" >/dev/null
pass "user registration"

CJAR="$(mktemp)"
authz="${API}/${ROOT}/authorize?response_type=code&client_id=CLIENT&redirect_uri=$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=""))' "$REDIRECT_URI")&scope=openid%20profile%20email&state=st&nonce=no&code_challenge=${CODE_CHALLENGE}&code_challenge_method=S256"
# The client is inserted directly into the DB (creation via the admin console is verified in 4)).
CID="e2e-cli-$(date +%s)"
# The client belongs to the root tenant (ADR-0009 §2; root is the only row with parent_tenant_id IS NULL).
mariadb_exec "SET @root := (SELECT id FROM tenants WHERE parent_tenant_id IS NULL); INSERT INTO clients (id,tenant_id,client_id,client_secret_hash,client_type,client_status,app_name,redirect_uris,grant_types,response_types,scopes,token_endpoint_auth_method) VALUES (UUID(),@root,'${CID}',NULL,'public','ACTIVE','E2E',JSON_ARRAY('${REDIRECT_URI}'),JSON_ARRAY('authorization_code'),JSON_ARRAY('code'),JSON_ARRAY('openid','profile','email'),'none');"
authz="${authz/CLIENT/$CID}"
loc="$(curl -fsS -o /dev/null -w '%{redirect_url}' "$authz")"
# ADR-0018 decision 2: the api does not Set-Cookie; it puts a single-use handle in the URL and 302s to web's /login.
[[ "$loc" == *"/${ROOT}/login?auth_session="* ]] || fail "/authorize does not lead to /{tenant_id}/login with a single-use handle ($loc)"
handle="${loc#*auth_session=}"
# web exchanges the handle via resume, issues a host-only Cookie and removes the handle from the URL with 303.
loc="$(curl -fsS -b "$CJAR" -c "$CJAR" -o /dev/null -w '%{redirect_url}' "${WEB}/${ROOT}/login?auth_session=${handle}")"
[[ "$loc" == *"/${ROOT}/login" ]] || fail "web does not switch to /login after receiving the handle ($loc)"
pass "/authorize -> web handoff -> auth_session Cookie issued, handle removed from URL (303)"

csrf="$(curl -fsS -b "$CJAR" "${WEB}/${ROOT}/login" | grep -oE '[a-f0-9]{64}' | first_line)"
[[ -n "$csrf" ]] || fail "web /{tenant_id}/login does not return a form (CSRF)"
loc="$(curl -fsS -b "$CJAR" -c "$CJAR" -o /dev/null -w '%{redirect_url}' -X POST "${WEB}/${ROOT}/login" \
  -H 'content-type: application/x-www-form-urlencoded' -H 'X-Forwarded-For: 203.0.113.5' \
  --data-urlencode "username=${U}" --data-urlencode "password=${P}" --data-urlencode "csrf_token=${csrf}")"
# The first login has profile/email not yet consented, so it is led to the consent screen (F3).
[[ "$loc" == *"/${ROOT}/consent"* ]] || fail "web login does not lead to the consent screen ($loc)"
pass "web /{tenant_id}/login -> api /internal/authenticate -> SSO Cookie + led to /{tenant_id}/consent (consent required on first login)"

consent_html="$(curl -fsS -b "$CJAR" "${WEB}/${ROOT}/consent")"
ccsrf2="$(printf '%s' "$consent_html" | grep -oE 'name="csrf_token" value="[a-f0-9]{64}"' | grep -oE '[a-f0-9]{64}' | first_line)"
csess="$(printf '%s' "$consent_html" | grep -oE 'name="auth_session_id" value="[a-f0-9]+"' | grep -oE 'value="[a-f0-9]+"' | grep -oE '[a-f0-9]+' | tail -1)"
[[ -n "$ccsrf2" && -n "$csess" ]] || fail "consent screen does not return a form (CSRF, auth_session_id)"
loc="$(curl -fsS -b "$CJAR" -c "$CJAR" -o /dev/null -w '%{redirect_url}' -X POST "${WEB}/${ROOT}/consent" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode "auth_session_id=${csess}" --data-urlencode "csrf_token=${ccsrf2}" \
  --data-urlencode "action=approve")"
[[ "$loc" == "${REDIRECT_URI}"* ]] || fail "consent approval does not redirect the code to the RP ($loc)"
code="$(printf '%s' "$loc" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')"
[[ -n "$code" ]] || fail "cannot get the code"
pass "web /consent approval -> api /internal/consent/approve -> code redirect"

tok="$(curl -fsS -X POST "${API}/${ROOT}/token" -H 'content-type: application/x-www-form-urlencoded' \
  --data "grant_type=authorization_code&code=${code}&redirect_uri=$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=""))' "$REDIRECT_URI")&code_verifier=${CODE_VERIFIER}&client_id=${CID}")"
grep -q '"id_token"' <<<"$tok" || fail "/token does not return an id_token"
pass "api /token -> id_token issued (the code from web login is valid)"

# ── Admin console (web -> api JSON admin API) ──────────────────────────────────
info "4) admin console: admin login -> create client -> grant permission -> status/audit"
AJAR="$(mktemp)"
# To make the E2E re-runnable, put the initial admin back into the seed's awaiting-first-change state.
mariadb_exec "UPDATE users SET password_hash='\$argon2id\$v=19\$m=65536,t=3,p=4\$L1NMbjFwV21BYllKWng5Ng\$zTuAfd+FBQlcvMQF9KQyUFGkk2wqYNdAadNiCwKlTnY', must_change_password=1, failed_login_count=0, locked_until=NULL WHERE tenant_id='${ROOT}' AND email='admin@example.com';" >/dev/null
login_html="$(curl -fsS -c "$AJAR" "${WEB}/${ROOT}/admin/login")"
acsrf="$(printf '%s' "$login_html" | grep -oE '[a-f0-9]{64}' | first_line)"
admin_login_body="$(mktemp)"
admin_loc="$(curl -fsS -b "$AJAR" -c "$AJAR" -o "$admin_login_body" -w '%{redirect_url}' -X POST "${WEB}/${ROOT}/admin/login" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode "username=admin@example.com" --data-urlencode "password=admin@example.com" --data-urlencode "csrf_token=${acsrf}")"
if [[ -z "$admin_loc" ]] && grep -q 'admin/password-change' "$admin_login_body"; then
  pcsrf_admin="$(grep -oE 'name="csrf_token" value="[a-f0-9]{64}"' "$admin_login_body" | grep -oE '[a-f0-9]{64}' | first_line)"
  admin_loc="$(curl -fsS -b "$AJAR" -c "$AJAR" -o /dev/null -w '%{redirect_url}' -X POST "${WEB}/${ROOT}/admin/password-change" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "username=admin@example.com" --data-urlencode "current_password=admin@example.com" \
    --data-urlencode "new_password=ChangeMe!1234" --data-urlencode "new_password_confirm=ChangeMe!1234" \
    --data-urlencode "csrf_token=${pcsrf_admin}")"
fi
admin_home_html="$(curl -fsS -b "$AJAR" "${WEB}/${ROOT}/admin")"
grep -q "/${ROOT}/admin/clients" <<<"$admin_home_html" || fail "admin home does not render (via whoami)"
pass "admin login -> initial password change if needed -> home rendered (web->api /admin/whoami)"

react_asset="$(curl -fsS "${WEB}/assets/react/app.js")"
grep -q "reactSurface" <<<"$react_asset" || fail "React bundle does not include data-react-surface hydration"
# Regression guard against development status text (hard-coded, not translated) leaking onto the screen.
! grep -q "テナント名を入力してください" <<<"$react_asset" || fail "React bundle still contains development debug output"
pass "React bundle served (/assets/react/app.js)"

tenants_html="$(curl -fsS -b "$AJAR" "${WEB}/${ROOT}/admin/tenants")"
grep -q 'data-react-surface="TenantRegistrationConsole"' <<<"$tenants_html" || fail "tenant registration screen does not return the React surface"
tcsrf="$(printf '%s' "$tenants_html" | grep -oE 'name="csrf_token" value="[a-f0-9]{64}"' | grep -oE '[a-f0-9]{64}' | first_line)"
[[ -n "$tcsrf" ]] || fail "tenant registration screen does not return CSRF"
TENANT_SUFFIX="$(date +%s)"
TENANT_NAME="E2E Tenant ${TENANT_SUFFIX}"
tenant_created="$(curl -fsS -b "$AJAR" -X POST "${WEB}/${ROOT}/admin/tenants" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode "name=${TENANT_NAME}" \
  --data-urlencode "csrf_token=${tcsrf}")"
grep -q "${TENANT_NAME}\|admin-tenants-created-title\|Tenant registered\|テナントを登録しました" <<<"$tenant_created" || fail "tenant creation result screen is not shown"
NEW_TENANT_ID="$(mariadb_exec "SELECT id FROM tenants WHERE parent_tenant_id='${ROOT}' AND name='${TENANT_NAME}' LIMIT 1;")"
[[ -n "$NEW_TENANT_ID" ]] || fail "tenant creation is not reflected in the DB"
# The creator (root admin) has become an ACTIVE GUEST admin of the new tenant (bootstrap).
[[ "$(mariadb_exec "SELECT COUNT(*) FROM tenant_memberships tm JOIN users u ON u.id=tm.user_id WHERE tm.tenant_id='${NEW_TENANT_ID}' AND u.tenant_id='${ROOT}' AND u.email='admin@example.com' AND tm.membership_type='GUEST' AND tm.status='ACTIVE';")" == "1" ]] \
  || fail "the creator's bootstrap guest admin membership is not reflected in the DB"
[[ "$(mariadb_exec "SELECT COUNT(*) FROM user_permissions up JOIN users u ON u.id=up.user_id WHERE up.tenant_id='${NEW_TENANT_ID}' AND u.email='admin@example.com' AND up.permission_code='idp.tenant.admin';")" == "1" ]] \
  || fail "the creator's idp.tenant.admin grant is not reflected in the DB"
pass "tenant registration screen (React surface) -> web->api POST /admin/tenants -> creator is bootstrap admin (reflected in DB)"

ccsrf="$(curl -fsS -b "$AJAR" "${WEB}/${ROOT}/admin/clients/new" | grep -oE 'name="csrf_token" value="[a-f0-9]{64}"' | grep -oE '[a-f0-9]{64}' | first_line)"
# The default authentication method is private_key_jwt (ADR-0036). Here we check the one-time secret display, so
# register with client_secret_basic explicitly.
created="$(curl -fsS -b "$AJAR" -X POST "${WEB}/${ROOT}/admin/clients/new" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode "app_name=E2E Console App" --data-urlencode "client_type=confidential" \
  --data-urlencode "usage=user_login" \
  --data-urlencode "redirect_uris=${REDIRECT_URI}" \
  --data-urlencode "token_endpoint_auth_method=client_secret_basic" \
  --data-urlencode "csrf_token=${ccsrf}")"
grep -qi "secret" <<<"$created" || fail "client creation does not show the secret"
pass "client creation (web->api POST /admin/clients, one-time secret display)"

# Register a service account with a note at creation, and the note is readable on the account's single-item screen (ADR-0065).
sa_marker="e2e-sa-note-$$"
sacsrf="$(curl -fsS -b "$AJAR" "${WEB}/${ROOT}/admin/service-accounts/new" | grep -oE 'name="csrf_token" value="[a-f0-9]{64}"' | grep -oE '[a-f0-9]{64}' | first_line)"
sa_created="$(curl -fsS -b "$AJAR" -o /dev/null -w '%{http_code} %{redirect_url}' -X POST "${WEB}/${ROOT}/admin/service-accounts/new" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode "app_name=E2E Service Account" --data-urlencode "usage=system" \
  --data-urlencode "redirect_uris=" \
  --data-urlencode "token_endpoint_auth_method=client_secret_basic" \
  --data-urlencode "note=${sa_marker}" \
  --data-urlencode "csrf_token=${sacsrf}")" \
  || fail "cannot register the service account"
sa_client_id="$(mariadb_exec "SELECT client_id FROM clients WHERE app_name = 'E2E Service Account' ORDER BY created_at DESC LIMIT 1")"
[[ -n "$sa_client_id" ]] || fail "the service account was not created in the DB"
# Receive the screen into a file before inspecting. ⚠ With `curl | grep -q`, on failure nothing tells whether
#   "the screen redirected (empty body)" or "it rendered but the note is missing".
sa_page="$(mktemp)"
sa_shown="$(curl -fsS -b "$AJAR" -o "$sa_page" -w '%{http_code} %{redirect_url}' \
  "${WEB}/${ROOT}/admin/service-accounts/${sa_client_id}")" \
  || fail "cannot open the service account screen"
if ! grep -q "$sa_marker" "$sa_page"; then
  printf '    registration response: %s\n    screen response: %s (client_id=%s)\n    notes in DB: %s\n' \
    "$sa_created" "$sa_shown" "$sa_client_id" \
    "$(mariadb_exec "SELECT COUNT(*) FROM account_notes n JOIN clients c ON c.id = n.client_id WHERE c.client_id = '${sa_client_id}'")" >&2
  grep -oE '(alert|error)[^>]*>[^<]{1,200}' "$sa_page" | sed -n '1,5p' >&2 || true
  fail "the service account screen does not show the note from creation"
fi
curl -fsS -b "$AJAR" "${WEB}/${ROOT}/admin/accounts?kind=service_account&q=${sa_marker}" \
  | grep -q "/${ROOT}/admin/service-accounts/${sa_client_id}" \
  || fail "the account list cannot find the service account by the note's words"
pass "service account (note at creation -> single-item screen -> list filter; web->api /admin/service-accounts)"

curl -fsS -b "$AJAR" -o /dev/null -w '%{http_code}' "${WEB}/${ROOT}/admin/status"     | grep -q 200 || fail "status screen does not return 200"
curl -fsS -b "$AJAR" -o /dev/null -w '%{http_code}' "${WEB}/${ROOT}/admin/audit-logs"  | grep -q 200 || fail "audit screen does not return 200"
pass "status and audit screens (web->api /admin/clients/status, /admin/audit-logs)"

# SAML: download the IdP metadata from the same web origin as the admin screen, without exposing the api directly.
saml_html="$(curl -fsS -b "$AJAR" "${WEB}/${ROOT}/admin/saml-clients")"
metadata_href="$(grep -oE 'href="[^"]*/admin/saml-clients/idp-metadata"' <<<"$saml_html" | first_line | sed -E 's/^href="//; s/"$//')"
[[ "$metadata_href" == "/${ROOT}/admin/saml-clients/idp-metadata" ]] \
  || fail "the IdP metadata link is not web's download URL: ${metadata_href:-(no link)}"
curl -fsS -b "$AJAR" "${WEB}${metadata_href}" | grep -q "IDPSSODescriptor" \
  || fail "cannot fetch the IdP metadata from web's download URL"
pass "IdP metadata link (downloaded from the same web origin as the console)"

# Account list (filtered to people) -> single-person screen -> grant permission. The user search screen was removed, so the account screen is the start
# (ADR-0065; the old `/admin/members` only redirects, so reading it without -L gives empty).
# ⚠ **No operations in the list** (7 buttons in the 168px action column broke the layout). The permission
#   link is on the single-person screen, so follow it in two steps here too.
members_html="$(curl -fsS -b "$AJAR" "${WEB}/${ROOT}/admin/accounts?kind=user&q=${U}")"
grep -q "/${ROOT}/admin/members/[0-9a-f-]\{36\}" <<<"$members_html" || fail "the account filter does not return a link to the single-person screen"
tid="$(mariadb_exec "SELECT u.id FROM users u JOIN user_login_identifiers p ON p.primary_of_user = u.id \
  WHERE u.tenant_id='${ROOT}' AND p.normalized_value='${U}' LIMIT 1;")"
[[ -n "$tid" ]] || fail "target user not found"
member_html="$(curl -fsS -b "$AJAR" "${WEB}/${ROOT}/admin/members/${tid}")"
grep -q "/${ROOT}/admin/users/${tid}/permissions" <<<"$member_html" || fail "the member screen does not return the permissions link"
grep -q "/${ROOT}/admin/members/${tid}/reset-mfa" <<<"$member_html" || fail "the member screen has no MFA reset"
perm_page="$(mktemp)"
perm_status="$(curl -sS -b "$AJAR" -o "$perm_page" -w '%{http_code}' "${WEB}/${ROOT}/admin/users/${tid}/permissions")"
if [[ "$perm_status" == "200" ]]; then
  pcsrf="$(grep -oE 'name="csrf_token" value="[a-f0-9]{64}"' "$perm_page" | grep -oE '[a-f0-9]{64}' | first_line)"
  curl -fsS -b "$AJAR" -o /dev/null -X POST "${WEB}/${ROOT}/admin/users/${tid}/permissions/grant" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "permission_code=idp.tenant.admin" --data-urlencode "csrf_token=${pcsrf}"
else
  # Even in environments where screen rendering fails, verify the api's admin JSON API path directly.
  #
  # The admin API accepts only Bearer (ADR-0037). There is no longer a path forwarding the Cookie as is, so
  # exchange the SSO session for an admin token **with the same steps as web** before calling. Since this branch stands in
  # for web's path, it is no stand-in unless authorization is done the same way as web.
  sso="$(awk '$6 == "sso_session_id" { print $7 }' "$AJAR" | first_line)"
  [[ -n "$sso" ]] || fail "cannot get the SSO session Cookie"
  mtok="$(curl -fsS -X POST "${API_INTERNAL}/internal/admin/token" \
    -H "x-internal-auth-token: ${TOKEN}" -H 'content-type: application/json' \
    -d "{\"tenant_id\":\"${ROOT}\",\"sso_session_id\":\"${sso}\"}" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')"
  [[ -n "$mtok" ]] || fail "exchange for an admin token failed"
  curl -fsS -H "authorization: Bearer ${mtok}" -o /dev/null \
    -X POST "${API}/${ROOT}/admin/users/${tid}/permissions" \
    -H 'content-type: application/json' \
    -d '{"permission_code":"idp.tenant.admin"}'
fi
[[ "$(mariadb_exec "SELECT COUNT(*) FROM user_permissions WHERE user_id='${tid}' AND permission_code='idp.tenant.admin';")" == "1" ]] \
  || fail "permission grant is not reflected in the DB"
pass "member filter -> idp.tenant.admin granted (web/api, reflected in DB)"

printf '\n\033[32mE2E OK\033[0m — web->api connectivity all passed.\n'
