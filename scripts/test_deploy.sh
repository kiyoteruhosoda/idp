#!/usr/bin/env bash
# scripts/test_deploy.sh — deploy.sh の CLI/エラー処理をスタブ docker で検証する（CI 用）。
set -Eeuo pipefail

# アサーションの多くは素の `grep -q`（メッセージ無し）で、失敗すると set -e が何も出さずに終了する。
# CI ログに手掛かりが残らず、ローカルで再現するまで原因が分からないため、最後に失敗した行と式を控えて
# おき、異常終了したときだけ出す。デプロイの失敗そのものを検証するケース（set +e 区間の意図的な失敗）
# でも ERR は発火するため、その場では出さず記録だけに留める。
LAST_ERR=""
trap 'LAST_ERR="line $LINENO: $BASH_COMMAND"' ERR

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
# EXIT トラップは 1 つしか持てないため、後始末と失敗報告をまとめて行う。
on_exit() {
  local status=$?
  rm -rf "$TMP"
  [[ $status -eq 0 || -z "$LAST_ERR" ]] ||
    echo "[test_deploy] FAILED (exit $status); last failing command was $LAST_ERR" >&2
}
trap on_exit EXIT

# --- リポジトリ配置（scripts/deploy.sh ＋ ルートの docker-compose.deploy.yml） ---
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
# readiness probe の宛先を検証できるよう、呼び出しを記録する（成否は常に成功）。
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
      # コンテナの環境変数読み出し（deploy.sh は .env を自前で解釈せず Compose の解決結果を読む）。
      # DOCKER_STUB_CONTAINER_ENV_FILE で「コンテナが持つ環境変数」を差し替えられるようにし、
      # .env の字面と実効値が食い違うケース（引用符・インラインコメント）を検証できるようにする。
      if [[ "$*" == *"printf %s"* ]]; then
        var="$(printf '%s' "$*" | grep -oE '\$\{[A-Za-z_]+' | tail -n1 | tr -d '${')"
        if [[ -n "${DOCKER_STUB_CONTAINER_ENV_FILE:-}" && -f "${DOCKER_STUB_CONTAINER_ENV_FILE}" && -n "$var" ]]; then
          line="$(grep -E "^${var}=" "$DOCKER_STUB_CONTAINER_ENV_FILE" | tail -n1 || true)"
          [[ -n "$line" ]] && printf '%s' "${line#*=}"
        fi
        exit 0
      fi
      # パスワード同期（root で ALTER USER）。成功すると以後アプリ用ユーザーの認証も通るよう、
      # マーカーファイルで「同期済み」を記録する（実 DB の挙動を模す）。
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
        # 資格情報は正しいが DB へのアクセス権が無い場合。1045 と同じ "Access denied for user" で
        # 始まるが、パスワード不一致ではない（エラーコードは 1044）。
        if [[ "${DOCKER_STUB_FAIL_DB_PRIV:-0}" == "1" ]]; then
          echo "ERROR 1044 (42000): Access denied for user 'idp'@'%' to database 'idp'" >&2
          exit 1
        fi
      fi
      if [[ "$*" == *"SELECT id FROM tenants"* ]]; then printf '01970000-0000-7000-8000-000000000001\n'; fi
      exit 0 ;;
    logs) echo "stub docker logs for ${*: -1}: ${MARIADB_PASSWORD:-secret}"; exit 0 ;;
    # deploy.sh は `config --services` で「定義に無いサービスを待ち続ける」事故を防いでいる。
    # DOCKER_STUB_SERVICES で定義一覧を差し替えられるようにして、その分岐を検証できるようにする。
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

# 追記で既存配置の「公開先・公開トポロジ」を黙って変えないこと（ADR-0016 の既定変更の移行）。
# 本番想定: ISSUER は公開ドメイン、PUBLIC_WEB_BASE_URL と PUBLISH_TOPOLOGY は当時の .env に無い。
sed -i 's|^ISSUER=.*|ISSUER=https://idp.example.com|' .env
sed -i '/^PUBLIC_WEB_BASE_URL=/d' .env
sed -i '/^PUBLISH_TOPOLOGY=/d' .env
: >"$DOCKER_STUB_LOG"; : >"${CURL_STUB_LOG:-/dev/null}"
./scripts/deploy.sh app >/tmp/deploy-migrate-topology.out 2>&1
# PUBLIC_WEB_BASE_URL は追記しない（未設定＝ISSUER フォールバック＝従来挙動）。localhost を
# 本番 .env へ書き込むと、ログイン・招待・リセットのリダイレクト先だけが localhost になる。
if grep -q '^PUBLIC_WEB_BASE_URL=' .env; then
  echo "PUBLIC_WEB_BASE_URL must not be backfilled into an existing .env" >&2
  grep '^PUBLIC_WEB_BASE_URL=' .env >&2
  exit 1
fi
grep -q 'ログイン URL: https://idp.example.com/' /tmp/deploy-migrate-topology.out ||
  { echo "existing deployment must keep redirecting to its own ISSUER origin" >&2; exit 1; }
# PUBLISH_TOPOLOGY が無い .env は ADR-0016 以前の配置＝単一オリジンなので、その意味を維持する。
grep -q '^PUBLISH_TOPOLOGY=single-origin$' .env ||
  { echo "missing PUBLISH_TOPOLOGY must be backfilled as single-origin, not the new default" >&2; exit 1; }
grep -q '公開トポロジ: single-origin' /tmp/deploy-migrate-topology.out ||
  { echo "existing deployment must keep the single-origin topology" >&2; exit 1; }
# 移行検証で書き換えた値を .env.example の既定へ戻す（以降のトポロジ試験の前提）。
sed -i 's|^ISSUER=.*|ISSUER=http://localhost:8070|' .env
sed -i 's/^PUBLISH_TOPOLOGY=.*/PUBLISH_TOPOLOGY=domain-split/' .env
printf 'PUBLIC_WEB_BASE_URL=http://localhost:8060\n' >>.env

# --- 公開トポロジ（ADR-0015・ADR-0016。既定 domain-split / 明示指定の single-origin） ---
export CURL_STUB_LOG="$TMP/curl.log"

# 既定（.env.example の PUBLISH_TOPOLOGY=domain-split。ADR-0016）では override を重ね、
# web（WEB_PORT）と api（API_PORT）の両方の readiness を見る。
: >"$DOCKER_STUB_LOG"; : >"$CURL_STUB_LOG"
./scripts/deploy.sh app >/tmp/deploy-default-topology.out 2>&1
grep -q '公開トポロジ: domain-split' /tmp/deploy-default-topology.out ||
  { echo "default topology must be domain-split" >&2; cat /tmp/deploy-default-topology.out >&2; exit 1; }
grep -q -- '-f docker-compose.deploy.yml -f docker-compose.domain-split.yml' "$DOCKER_STUB_LOG" ||
  { echo "default topology must overlay docker-compose.domain-split.yml" >&2; cat "$DOCKER_STUB_LOG" >&2; exit 1; }
grep -q 'http://127.0.0.1:8060/readyz' "$CURL_STUB_LOG" ||
  { echo "default topology must probe the web readiness endpoint" >&2; cat "$CURL_STUB_LOG" >&2; exit 1; }
grep -q 'http://127.0.0.1:8070/readyz' "$CURL_STUB_LOG" ||
  { echo "default topology must probe the api readiness endpoint" >&2; cat "$CURL_STUB_LOG" >&2; exit 1; }

# PUBLISH_TOPOLOGY が空（値なし）でも既定の domain-split に落ちる。
sed -i 's/^PUBLISH_TOPOLOGY=.*/PUBLISH_TOPOLOGY=/' .env
: >"$DOCKER_STUB_LOG"; : >"$CURL_STUB_LOG"
./scripts/deploy.sh app >/tmp/deploy-topology-empty.out 2>&1
grep -q '公開トポロジ: domain-split' /tmp/deploy-topology-empty.out ||
  { echo "empty PUBLISH_TOPOLOGY must fall back to domain-split" >&2; exit 1; }
sed -i 's/^PUBLISH_TOPOLOGY=.*/PUBLISH_TOPOLOGY=domain-split/' .env

# 実ドメインで公開する場合も同じ経路。まとめの URL だけが公開オリジン基点に変わる。
sed -i 's|^ISSUER=.*|ISSUER=https://api.example.com|' .env
sed -i 's|^PUBLIC_WEB_BASE_URL=.*|PUBLIC_WEB_BASE_URL=https://id.example.com|' .env
: >"$DOCKER_STUB_LOG"; : >"$CURL_STUB_LOG"
./scripts/deploy.sh app >/tmp/deploy-domain-split.out 2>&1
grep -q '公開トポロジ: domain-split' /tmp/deploy-domain-split.out
grep -q -- '-f docker-compose.deploy.yml -f docker-compose.domain-split.yml' "$DOCKER_STUB_LOG" ||
  { echo "domain-split must overlay docker-compose.domain-split.yml" >&2; cat "$DOCKER_STUB_LOG" >&2; exit 1; }
grep -q 'http://127.0.0.1:8060/readyz' "$CURL_STUB_LOG" ||
  { echo "domain-split must probe the web readiness endpoint" >&2; cat "$CURL_STUB_LOG" >&2; exit 1; }
grep -q 'http://127.0.0.1:8070/readyz' "$CURL_STUB_LOG" ||
  { echo "domain-split must probe the api readiness endpoint" >&2; cat "$CURL_STUB_LOG" >&2; exit 1; }
# 画面（/login・/admin）を返すのは web なので、まとめの URL は PUBLIC_WEB_BASE_URL 基点にする。
grep -q 'ログイン URL: https://id.example.com/' /tmp/deploy-domain-split.out ||
  { echo "login URL must be based on PUBLIC_WEB_BASE_URL, not ISSUER" >&2; cat /tmp/deploy-domain-split.out >&2; exit 1; }
grep -q '管理コンソール: https://id.example.com/.*/admin' /tmp/deploy-domain-split.out ||
  { echo "admin URL must be based on PUBLIC_WEB_BASE_URL, not ISSUER" >&2; exit 1; }

# IPv6 の bind では、URL のホスト部として使える形（角括弧付き）で probe する。
# ワイルドカード（::）は IPv4 ループバックではなく IPv6 ループバックへ読み替える
# （IPv6 のみで待ち受けているポートへ到達できず readiness がタイムアウトするため）。
sed -i 's/^WEB_BIND_HOST=.*/WEB_BIND_HOST=::/' .env
sed -i 's/^API_BIND_HOST=.*/API_BIND_HOST=::1/' .env
: >"$DOCKER_STUB_LOG"; : >"$CURL_STUB_LOG"
./scripts/deploy.sh app >/tmp/deploy-ipv6.out 2>&1
grep -q 'http://\[::1\]:8060/readyz' "$CURL_STUB_LOG" ||
  { echo "IPv6 wildcard bind must probe the bracketed IPv6 loopback" >&2; cat "$CURL_STUB_LOG" >&2; exit 1; }
grep -q 'http://\[::1\]:8070/readyz' "$CURL_STUB_LOG" ||
  { echo "IPv6 literal bind must be bracketed in the probe URL" >&2; cat "$CURL_STUB_LOG" >&2; exit 1; }
sed -i 's/^WEB_BIND_HOST=.*/WEB_BIND_HOST=127.0.0.1/' .env
sed -i 's/^API_BIND_HOST=.*/API_BIND_HOST=127.0.0.1/' .env

# override ファイルが無い配置で domain-split を指定したら fail-fast する。
mv docker-compose.domain-split.yml "$TMP/domain-split.yml.bak"
set +e
./scripts/deploy.sh app >/tmp/deploy-domain-split-missing.out 2>&1
status=$?
set -e
[[ $status -ne 0 ]] || { echo "domain-split without the overlay file must fail" >&2; exit 1; }
grep -q 'docker-compose.domain-split.yml がありません' /tmp/deploy-domain-split-missing.out
mv "$TMP/domain-split.yml.bak" docker-compose.domain-split.yml

# 未知のトポロジ値は誤記のまま起動させず fail-fast する。
sed -i 's/^PUBLISH_TOPOLOGY=.*/PUBLISH_TOPOLOGY=split-domain/' .env
set +e
./scripts/deploy.sh app >/tmp/deploy-topology-typo.out 2>&1
status=$?
set -e
[[ $status -ne 0 ]] || { echo "unknown PUBLISH_TOPOLOGY must fail" >&2; exit 1; }
grep -q "PUBLISH_TOPOLOGY が不正です: 'split-domain'" /tmp/deploy-topology-typo.out

# single-origin を明記したときだけ override を重ねず、readiness も WEB_PORT の 1 つだけを見る。
sed -i 's/^PUBLISH_TOPOLOGY=.*/PUBLISH_TOPOLOGY=single-origin/' .env
sed -i 's|^ISSUER=.*|ISSUER=http://localhost:8060|' .env
# 単一オリジンでは api・web とも同一オリジン（= WEB_PORT）に揃える。
sed -i 's|^PUBLIC_WEB_BASE_URL=.*|PUBLIC_WEB_BASE_URL=http://localhost:8060|' .env
: >"$DOCKER_STUB_LOG"; : >"$CURL_STUB_LOG"
./scripts/deploy.sh app >/tmp/deploy-single-origin.out 2>&1
grep -q '公開トポロジ: single-origin' /tmp/deploy-single-origin.out
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
# 単一オリジン構成では ISSUER と PUBLIC_WEB_BASE_URL が同一オリジンなので、まとめの URL も同じ。
grep -q 'ログイン URL: http://localhost:8060/' /tmp/deploy-single-origin.out ||
  { echo "single-origin login URL must stay on the WEB_PORT origin" >&2; exit 1; }

# Compose 定義に無いサービスは、待機タイムアウトではなく即座に原因を示して落とす。
set +e
DOCKER_STUB_SERVICES="api mariadb migrate web" ./scripts/deploy.sh app >/tmp/deploy-missing-service.out 2>&1
status=$?
set -e
[[ $status -ne 0 ]] || { echo "missing compose service must fail" >&2; exit 1; }
grep -q 'proxy が Compose 定義にありません' /tmp/deploy-missing-service.out
unset CURL_STUB_LOG

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
# 結論（初期化が必要）を明示すること。
grep -q '初期化' /tmp/deploy-checksum-fail.out ||
  { echo "checksum mismatch guidance must state that DB re-initialization is required" >&2; exit 1; }
# バックアップコマンドは compose の service（mariadb）経由で解決すること（v1/v2 の命名差に耐える）。
grep -q 'exec -T mariadb sh -c' /tmp/deploy-checksum-fail.out ||
  { echo "backup command must resolve the mariadb service via compose (v1/v2 safe)" >&2; exit 1; }
# Compose v2 固定のコンテナ名（project-mariadb-1）を直書きしないこと（v1 では project_mariadb_1）。
if grep -qE 'docker exec [^ ]*-mariadb-1' /tmp/deploy-checksum-fail.out; then
  echo "backup command must not hardcode a compose-v2 container name" >&2
  exit 1
fi
# 対処案内を MariaDB のコンテナログ（無関係なノイズ）で埋もれさせないこと。
if grep -q '\[idp\]\[diagnostic\] logs tail: mariadb' /tmp/deploy-checksum-fail.out; then
  echo "checksum mismatch must not bury guidance under mariadb container logs" >&2
  exit 1
fi

# バックアップ対象 DB 名は ENV > .env の順で解決すること（MARIADB_DATABASE を環境で上書きしたら
# 既定 idp ではなくその DB をダンプするコマンドを出す）。
: >"$DOCKER_STUB_LOG"
set +e
MARIADB_DATABASE=tenantdb DOCKER_STUB_MIGRATE_CHECKSUM_MISMATCH=1 ./scripts/deploy.sh migrate >/tmp/deploy-checksum-dbname.out 2>&1
set -e
grep -q -- '--single-transaction tenantdb' /tmp/deploy-checksum-dbname.out ||
  { echo "backup command must honor MARIADB_DATABASE env override (env > .env)" >&2; cat /tmp/deploy-checksum-dbname.out >&2; exit 1; }
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

# 短い値（開発・CI で使う MARIADB_PASSWORD=idp 等）をマスク対象にしてはならない。マスクはログ本文への
# 単純な部分文字列置換なので、`idp` を潰すと `[idp][diagnostic]` まで消えて診断が読めなくなる。
: >"$DOCKER_STUB_LOG"
set +e
MARIADB_PASSWORD=idp MARIADB_ROOT_PASSWORD=root DOCKER_STUB_FAIL_UP=1 \
  ./scripts/deploy.sh app >/tmp/deploy-short-secret.out 2>&1
status=$?
set -e
[[ $status -eq 42 ]] || { echo "deploy failure should preserve failing exit code" >&2; cat /tmp/deploy-short-secret.out >&2; exit 1; }
grep -q '\[idp\]\[diagnostic\] compose ps' /tmp/deploy-short-secret.out ||
  { echo "short secret values must not be masked (diagnostics became unreadable)" >&2; cat /tmp/deploy-short-secret.out >&2; exit 1; }

# DB 資格情報は .env の字面ではなく Compose が解決した実効値（mariadb コンテナの環境変数）を使うこと。
# `.env` の dotenv 構文（引用符・インラインコメント・変数展開）を deploy.sh 側で再実装すると必ず
# 食い違い、パスワード同期が誤った値を DB へ書き込んでしまう。
: >"$DOCKER_STUB_LOG"
export DOCKER_STUB_CONTAINER_ENV_FILE="$TMP/container-env"
cat > "$DOCKER_STUB_CONTAINER_ENV_FILE" <<'ENVEOF'
MARIADB_USER=idp
MARIADB_DATABASE=idp
MARIADB_PASSWORD=resolved-secret
MARIADB_ROOT_PASSWORD=resolved-root-secret
ENVEOF
# .env には Compose なら `resolved-secret` に解決される書き方（引用符＋インラインコメント）を置く。
sed -i 's|^MARIADB_PASSWORD=.*|MARIADB_PASSWORD="resolved-secret" # rotated|' .env
./scripts/deploy.sh migrate >/tmp/deploy-resolved-secret.out 2>&1
grep -qF -- '-presolved-secret' "$DOCKER_STUB_LOG" ||
  { echo "DB credentials must come from the Compose-resolved container environment" >&2; cat "$DOCKER_STUB_LOG" >&2; exit 1; }
if grep -qF -- '-p"resolved-secret"' "$DOCKER_STUB_LOG"; then
  echo "raw .env text must not be passed through to the DB client" >&2
  exit 1
fi
# 実効値は .env の字面と一致しなくてもマスクされること（診断出力からの漏洩防止）。
if grep -qF 'resolved-secret' /tmp/deploy-resolved-secret.out; then
  echo "Compose-resolved secret must be masked in deploy output" >&2
  exit 1
fi
sed -i "s|^MARIADB_PASSWORD=.*|${orig_pw_line}|" .env
rm -f "$DOCKER_STUB_CONTAINER_ENV_FILE"
unset DOCKER_STUB_CONTAINER_ENV_FILE

# 資格情報は正しいが DB へのアクセス権が無い場合（1044）は、パスワード不一致（1045）ではない。
# 権限を勝手に GRANT で広げず、破壊的な reset も勧めない汎用エラーとして報告する。
: >"$DOCKER_STUB_LOG"
set +e
DOCKER_STUB_FAIL_DB_PRIV=1 DOCKER_STUB_ROOT_AUTH_OK=1 \
  ./scripts/deploy.sh migrate >/tmp/deploy-db-priv-fail.out 2>&1
status=$?
set -e
[[ $status -eq 1 ]] || { echo "deploy must fail fast on a privilege error" >&2; cat /tmp/deploy-db-priv-fail.out >&2; exit 1; }
grep -q 'DB preflight failed (non-authentication error)' /tmp/deploy-db-priv-fail.out ||
  { echo "privilege error must not be reported as password drift" >&2; cat /tmp/deploy-db-priv-fail.out >&2; exit 1; }
if grep -q 'ALTER USER\|GRANT ALL' "$DOCKER_STUB_LOG"; then
  echo "privilege error must not trigger password sync / GRANT" >&2
  cat "$DOCKER_STUB_LOG" >&2
  exit 1
fi
if grep -q './deploy.sh reset' /tmp/deploy-db-priv-fail.out; then
  echo "privilege error must NOT recommend destructive reset" >&2
  exit 1
fi

# アプリ用ユーザーの認証が失敗しても root が有効なら、DB 側のパスワードを .env へ揃えて復旧し、
# デプロイを続行する（既存データを保持したまま drift を解消する）。
: >"$DOCKER_STUB_LOG"
export DOCKER_STUB_SYNCED_MARKER="$TMP/db-password-synced"
rm -f "$DOCKER_STUB_SYNCED_MARKER"
set +e
DOCKER_STUB_FAIL_DB_AUTH=1 DOCKER_STUB_ROOT_AUTH_OK=1 \
  ./scripts/deploy.sh migrate >/tmp/deploy-db-auth-sync.out 2>&1
status=$?
set -e
[[ $status -eq 0 ]] || {
  echo "deploy must recover from password drift when root credentials are valid" >&2
  cat /tmp/deploy-db-auth-sync.out >&2; exit 1
}
grep -q 'ALTER USER' "$DOCKER_STUB_LOG" ||
  { echo "password drift must be repaired via ALTER USER" >&2; cat "$DOCKER_STUB_LOG" >&2; exit 1; }
grep -q 'run --rm -T migrate' "$DOCKER_STUB_LOG" ||
  { echo "migrate must run after the password was synced" >&2; exit 1; }
if grep -q "$(grep '^MARIADB_PASSWORD=' .env | cut -d= -f2-)" /tmp/deploy-db-auth-sync.out; then
  echo "secret was not masked while syncing the DB password" >&2
  exit 1
fi
rm -f "$DOCKER_STUB_SYNCED_MARKER"
unset DOCKER_STUB_SYNCED_MARKER

# アプリ用ユーザーでも root でも認証できない場合（= .env ごと別物）は、意味のない migrate リトライでは
# なくプリフライトで即座に停止し、原因と対処を提示する。
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
if grep -q 'ALTER USER' "$DOCKER_STUB_LOG"; then
  echo "password must not be altered when root credentials are invalid too" >&2
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
# build.sh は既定トポロジ（domain-split）の override 一式も必ず同梱する。
cp "$ROOT/docker-compose.domain-split.yml" "$TMP/bundle/"
cp "$ROOT/docker/nginx.domain-split.conf" "$TMP/bundle/docker/"
for svc in api web migrate; do
  touch "$TMP/bundle/assay-${svc}.tar"
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
cp "$ROOT/docker-compose.domain-split.yml" "$TMP/stg/"
cp "$ROOT/docker/nginx.domain-split.conf" "$TMP/stg/docker/"
for svc in api web migrate; do
  touch "$TMP/stg/assay-${svc}.tar"
  printf '%s_ref=idp/%s:stg\n%s_image_id=sha256:stub-image-id\n' "$svc" "$svc" "$svc"
done >"$TMP/stg/manifest.env"
cd "$TMP/stg"

: >"$DOCKER_STUB_LOG"
./deploy.sh migrate >/tmp/deploy-stg.out 2>&1
grep -q '生成元: .env.staging.example' /tmp/deploy-stg.out ||
  { echo "stg dir must seed .env from .env.staging.example" >&2; cat /tmp/deploy-stg.out >&2; exit 1; }
grep -q '^WEB_PORT=10010$' .env || { echo "stg .env must use staging WEB_PORT (10010)" >&2; exit 1; }
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
grep -q '^API_PORT=10011$' .env || { echo "stg .env must use staging API_PORT (10011)" >&2; exit 1; }
# ADR-0018 決定 4: セッション Cookie は host-only。COOKIE_DOMAIN は既定で設定しない
# （旧構成からの移行掃除でのみ一時的に有効化する）。
if grep -qE '^COOKIE_DOMAIN=' .env; then
  echo "stg .env must not set COOKIE_DOMAIN by default (ADR-0018)" >&2; exit 1
fi

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
