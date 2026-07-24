#!/usr/bin/env bash
# deploy.sh — デプロイ先の単一入口（app / migrate / reset）。
#
# 使い方（モード引数は必須）:
#   ./deploy.sh app      通常デプロイ（migration を冪等に適用し、アプリコンテナを必ず入れ替える）
#   ./deploy.sh migrate  DDL 更新時（migration 適用後、アプリコンテナも必ず入れ替える）
#   ./deploy.sh reset    DB 初期化（volume 削除）後、migration 適用とアプリコンテナ入れ替えを行う
#
# 前提: docker（Compose v2 または docker-compose v1）と openssl。ソース不要・ビルドしない。
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
[[ -f "$base/$compose_file" ]] || die "$compose_file がありません（デプロイ用 Compose）。"

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
  log "ログファイル: $deploy_log_file"
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

command -v docker >/dev/null 2>&1 || die "docker が見つかりません。"
if ! docker info >/dev/null 2>&1; then
  die "Docker daemon に接続できません（daemon 停止または権限不足）。docker info が成功する状態で再実行してください。"
fi

CURRENT_PHASE="startup"
PHASE_STARTED_AT=0
APP_SERVICES=(api web proxy)
compose=()
COMPOSE_PROJECT=""
LEGACY_COMPOSE_PROJECT_NAME=""
DIAGNOSTIC_SERVICES=(mariadb migrate api web proxy)
# デプロイ完了時のまとめ表示に使う root テナントの URL（replace_app_containers で確定する）。
ROOT_LOGIN_URL=""
ROOT_ADMIN_URL=""

get_env_var() {
  local key="$1"
  [[ -f "$env_file" ]] || return 0
  grep -E "^${key}=" "$env_file" 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' || true
}

mask_secrets() {
  local sed_expr=() key value escaped
  if [[ -f "$env_file" ]]; then
    for key in MARIADB_PASSWORD MARIADB_ROOT_PASSWORD KEY_ENCRYPTION_KEY INTERNAL_SERVICE_TOKEN CSRF_SECRET; do
      value="$(get_env_var "$key" 2>/dev/null || true)"
      [[ -n "$value" ]] || continue
      # 秘密値を sed の BRE パターンとして使うため、メタ文字（\ . * [ ] ^ $ と区切りの |）を
      # エスケープする。これを怠ると、記号を含むパスワード（例 MARIADB_PASSWORD=[…）で不正な
      # 正規表現になり sed が失敗し、pipefail 下では migrate 成功時のマスク処理までデプロイを中断させる。
      escaped="$(printf '%s' "$value" | sed 's/[][\.*^$|]/\\&/g')"
      sed_expr+=(-e "s|${escaped}|***MASKED***|g")
    done
  fi
  if [[ ${#sed_expr[@]} -gt 0 ]]; then sed "${sed_expr[@]}"; else cat; fi
}

phase_begin() { CURRENT_PHASE="$1"; PHASE_STARTED_AT="$(date +%s)"; log "▶ $CURRENT_PHASE を開始します"; }
phase_end() { log "✓ $CURRENT_PHASE が完了しました ($(($(date +%s) - PHASE_STARTED_AT))s)"; }

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

# 初回 .env 生成のテンプレートを、デプロイディレクトリ名から選ぶ。stg/prod 系のディレクトリでは
# 専用テンプレート（WEB_PORT・IMAGE_TAG・COMPOSE_PROJECT_NAME を分離済み）を優先し、無ければ
# 汎用 .env.example へ退避する。これにより「.env 未作成のまま実行して汎用既定で起動してしまう」事故を防ぐ。
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

# 指定キーの現在値に含まれる CHANGE-ME だけを置換値へ差し替える（host:port 等の他部分は保持）。
# stg/prod テンプレートの DATABASE_URL がそれぞれ異なるポートを持つため、値ごと上書きしない。
fill_change_me() {
  local key="$1" replacement="$2" current
  current="$(get_env_var "$key")"
  [[ -n "$current" ]] || return 0
  set_env_var "$key" "${current//CHANGE-ME/$replacement}"
}

init_compose_command() {
  local project_name
  project_name="$(get_env_var COMPOSE_PROJECT_NAME)"
  project_name="${project_name:-${LEGACY_COMPOSE_PROJECT_NAME:-$(default_compose_project_name)}}"
  if docker compose version >/dev/null 2>&1; then
    compose=(docker compose --project-name "$project_name" -f "$compose_file")
  elif command -v docker-compose >/dev/null 2>&1; then
    compose=(docker-compose --project-name "$project_name" -f "$compose_file")
  else
    die "docker compose（v2）または docker-compose（v1）が見つかりません。"
  fi
  COMPOSE_PROJECT="$project_name"
  log "Compose project name: $project_name"
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

# 既存 .env に、`.env.example` にあって不足している「設定キー」だけを追記する（バージョン更新で
# 増えたキーへ自動追随）。既存の値は一切書き換えない（秘密・手編集を保全）。次は対象外:
#   * 秘密情報（example 値が CHANGE-ME）。誤って空/プレースホルダで上書きしないため。
#   * 値が空のキー（deploy.sh が別途設定する、または任意設定のもの）。
#   * COMPOSE_PROJECT_NAME（volume 名前空間。誤って別 volume を指すと破損するため既存挙動を維持）。
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
    # 追記前に末尾改行を保証する。手編集で末尾改行の無い .env でも、最終行の値へ連結して
    # 壊さないようにする（例: `FOO=bar` + `LOG_FORMAT=pretty` → `FOO=barLOG_FORMAT=...` を防ぐ）。
    if [[ -s "$env_file" && -n "$(tail -c1 "$env_file")" ]]; then printf '\n' >>"$env_file"; fi
    printf '%s\n' "$line" >>"$env_file"
    added=$((added + 1))
  done <"$example_file"
  [[ $added -gt 0 ]] &&
    log ".env に不足していた設定キー ${added} 個を .env.example から追記しました（既存値・秘密は不変）。"
  return 0
}

# .env にテンプレートのプレースホルダ CHANGE-ME が残っていたら fail-fast する。
# `.env.*.example` を手動コピーして置換し忘れた場合、api は KEY_ENCRYPTION_KEY 等を base64 として
# 解釈できず crash-loop する（エラーは `Invalid symbol 45, offset 6` としか出ない）ため、
# コンテナ起動前に原因と対処を明示して止める。
ensure_no_placeholder_secrets() {
  local key value leftover=()
  for key in MARIADB_PASSWORD MARIADB_ROOT_PASSWORD KEY_ENCRYPTION_KEY INTERNAL_SERVICE_TOKEN CSRF_SECRET DATABASE_URL TEST_DATABASE_URL; do
    value="$(get_env_var "$key")"
    [[ "$value" == *CHANGE-ME* ]] && leftover+=("$key")
  done
  [[ ${#leftover[@]} -eq 0 ]] && return 0
  err ".env にテンプレートのプレースホルダ CHANGE-ME が残っています: ${leftover[*]}"
  err "対処: .env の該当キーへ実値を設定してから再実行してください。"
  err "  * KEY_ENCRYPTION_KEY / CSRF_SECRET: openssl rand -base64 32"
  err "  * INTERNAL_SERVICE_TOKEN: openssl rand -hex 32"
  err "  * MARIADB_PASSWORD / MARIADB_ROOT_PASSWORD: openssl rand -hex 24"
  err "    （DATABASE_URL / TEST_DATABASE_URL 内のパスワード部分も MARIADB_PASSWORD と揃える）"
  die "placeholder secrets (CHANGE-ME) remain in .env"
}

ensure_env_file() {
  if [[ -f "$env_file" ]]; then
    log "既存の .env を使用します（上書きしません）。"
    merge_missing_env_keys
    ensure_no_placeholder_secrets
    if [[ -z "$(get_env_var COMPOSE_PROJECT_NAME)" ]]; then
      LEGACY_COMPOSE_PROJECT_NAME="$(legacy_compose_project_name)"
      warn "既存 .env に COMPOSE_PROJECT_NAME が無いため、既存 volume を保護するため従来の Compose project name ($LEGACY_COMPOSE_PROJECT_NAME) を使用します。変更する場合は volume 移行または reset 後に .env へ明示してください。"
    fi
    return 0
  fi
  local seed_example
  seed_example="$(select_env_example)"
  [[ -f "$seed_example" ]] || die ".env の生成元テンプレートが見つかりません: $seed_example"
  command -v openssl >/dev/null 2>&1 || die "openssl が見つかりません。"
  log ".env を新規生成します（生成元: $(basename "$seed_example")、秘密情報を乱数生成）。"
  cp "$seed_example" "$env_file"
  local db_password
  db_password="$(openssl rand -hex 24)"
  set_env_var MARIADB_PASSWORD "$db_password"
  set_env_var MARIADB_ROOT_PASSWORD "$(openssl rand -hex 24)"
  set_env_var KEY_ENCRYPTION_KEY "$(openssl rand -base64 32)"
  set_env_var INTERNAL_SERVICE_TOKEN "$(openssl rand -hex 32)"
  set_env_var CSRF_SECRET "$(openssl rand -base64 32)"
  # テンプレートの DATABASE_URL は host:port（stg/prod で異なる）を保持し、CHANGE-ME だけ実値へ置換する。
  fill_change_me DATABASE_URL "$db_password"
  fill_change_me TEST_DATABASE_URL "$db_password"
  set_env_var COMPOSE_PROJECT_NAME "$(default_compose_project_name)"
  chmod 600 "$env_file"
  ensure_no_placeholder_secrets
  log ".env を生成しました（パーミッション 600、Compose project: $(get_env_var COMPOSE_PROJECT_NAME)）。"
}

load_image_with_progress() {
  local tar="$1" size_human pid waited=0
  size_human="$(du -h "$tar" 2>/dev/null | cut -f1 || true)"
  log "イメージを読み込みます: $tar (${size_human:-unknown size})"
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
    tar="$dist_dir/idp-${svc}.tar"
    actual_id="$(docker image inspect -f '{{.Id}}' "$ref" 2>/dev/null || true)"
    if [[ -z "$actual_id" || ( -n "$expected_id" && "$actual_id" != "$expected_id" ) ]]; then
      [[ -f "$tar" ]] || die "イメージ $ref がありません（$tar も無し）。build.sh が出力した dist/ を配置してください。"
      load_image_with_progress "$tar"
      actual_id="$(docker image inspect -f '{{.Id}}' "$ref" 2>/dev/null || true)"
    fi
    [[ -n "$actual_id" ]] || die "イメージ $ref を解決できません。"
    [[ -z "$expected_id" || "$actual_id" == "$expected_id" ]] || die "$ref の image ID が manifest と不一致です: $actual_id != $expected_id"
    revision="$(docker image inspect -f '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$ref" 2>/dev/null || true)"
    if [[ -n "$revision" ]]; then
      [[ -z "$first_revision" || "$revision" == "$first_revision" ]] || die "api/web/migrate の commit label が一致しません。"
      first_revision="$revision"
    fi
    log "配置対象 image: service=$svc ref=$ref revision=${revision:-unknown}"
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
  now="$(date +%s)"
  deadline=$((now + timeout))
  next_log=$((now + 30))
  log "$service の起動を待機します... (timeout=${timeout}s)"
  while (( $(date +%s) < deadline )); do
    cid="$("${compose[@]}" ps -q "$service" 2>/dev/null || true)"
    if [[ -n "$cid" ]]; then
      status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null || true)"
      case "$status" in
        healthy|running) log "$service: $status"; return 0 ;;
        exited|dead) compose_diagnostics; die "$service が異常終了しました（status=$status）。" ;;
        unhealthy|starting|created|restarting|*)
          now="$(date +%s)"
          if (( now >= next_log )); then
            log "$service: ${status:-unknown} のため待機を継続します (remaining=$((deadline - now))s)"
            next_log=$((now + 30))
          fi
          ;;
      esac
    fi
    sleep "$interval"
  done
  compose_diagnostics
  die "$service が healthy になりませんでした（${timeout}s タイムアウト）。"
}

# sqlx は適用済みマイグレーションの内容が変わると「migration <n> was previously applied but has
# been modified」で適用を中止する（履歴改変からの保護）。これは決定論的な失敗で、リトライしても必ず
# 同じ結果になる。MariaDB 側には失敗した migrate プロセスが接続を切ったときの
# 「Aborted connection ... Got an error reading communication packets」という一見無関係な警告だけが
# 残り、真因が埋もれる。ここで検出し、リトライせず対処可能なメッセージで即停止する（fail-fast）。
migration_checksum_mismatch_guidance() {
  local out="$1" ver
  # version が取れなくても案内は出す（set -e + pipefail で中断しないよう best-effort にする）。
  ver="$(printf '%s' "$out" | grep -oiE 'migration [0-9]+ was previously applied' \
    | grep -oE '[0-9]+' | head -n1 || true)"
  err "適用済みマイグレーション${ver:+（version $ver）}の内容が、DB に記録されたチェックサムと一致しません。"
  err "sqlx は適用済みマイグレーションの改変を検出すると適用を中止します（意図しない履歴改変からの保護）。"
  err "原因は次のいずれかです:"
  err "  1) 既存 DB へ適用済みのマイグレーションファイルを後から編集した"
  err "     （seed の一度限りの改訂など。例: root テナント UUID の固定化＝ADR-0011 / ADR-0009 §11）。"
  err "  2) デプロイするイメージと、この DB のマイグレーション履歴が食い違っている。"
  err "対処のいずれか:"
  err "  * 改訂が意図的で、この DB を作り直してよい（初期構築・staging 等）:"
  err "    ./deploy.sh reset で DB volume を作り直す（既存データは消えます。事前にバックアップを推奨。"
  err "    手順は docs/OPERATIONS.md「DB を作り直したいとき」）。"
  err "  * 編集が意図的でない: 該当マイグレーションファイルを元の内容へ戻して再デプロイする。"
  err "  * データを保持したまま改訂を反映したい: 適用済みファイルは編集せず、追記型の新規マイグレーション"
  err "    として書き直す（docs/OPERATIONS.md・migrations/README.md 参照）。"
}

run_migrations_with_retry() {
  local attempt status out
  for attempt in 1 2 3; do
    # migrate の出力を取り込みつつ（機微値をマスクして）画面へも流す。sqlx のエラー本文を検査して
    # 決定論的な失敗（チェックサム不一致）を判別するため。-T で疑似 TTY を無効化し出力を綺麗に取り込む。
    # set -e で捕捉前に停止しないよう、コマンド置換は if 条件で評価して exit code を退避する。
    if out="$("${compose[@]}" run --rm -T migrate 2>&1)"; then status=0; else status=$?; fi
    printf '%s\n' "$out" | mask_secrets
    [[ $status -eq 0 ]] && return 0

    # チェックサム不一致はリトライ無意味。原因（適用済みマイグレーションの改変）を明示して即停止する。
    if printf '%s' "$out" | grep -qiE 'was previously applied but has been modified'; then
      migration_checksum_mismatch_guidance "$out"
      compose_diagnostics_for migrate mariadb
      die "DB migration failed: 適用済みマイグレーションのチェックサム不一致（リトライを省略しました）"
    fi

    warn "DB migration failed (attempt $attempt/3, exit=$status); Docker logs を出力します"
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
  local db_user db_name db_password
  db_user="$(get_env_var MARIADB_USER)"; db_name="$(get_env_var MARIADB_DATABASE)"; db_password="$(get_env_var MARIADB_PASSWORD)"
  "${compose[@]}" exec -T mariadb mariadb -u"${db_user:-idp}" -p"$db_password" "${db_name:-idp}" -N -B \
    -e 'SELECT id FROM tenants WHERE parent_tenant_id IS NULL' 2>/dev/null || true
}

# MariaDB 公式イメージは data volume を「初回初期化時の MARIADB_PASSWORD」で固定し、その後 .env の
# パスワードを変更しても既存 volume 内の idp ユーザーには反映しない。結果 migrate/api は新パスワードで
# 接続し「Access denied for user 'idp'」で失敗する。healthcheck は root/socket でサーバ稼働しか見ないため、
# この不一致は検出できず、意味のない migrate リトライ 3 回で終わる。migration の前にアプリ用ユーザーで
# 実際に認証できるかを確認し、不一致なら原因と対処を明示して即座に停止する（fail-fast）。
preflight_db_auth() {
  local db_user db_name db_password attempt err_out auth_denied=0
  # 資格情報は Compose と同じ解決順（エクスポート済みシェル環境変数 > .env ファイル値）で読む。
  # Compose は ${MARIADB_PASSWORD} をシェル環境変数から先に補間するため、ここも同じ実効値を使わないと
  # 「Compose/migrate は有効なのにプリフライトだけ弾く／その逆」の食い違いが起きる。
  db_user="${MARIADB_USER:-$(get_env_var MARIADB_USER)}"; db_user="${db_user:-idp}"
  db_name="${MARIADB_DATABASE:-$(get_env_var MARIADB_DATABASE)}"; db_name="${db_name:-idp}"
  db_password="${MARIADB_PASSWORD:-$(get_env_var MARIADB_PASSWORD)}"
  log "DB 認証プリフライトを実行します（アプリ用ユーザー $db_user）..."
  for attempt in 1 2 3; do
    # migrate と同じ TCP 経路で試す（-h mariadb でコンテナ IP から接続＝ '%' ホスト定義にマッチ）。
    # ソケット（-h 省略＝localhost）だと host 別アカウント（'user'@'localhost'）がある環境で
    # migrate と別のアカウントを検証してしまうため、ホスト一致まで揃える。
    # 認証エラーはパスワード不一致なので即断（リトライしない）。それ以外の一過性の失敗のみ短く再試行する。
    if err_out="$("${compose[@]}" exec -T mariadb \
        mariadb -h mariadb -u"$db_user" -p"$db_password" "$db_name" -N -B -e 'SELECT 1' 2>&1)"; then
      log "DB 認証プリフライト OK（ユーザー $db_user）。"
      return 0
    fi
    if printf '%s' "$err_out" | grep -qi 'access denied'; then auth_denied=1; break; fi
    auth_denied=0
    [[ $attempt -lt 3 ]] && sleep 2
  done
  compose_diagnostics_for mariadb
  # 認証失敗（パスワード drift）のときだけ破壊的な reset を提案する。認証以外（DB 不在・権限・
  # ネットワーク障害等）で reset を勧めると誤って既存データを消しかねないため、診断を分ける。
  if [[ $auth_denied -eq 1 ]]; then
    err "アプリ用 DB ユーザー '$db_user' で認証できません（.env の MARIADB_PASSWORD が既存の DB volume と不一致）。"
    err "MariaDB は data volume を初回作成時のパスワードで固定し、その後の .env 変更を反映しません。"
    err "対処のいずれか:"
    err "  * データを破棄してよい（初期構築・staging 等）: ./deploy.sh reset で DB volume を作り直す（既存データは消えます）"
    err "  * データを保持したい: .env の MARIADB_PASSWORD を volume 作成時の値へ戻す"
    err "    （または root で ALTER USER '$db_user'@'%' IDENTIFIED BY ... を実行してパスワードを揃える）"
    die "DB authentication preflight failed"
  fi
  err "DB 認証プリフライトが認証以外の理由で失敗しました（ユーザー '$db_user'・DB '$db_name'）。"
  err "接続経路・DB の存在・権限・一時的なネットワーク障害を確認してください（詳細は上の mariadb ログと下の出力）。"
  printf '%s\n' "$err_out" | mask_secrets >&2
  die "DB preflight failed (non-authentication error)"
}

start_database() {
  log "MariaDB を起動します..."
  "${compose[@]}" up -d mariadb
  wait_healthy mariadb
  preflight_db_auth
}

remove_stale_renamed_containers() {
  # docker compose は --force-recreate の入れ替え時、旧コンテナを
  # 「<旧コンテナID先頭12桁>_<コンテナ名>」へ一時リネームしてから新コンテナを作る。
  # 前回のデプロイが途中で中断されるとこのリネーム済みコンテナが残り、次回の入れ替えが
  # 「Conflict. The container name ... is already in use」で失敗するため、事前に削除する。
  # 他プロジェクトを誤削除しないよう Compose のプロジェクトラベルで絞り込み、
  # コンテナ名の区切りは v2（-）と v1／互換モード（_）の両方を許容する。
  local cid name
  while read -r cid name; do
    [[ -n "$cid" ]] || continue
    warn "前回の入れ替えで残った一時コンテナを削除します: $name"
    docker rm -f "$cid" >/dev/null || warn "一時コンテナ $name (id=$cid) の削除に失敗しました。"
  done < <(docker ps -a --filter "label=com.docker.compose.project=${COMPOSE_PROJECT}" \
      --format '{{.ID}} {{.Names}}' 2>/dev/null \
    | grep -E "^[0-9a-f]+ [0-9a-f]{12}_${COMPOSE_PROJECT}[-_][a-z]+[-_][0-9]+$" || true)
}

replace_app_containers() {
  local web_port issuer ready_url root
  log "api・web・proxy を起動します（--force-recreate で全モード必ずアプリコンテナを入れ替え）..."
  remove_stale_renamed_containers
  "${compose[@]}" up -d --force-recreate --remove-orphans "${APP_SERVICES[@]}"
  wait_healthy api
  wait_healthy web
  wait_healthy proxy
  web_port="$(get_env_var WEB_PORT)"; web_port="${web_port:-8060}"
  issuer="$(get_env_var ISSUER)"; issuer="${issuer:-http://localhost:${web_port}}"
  ready_url="http://127.0.0.1:${web_port}/readyz"
  log "readiness を確認します: $ready_url"
  for _ in $(seq 1 30); do
    if curl -fsS "$ready_url" >/dev/null 2>&1; then
      root="$(root_tenant_id)"; root="${root:-<root-tenant-id>}"
      # デプロイ完了時のまとめ（スクリプト末尾）で表示するため、root テナントの URL を保持する。
      ROOT_LOGIN_URL="${issuer%/}/${root}/login"
      ROOT_ADMIN_URL="${issuer%/}/${root}/admin"
      log "readyz OK。デプロイが完了しました。"
      log "ログイン URL: $ROOT_LOGIN_URL"
      return 0
    fi
    sleep 2
  done
  compose_diagnostics
  die "readyz が OK になりませんでした。"
}

# デプロイの最後に root テナントの URL をまとめて表示する（実行者が接続先へ即座に飛べるように）。
# replace_app_containers が readyz OK 時に確定した値を使う。未確定（早期 return 等）なら表示しない。
print_root_urls() {
  [[ -n "$ROOT_ADMIN_URL" || -n "$ROOT_LOGIN_URL" ]] || return 0
  log "──────────────────────────────────────────────"
  log "Root テナント URL:"
  [[ -n "$ROOT_ADMIN_URL" ]] && log "  管理コンソール: $ROOT_ADMIN_URL"
  [[ -n "$ROOT_LOGIN_URL" ]] && log "  ログイン:       $ROOT_LOGIN_URL"
  log "──────────────────────────────────────────────"
}

phase_begin "env"; ensure_env_file; phase_end
init_compose_command
phase_begin "images"; ensure_images; phase_end

case "$mode" in
  reset)
    phase_begin "reset"
    warn "DB volume を削除します（.env は保持します）。"
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
