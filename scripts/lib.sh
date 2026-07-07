#!/usr/bin/env bash
# scripts/lib.sh — init.sh / deploy.sh 共通ヘルパ。単体では実行しない（source して使う）。

log() { printf '[idp] %s\n' "$*" >&2; }
die() { printf '[idp][error] %s\n' "$*" >&2; exit 1; }

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
ensure_images() {
  local missing=0 ref
  for svc in api web migrate; do
    ref="$(image_ref "$svc")"
    if docker image inspect "$ref" >/dev/null 2>&1; then
      continue
    fi
    log "ローカルに $ref がありません。pull を試みます..."
    docker pull "$ref" >/dev/null 2>&1 || { log "pull できませんでした: $ref"; missing=1; }
  done
  [[ $missing -eq 0 ]] ||
    die "必要なイメージが揃っていません。ソース側で ./scripts/build.sh --docker --push（レジストリ）、または --save して転送し docker load -i してください。"
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
        exited | dead) die "$service が異常終了しました（status=$status）。ログ: $compose logs $service" ;;
      esac
    fi
    sleep 2
  done
  die "$service が healthy になりませんでした（タイムアウト）。ログ: $compose logs $service"
}
