#!/usr/bin/env bash
# scripts/build-remote-container.sh — git 非搭載のデプロイ先（例: Synology DSM）向けの一ホスト方式。
#
# ソース取得＆イメージビルドは「dev コンテナ」内で行い（コンテナに git・ツールチェーンがある前提）、
# 生成された dist/ をコンテナのワークスペース（ホストから見えるパス）からデプロイ先へ取り込み、
# 同梱の deploy.sh を実行する。**デプロイ先に git は不要**（build-remote.sh の git 版が使えない環境向け）。
#
# 3 ステップを 1 本で実行する（旧来の別 pick.sh は本スクリプトへ統合済み）:
#   BUILD  … dev コンテナ内で git pull → scripts/build.sh（dist/ を生成）
#   PICK   … ビルド済み dist/ をデプロイ先へ取り込み
#   DEPLOY … 取り込んだ deploy.sh を実行
#
# 使い方（デプロイ先で。モードはどの引数位置でも拾う。既定 migrate）:
#   ./build-remote-container.sh            # migrate
#   ./build-remote-container.sh app
#   ./build-remote-container.sh reset
#
# 設定（環境変数で上書き可。下の既定値を環境に合わせて書き換えてもよい）:
#   IDP_PROJECT        dev コンテナ内のプロジェクト名（設定ファイルの PROJECT でも指定可。{PROJECT} の展開元）
#   IDP_DEV_CONTAINER  ビルドを行う dev コンテナ名
#   IDP_DEV_USER       コンテナ内でビルドする実行ユーザー
#   IDP_DEV_WORKDIR    コンテナ内のリポジトリ working dir（scripts/build.sh がある場所）
#   IDP_DIST_DIR       ホストから見えるビルド済み dist/ の絶対パス（必須。無指定はエラー）
#   IDP_TARGET_DIR     デプロイ先ディレクトリ（既定: このスクリプトの場所）
#
# 設定は上記の環境変数のほか、**スクリプトと同じ場所の `build-remote-container.env`**（KEY=VALUE 形式）
# にも書ける（`export` 等のコマンド実行は不要）。プロジェクト名は PROJECT に 1 度だけ書けばよく、
# 各パスの `{PROJECT}` がその値へ展開される。例:
#     PROJECT=idp
#     IDP_DEV_CONTAINER=ubuntu-dev
#     IDP_DEV_WORKDIR=/work/project/{PROJECT}
#     IDP_DIST_DIR=/var/services/homes/kyon/.../work/project/{PROJECT}/dist
# ※ デプロイ用 `.env`（deploy.sh / Compose が読む秘密情報ファイル）とは別物。ここへ書いても効かない。
#
# 前提: docker（デプロイ先）と、ビルド用 dev コンテナが起動していること。
set -euo pipefail

# ---- 設定ファイル（任意）を読み込む: <スクリプトと同じ場所>/build-remote-container.env -----
# KEY=VALUE 行だけを安全に取り込む（source/eval しない）。既に設定済みの環境変数を優先し、
# 未設定のものだけ設定ファイルの値で補う。行頭コメント（#）・空行・不正キーは無視し、値は前後空白と
# 空白に続くインラインコメント（` # ...`）を除去する（`#` を含む値でも空白が前に無ければ保持）。
_config_file="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/build-remote-container.env"
_config_loaded_keys=()   # 設定ファイルから実際に取り込んだキー（起動情報の表示用）
if [[ -f "$_config_file" ]]; then
  while IFS= read -r _line || [[ -n "$_line" ]]; do
    _line="${_line%$'\r'}"
    [[ "$_line" =~ ^[[:space:]]*# ]] && continue
    [[ "$_line" == *=* ]] || continue
    _key="${_line%%=*}"
    _val="${_line#*=}"
    _key="${_key//[[:space:]]/}"
    _val="${_val%%[[:space:]]#*}"                 # 空白+# 以降のインラインコメントを除去
    _val="${_val#"${_val%%[![:space:]]*}"}"       # 先頭空白を除去
    _val="${_val%"${_val##*[![:space:]]}"}"       # 末尾空白を除去
    [[ "$_key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
    if [[ -z "${!_key:-}" ]]; then
      export "$_key=$_val"
      _config_loaded_keys+=("$_key")
    fi
  done <"$_config_file"
fi

# ---- 既定値（設定ファイル／環境変数で上書きされる。直接編集も可） ------------------
# プロジェクト名は 1 度だけ定義する。環境変数 IDP_PROJECT > 設定ファイル PROJECT > 既定値 idp。
project="${IDP_PROJECT:-${PROJECT:-idp}}"
dev_container="${IDP_DEV_CONTAINER:-ubuntu-dev}"
dev_user="${IDP_DEV_USER:-sshuser}"
dev_workdir="${IDP_DEV_WORKDIR:-/work/project/$project}"
dist_dir="${IDP_DIST_DIR:-}"
target_dir="${IDP_TARGET_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"

# パス中の {PROJECT} を project の値へ展開する（プロジェクト名の一元管理）。
# 置換文字列側では bash 5.2 の patsub_replacement により `&`（マッチ全体）・`\` が
# 特別扱いされるため、project 値を差し込む前に両者をエスケープしてリテラル挿入する。
_project_repl="${project//\\/\\\\}"
_project_repl="${_project_repl//&/\\&}"
dev_workdir="${dev_workdir//\{PROJECT\}/$_project_repl}"
dist_dir="${dist_dir//\{PROJECT\}/$_project_repl}"

log() { printf '[idp:build-remote-container] %s\n' "$*" >&2; }
die() { printf '[idp:build-remote-container][error] %s\n' "$*" >&2; exit 1; }

# モードは引数のどこにあっても拾う（余分な語が前に付いても動く）。既定 migrate。
mode=migrate
for arg in "$@"; do
  case "$arg" in app | migrate | reset) mode="$arg" ;; esac
done

# ---- 起動情報（どの引数で動き・どの設定を読み込み・どう解決したかを表示） -------------
log "START  project=$project  mode=$mode"
log "  引数        : $([[ $# -gt 0 ]] && printf '%q ' "$@" || printf '(なし → 既定 %s)' "$mode")"
if [[ -f "$_config_file" ]]; then
  if [[ ${#_config_loaded_keys[@]} -gt 0 ]]; then
    log "  設定ファイル: $_config_file （読込: ${_config_loaded_keys[*]}）"
  else
    log "  設定ファイル: $_config_file （取り込んだキーなし＝全て環境変数が優先）"
  fi
else
  log "  設定ファイル: なし（$_config_file 不在。環境変数と既定値のみ）"
fi
log "  解決した設定:"
log "    PROJECT           = $project"
log "    IDP_DEV_CONTAINER = $dev_container"
log "    IDP_DEV_USER      = $dev_user"
log "    IDP_DEV_WORKDIR   = $dev_workdir"
log "    IDP_DIST_DIR      = ${dist_dir:-(未設定)}"
log "    IDP_TARGET_DIR    = $target_dir"

command -v docker >/dev/null 2>&1 || die "docker が見つかりません。"
[[ -n "$dist_dir" ]] || die "IDP_DIST_DIR（ホストから見えるビルド済み dist/ の絶対パス）を設定してください。"

cd "$target_dir"

# デプロイ先 .env のイメージ設定（IMAGE_TAG / IMAGE_PREFIX）をビルドへ引き継ぐ。これを揃えないと
# build.sh は既定（idp/*:latest）で作る一方、docker-compose.deploy.yml は .env のタグを要求して
# 起動時にイメージ不一致で失敗する（stg/prod タグ・カスタム prefix 運用への対応）。環境変数が
# 明示されていればそれを優先し、無ければ既存 .env から読む（初回は .env 未生成のため既定値）。
read_env_value() {
  local key="$1"
  [[ -f "$target_dir/.env" ]] || return 0
  # キーが無ければ空を返す。set -o pipefail 下でも grep の不一致(1)で落ちないよう `|| true`。
  { grep -E "^${key}=" "$target_dir/.env" | tail -n1 | cut -d= -f2- | tr -d '\r'; } || true
}
image_tag="${IMAGE_TAG:-$(read_env_value IMAGE_TAG)}"
image_prefix="${IMAGE_PREFIX:-$(read_env_value IMAGE_PREFIX)}"
image_tag="${image_tag:-latest}"
image_prefix="${image_prefix:-idp}"

# --- BUILD（dev コンテナ内で git pull → build.sh） ------------------------------
log "BUILD  dev コンテナ '$dev_container' でビルドします（$dev_workdir, image=${image_prefix}/*:${image_tag}）..."
docker exec \
  -e IMAGE_TAG="$image_tag" -e IMAGE_PREFIX="$image_prefix" \
  -u "$dev_user" "$dev_container" bash -lc "
  set -e
  cd '$dev_workdir'
  git pull --ff-only
  ./scripts/build.sh
" || die "コンテナ内ビルドに失敗しました。"

# --- PICK（ビルド済み dist をデプロイ先へ取り込み。旧 pick.sh 相当） --------------
log "PICK   $dist_dir → $target_dir"
[[ -d "$dist_dir" ]] || die "dist が見つかりません: $dist_dir（build.sh の出力先か IDP_DIST_DIR を確認）。"
# デプロイ先の .env は取り込みで絶対に壊さない（秘密情報を保全）。万一 dist 側に .env が紛れても
# 上書きしないよう、コピー前に退避し、コピー後に戻す（.env の管理は deploy.sh に一本化）。
env_backup=""
if [[ -f "$target_dir/.env" ]]; then
  env_backup="$(mktemp)"
  cp -a "$target_dir/.env" "$env_backup"
fi
cp -a "$dist_dir/." "$target_dir/"
if [[ -n "$env_backup" ]]; then
  mv -f "$env_backup" "$target_dir/.env"
fi
[[ -f "$target_dir/deploy.sh" ]] || die "deploy.sh が取り込まれていません（build.sh の出力を確認）。"
chmod +x "$target_dir"/*.sh 2>/dev/null || true

# --- DEPLOY（.env は deploy.sh が管理: 初回生成・以後は不足キーのみ追記・秘密は不変） ----
log "DEPLOY ./deploy.sh $mode"
"$target_dir/deploy.sh" "$mode"

log "END    mode=$mode"
