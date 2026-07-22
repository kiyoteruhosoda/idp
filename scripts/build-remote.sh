#!/usr/bin/env bash
# scripts/build-remote.sh — デプロイ先（リモート）で「取得 → 自己更新 → ビルド → デプロイ」を一気通貫で行う。
#
# 二ホスト方式（ビルド側で build.sh → dist/ を作り、デプロイ先へ転送）に対し、本スクリプトは
# **デプロイ先だけで完結する一ホスト方式**を提供する。デプロイ先に置くのは最初にこの
# build-remote.sh 一本だけでよい。ソースは git から取得するので dist/ の転送は不要。
# 以後スクリプト自体が更新されても、実行時に git 上の最新版へ自分を書き換えて再実行する（自己更新）。
#
# 使い方（デプロイ先で。モードは deploy.sh へそのまま渡す。既定 app）:
#   ./build-remote.sh            # app: 取得 → ビルド → deploy.sh app（初回・更新とも）
#   ./build-remote.sh migrate    # migrate: 取得 → ビルド → deploy.sh migrate
#   ./build-remote.sh reset      # reset: 取得 → ビルド → deploy.sh reset（破壊的）
#
# 設定（環境変数。既定のままでも動く）:
#   IDP_REPO_URL   取得元 git URL   （既定 https://github.com/kiyoteruhosoda/idp.git）
#   IDP_BRANCH     取得ブランチ     （既定 main）
#   IDP_SRC_DIR    ソース取得先 DIR （既定 <このスクリプトの場所>/src）
#   IMAGE_TAG      イメージタグ     （build.sh / deploy へ引き継ぐ。既定 latest）
#
# 前提: git・docker（Compose v2 か v1）・openssl。
set -euo pipefail

log() { printf '[idp:build-remote] %s\n' "$*" >&2; }
die() { printf '[idp:build-remote][error] %s\n' "$*" >&2; exit 1; }

# --- 自身の正準パスとソース取得先を解決 ------------------------------------------
resolve_path() {
  if command -v realpath >/dev/null 2>&1; then
    realpath "$1"
  else
    printf '%s/%s\n' "$(cd "$(dirname "$1")" && pwd)" "$(basename "$1")"
  fi
}

self="$(resolve_path "${BASH_SOURCE[0]}")"
script_dir="$(dirname "$self")"

repo_url="${IDP_REPO_URL:-https://github.com/kiyoteruhosoda/idp.git}"
branch="${IDP_BRANCH:-main}"
src_dir="${IDP_SRC_DIR:-$script_dir/src}"
repo_script="$src_dir/scripts/build-remote.sh"

mode="${1:-app}"
case "$mode" in
  app | migrate | reset) ;;
  -h | --help) sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) die "不明なモード: $mode（app / migrate / reset のいずれか）" ;;
esac

command -v git >/dev/null 2>&1 || die "git が見つかりません。"
command -v docker >/dev/null 2>&1 || die "docker が見つかりません。"

# --- ソース取得（clone / 更新） -------------------------------------------------
fetch_source() {
  if [[ -d "$src_dir/.git" ]]; then
    log "ソースを更新します: $src_dir (branch=$branch)"
    # IDP_REPO_URL の変更（fork/mirror → 本番リポジトリ切替など）に追従。既存 clone の
    # 古い origin を使い続けて誤ったリポジトリからデプロイしないよう、取得前に URL を合わせる。
    if git -C "$src_dir" remote get-url origin >/dev/null 2>&1; then
      git -C "$src_dir" remote set-url origin "$repo_url"
    else
      git -C "$src_dir" remote add origin "$repo_url"
    fi
    git -C "$src_dir" fetch --depth 1 origin "$branch"
    git -C "$src_dir" reset --hard FETCH_HEAD
  else
    # 既存ディレクトリでも空なら git clone できる。非空かつ非 git のときだけ拒否する。
    if [[ -e "$src_dir" && -n "$(ls -A "$src_dir" 2>/dev/null)" ]]; then
      die "$src_dir は git リポジトリではなく空でもありません。IDP_SRC_DIR を見直すか、空のディレクトリを指定してください。"
    fi
    log "ソースを取得します: $repo_url → $src_dir (branch=$branch)"
    git clone --depth 1 --branch "$branch" "$repo_url" "$src_dir"
  fi
}

# --- 自己更新（リポジトリの build-remote.sh と不一致なら自分を書き換えて再実行） ----
self_update_and_reexec() {
  [[ -f "$repo_script" ]] || die "$repo_script が見つかりません（リポジトリ構成が想定と異なります）。"
  # 同一ファイルを実行している場合（ソースチェックアウト内から直接実行）は更新対象なし。
  [[ "$(resolve_path "$repo_script")" == "$self" ]] && return 0
  if cmp -s "$repo_script" "$self"; then
    return 0
  fi
  log "build-remote.sh がリポジトリ最新版と不一致のため、自身を更新して再実行します。"
  cp -f "$repo_script" "$self"
  chmod +x "$self"
  export IDP_BUILD_REMOTE_UPDATED=1
  exec "$self" "$mode"
}

# 取得と自己更新は初回のみ（再実行後は IDP_BUILD_REMOTE_UPDATED=1 でスキップし二重取得を防ぐ）。
if [[ "${IDP_BUILD_REMOTE_UPDATED:-0}" != 1 ]]; then
  fetch_source
  self_update_and_reexec
fi

# --- ビルド → デプロイ ----------------------------------------------------------
[[ -x "$src_dir/scripts/build.sh" ]] || die "$src_dir/scripts/build.sh が見つかりません。"
log "イメージをビルドします（build.sh）..."
IMAGE_TAG="${IMAGE_TAG:-latest}" "$src_dir/scripts/build.sh"

deploy_script="$src_dir/dist/deploy.sh"
[[ -x "$deploy_script" ]] || die "$deploy_script が見つかりません（build.sh の出力を確認してください）。"
log "デプロイします（deploy.sh $mode）..."
"$deploy_script" "$mode"

log "完了（mode: $mode）。"
