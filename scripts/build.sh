#!/usr/bin/env bash
# scripts/build.sh — ソース側でビルドする（デプロイ先とは別ホスト。ここでは起動しない）。
#
# ソースがあるのはこのホストだけ。デプロイ先はソースを持たないため、ここでイメージを作って
# レジストリ push か tar 保存で受け渡す。本スクリプトはコンテナを起動しない（配置は init/deploy が担う）。
#
# モード:
#   （既定）      cargo でワークスペースの release binary（idp / idp-web）をビルドする。
#   --docker      Docker イメージ（api / web / migrate）をビルドしてタグ付けする（起動しない）。
#   --push        --docker で作ったイメージをレジストリへ push する（IMAGE_PREFIX にホストを含めること）。
#   --save DIR    --docker で作ったイメージを DIR/*.tar へ保存する（レジストリ不要の受け渡し用）。
#   --check       ビルド前に fmt チェック・clippy（警告をエラー扱い）・test を実行する。
#   --help        使い方を表示する。
#
# イメージ名: ${IMAGE_PREFIX:-idp}/{api,web,migrate}:${IMAGE_TAG:-latest}
#   例）レジストリ配布: IMAGE_PREFIX=registry.example.com/idp IMAGE_TAG=1.2.3 ./scripts/build.sh --docker --push
#   例）tar 配布:       ./scripts/build.sh --docker --save ./dist   → dist/*.tar を scp してデプロイ先で docker load
#
# 前提: ネイティブビルドは rustup（cargo）。Docker ビルドは docker。
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
source "$repo_root/scripts/lib.sh"

target="native"
run_check=0
do_push=0
save_dir=""

usage() {
  sed -n '2,19p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --docker) target="docker" ;;
    --push)   target="docker"; do_push=1 ;;
    --save)   target="docker"; save_dir="${2:?--save にはディレクトリを指定してください}"; shift ;;
    --check)  run_check=1 ;;
    -h | --help) usage; exit 0 ;;
    *) die "不明な引数: $1（--help で使い方を表示）" ;;
  esac
  shift
done

# --- 事前検証（任意） ----------------------------------------------------------
if [[ $run_check -eq 1 ]]; then
  command -v cargo >/dev/null 2>&1 || die "cargo が見つかりません（rustup を導入してください）。"
  log "fmt チェック（cargo fmt --check）..."
  cargo fmt --all -- --check
  log "clippy（警告をエラー扱い）..."
  cargo clippy --workspace --all-targets -- -D warnings
  log "テスト（cargo test）..."
  cargo test --workspace --locked
fi

# --- ビルド --------------------------------------------------------------------
case "$target" in
  native)
    command -v cargo >/dev/null 2>&1 || die "cargo が見つかりません（rustup を導入してください）。"
    log "release binary をビルドします（idp / idp-web）..."
    cargo build --release --locked --bin idp --bin idp-web
    log "完了。成果物: target/release/idp・target/release/idp-web"
    ;;
  docker)
    command -v docker >/dev/null 2>&1 || die "docker が見つかりません。"
    # push は長いビルドの前に前提を検証する（既定 idp のままでは push させない）。
    if [[ $do_push -eq 1 ]]; then
      [[ -n "${IMAGE_PREFIX:-}" && "${IMAGE_PREFIX}" != "idp" ]] ||
        die "--push には IMAGE_PREFIX にレジストリ/名前空間を指定してください（例: registry.example.com/idp）。既定の idp のままでは push できません。"
    fi
    # サービス名 → Dockerfile ステージ の対応。イメージ名は image_ref で共通化する。
    declare -A stages=([api]=runtime-api [web]=runtime-web [migrate]=migrate)
    for svc in api web migrate; do
      ref="$(image_ref "$svc")"
      log "イメージをビルドします: $ref（stage=${stages[$svc]}）..."
      docker build --target "${stages[$svc]}" -t "$ref" -f Dockerfile .
    done

    if [[ $do_push -eq 1 ]]; then
      for svc in api web migrate; do
        ref="$(image_ref "$svc")"
        log "push します: $ref ..."
        docker push "$ref"
      done
      log "完了。デプロイ先で ./scripts/init.sh（初回）または ./scripts/deploy.sh（更新）を実行してください。"
    elif [[ -n "$save_dir" ]]; then
      mkdir -p "$save_dir"
      for svc in api web migrate; do
        ref="$(image_ref "$svc")"
        out="$save_dir/idp-${svc}.tar"
        log "保存します: $ref → $out ..."
        docker save "$ref" -o "$out"
      done
      log "完了。$save_dir/*.tar をデプロイ先へ転送し、docker load -i で読み込んでください。"
    else
      log "完了。イメージをビルドしました（受け渡しは --push または --save を使用）。"
    fi
    ;;
esac
