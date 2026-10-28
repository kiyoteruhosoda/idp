#!/usr/bin/env bash
# scripts/with-target-lock.sh — cargo の中間物置き場（target/）の「番」を取り、ジョブが終わるまで握る（CI 用）。
#
#   ./scripts/with-target-lock.sh --take                          # ジョブの最初に 1 回。空いている番を取る
#   ./scripts/with-target-lock.sh cargo test --workspace --locked # 取った番の中で実行する
#
# ⚠ **CI の `target/` は PR と main のジョブで共有している**（`.forgejo/workflows/ci.yml`）。
#   2 本が同じ置き場で並ぶと、片方が組んだ試験の実行ファイルや rlib を、もう片方が組み直して
#   消す・差し替える。症状は毎回違い（`could not execute process … (never executed)`、
#   `extern location … does not exist`、Doc-tests の `unresolved import`、`VersionMissing`）、
#   試験の中身はどれも ok のまま赤になる（2026-09-16 に PR #23・#24・#25 で計 5 回）。
#   ⚠ **cargo 自身のロックでは防げない。** cargo が握るのは組み立てている間だけで、組み終えた
#   試験を走らせている間に、別のジョブの cargo が同じ実行ファイルを書き換えられる。
#
# 置き場は 3 つ（`/cache/target-1`〜`-3`、ランナーの台が 3 台なので 4 つ目は要らない）。
# 2026-10-28 までは 1 つを段ごとのロックで 1 本ずつ使っていて、PR が 3 本並ぶと最後が
# 約 26 分待った（https://task.nolumia.com/issues/702）。
#
# - `--take` は空いている番を取り、**ジョブのコンテナが消えるまで握り続ける**（握るのは
#   切り離した `sleep`。コンテナが消えれば一緒に消えて番が空く）。番は `$GITHUB_ENV` で
#   後の段へ渡す ——⚠ **1 つのジョブの中では同じ番を使い続ける**ので、前の段が組んだ
#   実行ファイルを次の段が使っても消されない。
# - どの番も埋まっていれば、空くまで待つ（上限 `TARGET_SLOT_WAIT_SECONDS`）。
# - 取った番が `TARGET_SLOT_MAX_BYTES`（既定 20 GB）を超えていたら、使う前に空にする。
#   cargo は古い成果物を自分では掃除せず、1 つの置き場に 52 GB 積もっていた（1 回の組み立ては約 11 GB）。
# - コマンドを渡した形は、この段のジョブが番を握っているかを確かめてから実行する。
#   握っていなければ止める（素の cargo で共有の置き場を触るのを、ここで捕まえる）。
#
# ⚠ ロックは置き場そのもの（各番のボリュームの中のファイル）に掛ける。ボリュームは
#   nolumialab のローカルディスクにあり、コンテナをまたいでも flock が効く。
set -Eeuo pipefail

usage() {
  echo "usage: $0 --take | <command> [args...]" >&2
  exit 2
}
[[ $# -gt 0 ]] || usage

read -r -a slots <<<"${TARGET_SLOTS:-/cache/target-1 /cache/target-2 /cache/target-3}"
max_bytes="${TARGET_SLOT_MAX_BYTES:-20000000000}"
wait_seconds="${TARGET_SLOT_WAIT_SECONDS:-3000}"
# 握る時間の上限。`timeout-minutes`（60 分）を超えれば足りる。コンテナが残ってしまっても番は戻る。
hold_seconds="${TARGET_SLOT_HOLD_SECONDS:-7200}"

say() { echo "[with-target-lock] $*" >&2; }

# 1 つの番を取ってみる。取れたら握り手の pid を出して 0、埋まっていれば 1。
try_slot() {
  local dir="$1"
  mkdir -p "$dir"
  exec 9>"$dir/.ci-target.lock"
  if ! flock -n 9; then
    exec 9>&-
    return 1
  fi
  # 握り手は fd 9 を引き継ぐ。⚠ 標準入出力を閉じる ——開いたままだと段が終わらない。
  setsid sleep "$hold_seconds" 9>&9 </dev/null >/dev/null 2>&1 &
  local holder=$!
  exec 9>&-
  echo "$holder"
}

take() {
  local started dir holder="" said=""
  started="$(date +%s)"
  while :; do
    for dir in "${slots[@]}"; do
      if holder="$(try_slot "$dir")"; then
        break 2
      fi
    done
    if (($(date +%s) - started >= wait_seconds)); then
      say "${wait_seconds} 秒待っても番が空きませんでした（${slots[*]}）"
      exit 1
    fi
    [[ -n "$said" ]] || say "番が全部埋まっています（${slots[*]}）。空くまで待ちます"
    said=1
    sleep "${TARGET_SLOT_POLL_SECONDS:-10}"
  done
  local waited=$(($(date +%s) - started))
  say "番 $dir を取りました（${waited} 秒待ち）"

  local size
  size="$(du -sb --exclude=.ci-target.lock --exclude=.ci-target.owner "$dir" | cut -f1)"
  if ((size > max_bytes)); then
    say "番 $dir は ${size} バイトで上限 ${max_bytes} を超えています。空にしてから使います"
    find "$dir" -mindepth 1 -maxdepth 1 ! -name .ci-target.lock -exec rm -rf {} +
  else
    say "番 $dir は ${size} バイト（上限 ${max_bytes}）"
  fi

  local token="$holder-$RANDOM$RANDOM-$started"
  echo "$token" >"$dir/.ci-target.owner"
  if [[ -n "${GITHUB_ENV:-}" ]]; then
    {
      echo "CARGO_TARGET_DIR=$dir"
      echo "TARGET_SLOT_TOKEN=$token"
    } >>"$GITHUB_ENV"
  fi
  # 試験とログのため、取った番を標準出力にも出す。
  printf '%s %s %s\n' "$dir" "$token" "$holder"
}

run() {
  local dir="${CARGO_TARGET_DIR:-}" token="${TARGET_SLOT_TOKEN:-}"
  if [[ -z "$dir" || -z "$token" ]]; then
    say "番を取っていません。ジョブの最初に \`$0 --take\` を置いてください"
    exit 1
  fi
  if [[ "$(cat "$dir/.ci-target.owner" 2>/dev/null)" != "$token" ]]; then
    say "番 $dir はもうこのジョブのものではありません（握り手が消えて、他のジョブが取った）"
    exit 1
  fi
  # 握り手が生きていれば、ここで取れるはずがない。
  if flock -n "$dir/.ci-target.lock" true; then
    say "番 $dir を握っている者が居ません（握り手が消えた）"
    exit 1
  fi
  exec "$@"
}

if [[ "$1" == "--take" ]]; then
  [[ $# -eq 1 ]] || usage
  take
else
  run "$@"
fi
