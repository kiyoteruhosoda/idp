#!/usr/bin/env bash
# scripts/test_with_target_lock.sh — with-target-lock.sh の排他を検証する（CI 用）。
#
# 本物の cargo は使わない。作業場所を CARGO_TARGET_DIR に見立てて、次の 3 つを確かめる:
#   1. 同時に 2 本流しても、ロックの中身は重ならない
#   2. コマンドの終了コードがそのまま返る
#   3. コマンドが後に残したプロセスはロックを握らない（e2e.sh の api・web にあたる）
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK="$ROOT/scripts/with-target-lock.sh"
# ⚠ 固定の /tmp/<名前> を使わない（scripts/README.md）。
TMP="$(mktemp -d)"
leftover=""
on_exit() {
  [[ -z "$leftover" ]] || kill "$leftover" 2>/dev/null || true
  rm -rf "$TMP"
}
trap on_exit EXIT

pass() { printf '  ok   %s\n' "$*"; }
fail() { printf '  FAIL %s\n' "$*" >&2; exit 1; }

export CARGO_TARGET_DIR="$TMP/target"

# --- 1. 排他: 中で「入った・出た」を記録し、入れ子になっていないことを見る ---
critical() {
  "$LOCK" bash -c 'echo "in $1" >>"$2"; sleep 1; echo "out $1" >>"$2"' _ "$1" "$TMP/trace"
}
critical a &
pid_a=$!
critical b &
pid_b=$!
wait "$pid_a"
wait "$pid_b"
# 期待するのは in X / out X / in Y / out Y の形だけ。
mapfile -t trace <"$TMP/trace"
[[ ${#trace[@]} -eq 4 ]] || fail "記録が 4 行ではない: ${trace[*]}"
first="${trace[0]#in }"
second="${trace[2]#in }"
[[ "${trace[1]}" == "out $first" && "${trace[3]}" == "out $second" && "$first" != "$second" ]] ||
  fail "ロックの中身が重なった: ${trace[*]}"
pass "同時に 2 本流しても重ならない"

# --- 2. 終了コード ---
set +e
"$LOCK" bash -c 'exit 7'
status=$?
set -e
[[ $status -eq 7 ]] || fail "終了コードが 7 ではない: $status"
pass "終了コードをそのまま返す"

# --- 3. 後に残ったプロセスがロックを握らない ---
"$LOCK" bash -c 'sleep 30 >/dev/null 2>&1 & echo $! >"$1"' _ "$TMP/leftover.pid"
leftover="$(cat "$TMP/leftover.pid")"
kill -0 "$leftover" 2>/dev/null || fail "残すはずのプロセスが居ない"
timeout 5 "$LOCK" true || fail "後に残ったプロセスがロックを握っている"
pass "後に残ったプロセスはロックを握らない"

# --- 引数なしは使い方を出して 2 ---
set +e
"$LOCK" 2>/dev/null
status=$?
set -e
[[ $status -eq 2 ]] || fail "引数なしの終了コードが 2 ではない: $status"
pass "引数なしは使い方を出す"
