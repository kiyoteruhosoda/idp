#!/usr/bin/env bash
# scripts/test_with_target_lock.sh — with-target-lock.sh の番の取り方を検証する（CI 用）。
#
# 本物の cargo は使わない。作業場所の下の空のディレクトリを番に見立てて、次を確かめる:
#   1. 2 本同時に取ると、別々の番になる（待たない）
#   2. 番が全部埋まっていれば待ち、握り手が消えたら（＝ジョブのコンテナが消えたら）取れる
#   3. 上限を超えた番は、取ったときに空になる。超えていなければそのまま
#   4. 番を取っていない段・番を失った段は止める。握っていれば実行し、終了コードを返す
#   5. 握り手は段が終わっても残る（次の段も同じ番を使える）
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK="$ROOT/scripts/with-target-lock.sh"
# ⚠ 固定の /tmp/<名前> を使わない（scripts/README.md）。
TMP="$(mktemp -d)"
holders=()
on_exit() {
  local pid
  for pid in "${holders[@]}"; do kill "$pid" 2>/dev/null || true; done
  rm -rf "$TMP"
}
trap on_exit EXIT

pass() { printf '  ok   %s\n' "$*"; }
fail() { printf '  FAIL %s\n' "$*" >&2; exit 1; }

export TARGET_SLOTS="$TMP/slot-1 $TMP/slot-2"
export TARGET_SLOT_POLL_SECONDS=1
export TARGET_SLOT_WAIT_SECONDS=20
unset CARGO_TARGET_DIR TARGET_SLOT_TOKEN GITHUB_ENV

# 番を取って「番 token 握り手」の 1 行を返す。$1 はそのジョブの GITHUB_ENV。
take() { GITHUB_ENV="$1" "$LOCK" --take 2>/dev/null; }

# --- 1. 同時に 2 本: 別々の番 ---
take "$TMP/env-a" >"$TMP/a" &
pid_a=$!
take "$TMP/env-b" >"$TMP/b" &
pid_b=$!
wait "$pid_a"
wait "$pid_b"
read -r dir_a token_a holder_a <"$TMP/a"
read -r dir_b token_b holder_b <"$TMP/b"
holders+=("$holder_a" "$holder_b")
[[ "$dir_a" != "$dir_b" ]] || fail "2 本が同じ番を取った: $dir_a"
grep -qx "CARGO_TARGET_DIR=$dir_a" "$TMP/env-a" || fail "GITHUB_ENV に番が書かれていない"
grep -qx "TARGET_SLOT_TOKEN=$token_a" "$TMP/env-a" || fail "GITHUB_ENV に札が書かれていない"
pass "同時に 2 本取ると別々の番になる"

# --- 5. 段が終わっても握り手は残る ---
kill -0 "$holder_a" 2>/dev/null || fail "段が終わったら握り手が消えた"
pass "握り手は段が終わっても残る"

# --- 2. 全部埋まっていれば待ち、握り手が消えたら取れる ---
take "$TMP/env-c" >"$TMP/c" &
pid_c=$!
sleep 3
kill -0 "$pid_c" 2>/dev/null || fail "番が全部埋まっているのに待たなかった"
kill "$holder_a"
wait "$pid_c"
read -r dir_c _ holder_c <"$TMP/c"
holders+=("$holder_c")
[[ "$dir_c" == "$dir_a" ]] || fail "空いた番ではなく $dir_c を取った"
pass "埋まっていれば待ち、空いた番を取る"

# --- 4. 番を失った段・取っていない段は止める ---
set +e
CARGO_TARGET_DIR="$dir_a" TARGET_SLOT_TOKEN="$token_a" "$LOCK" true 2>/dev/null
status=$?
set -e
[[ $status -ne 0 ]] || fail "他のジョブに取られた番で実行した"
set +e
"$LOCK" true 2>/dev/null
status=$?
set -e
[[ $status -ne 0 ]] || fail "番を取っていないのに実行した"
set +e
CARGO_TARGET_DIR="$dir_b" TARGET_SLOT_TOKEN="$token_b" "$LOCK" bash -c 'exit 7'
status=$?
set -e
[[ $status -eq 7 ]] || fail "握っている番で終了コードが 7 ではない: $status"
pass "握っている番でだけ実行し、終了コードをそのまま返す"

# --- 3. 上限: 超えていれば空に、超えていなければそのまま ---
kill "$holder_b" "$holder_c"
sleep 1
export TARGET_SLOTS="$TMP/slot-3"
mkdir -p "$TMP/slot-3/debug"
head -c 2000 /dev/zero >"$TMP/slot-3/debug/big"
read -r _ _ holder <<<"$(TARGET_SLOT_MAX_BYTES=100000 take "$TMP/env-d")"
holders+=("$holder")
[[ -f "$TMP/slot-3/debug/big" ]] || fail "上限を超えていないのに空にした"
kill "$holder"
sleep 1
read -r _ token holder <<<"$(TARGET_SLOT_MAX_BYTES=1000 take "$TMP/env-e")"
holders+=("$holder")
[[ ! -e "$TMP/slot-3/debug" ]] || fail "上限を超えているのに空にしなかった"
[[ "$(cat "$TMP/slot-3/.ci-target.owner")" == "$token" ]] || fail "空にしたら札まで消えた"
pass "上限を超えた番だけ、取ったときに空にする"

# --- 引数なしは使い方を出して 2 ---
set +e
"$LOCK" 2>/dev/null
status=$?
set -e
[[ $status -eq 2 ]] || fail "引数なしの終了コードが 2 ではない: $status"
pass "引数なしは使い方を出す"
