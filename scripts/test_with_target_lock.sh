#!/usr/bin/env bash
# scripts/test_with_target_lock.sh — verifies how with-target-lock.sh takes slots (for CI).
#
# Does not use real cargo. Treats empty directories under the work area as slots and checks:
#   1. Two taken at once get different slots (no waiting)
#   2. When all slots are taken it waits, and can take one once the holder goes away (= the job's container goes away)
#   3. A slot over the limit is emptied when taken. If not over, left as is
#   4. Steps without a slot or that lost their slot stop. If held, the command runs and its exit code is returned
#   5. The holder survives the end of a step (the next step can use the same slot)
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK="$ROOT/scripts/with-target-lock.sh"
# ⚠ Do not use a fixed /tmp/<name> (scripts/README.md).
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

# Takes a slot and returns one line "slot token holder". $1 is that job's GITHUB_ENV.
take() { GITHUB_ENV="$1" "$LOCK" --take 2>/dev/null; }

# --- 1. Two at once: different slots ---
take "$TMP/env-a" >"$TMP/a" &
pid_a=$!
take "$TMP/env-b" >"$TMP/b" &
pid_b=$!
wait "$pid_a"
wait "$pid_b"
read -r dir_a token_a holder_a <"$TMP/a"
read -r dir_b token_b holder_b <"$TMP/b"
holders+=("$holder_a" "$holder_b")
[[ "$dir_a" != "$dir_b" ]] || fail "two took the same slot: $dir_a"
grep -qx "CARGO_TARGET_DIR=$dir_a" "$TMP/env-a" || fail "slot not written to GITHUB_ENV"
grep -qx "TARGET_SLOT_TOKEN=$token_a" "$TMP/env-a" || fail "token not written to GITHUB_ENV"
pass "two taken at once get different slots"

# --- 5. The holder survives the end of a step ---
kill -0 "$holder_a" 2>/dev/null || fail "holder went away when the step ended"
pass "holder survives the end of a step"

# --- 2. Wait when all are taken; take one once the holder goes away ---
take "$TMP/env-c" >"$TMP/c" &
pid_c=$!
sleep 3
kill -0 "$pid_c" 2>/dev/null || fail "did not wait although all slots were taken"
kill "$holder_a"
wait "$pid_c"
read -r dir_c _ holder_c <"$TMP/c"
holders+=("$holder_c")
[[ "$dir_c" == "$dir_a" ]] || fail "took $dir_c instead of the freed slot"
pass "waits when all are taken, then takes the freed slot"

# --- 4. Steps that lost their slot or took none stop ---
set +e
CARGO_TARGET_DIR="$dir_a" TARGET_SLOT_TOKEN="$token_a" "$LOCK" true 2>/dev/null
status=$?
set -e
[[ $status -ne 0 ]] || fail "ran in a slot taken by another job"
set +e
"$LOCK" true 2>/dev/null
status=$?
set -e
[[ $status -ne 0 ]] || fail "ran without taking a slot"
set +e
CARGO_TARGET_DIR="$dir_b" TARGET_SLOT_TOKEN="$token_b" "$LOCK" bash -c 'exit 7'
status=$?
set -e
[[ $status -eq 7 ]] || fail "exit code in the held slot is not 7: $status"
pass "runs only in a held slot and returns the exit code as is"

# --- 3. Limit: empty if over, leave as is if not ---
kill "$holder_b" "$holder_c"
sleep 1
export TARGET_SLOTS="$TMP/slot-3"
mkdir -p "$TMP/slot-3/debug"
head -c 2000 /dev/zero >"$TMP/slot-3/debug/big"
read -r _ _ holder <<<"$(TARGET_SLOT_MAX_BYTES=100000 take "$TMP/env-d")"
holders+=("$holder")
[[ -f "$TMP/slot-3/debug/big" ]] || fail "emptied although not over the limit"
kill "$holder"
sleep 1
read -r _ token holder <<<"$(TARGET_SLOT_MAX_BYTES=1000 take "$TMP/env-e")"
holders+=("$holder")
[[ ! -e "$TMP/slot-3/debug" ]] || fail "not emptied although over the limit"
[[ "$(cat "$TMP/slot-3/.ci-target.owner")" == "$token" ]] || fail "emptying also removed the token"
pass "only slots over the limit are emptied when taken"

# --- No arguments prints usage and exits 2 ---
set +e
"$LOCK" 2>/dev/null
status=$?
set -e
[[ $status -eq 2 ]] || fail "exit code without arguments is not 2: $status"
pass "no arguments prints usage"
