#!/usr/bin/env bash
# scripts/with-target-lock.sh — takes a "slot" of cargo's build output dir (target/) and holds it until the job ends (for CI).
#
#   ./scripts/with-target-lock.sh --take                          # once at the start of the job; takes a free slot
#   ./scripts/with-target-lock.sh cargo test --workspace --locked # runs inside the slot taken
#
# ⚠ **CI's `target/` is shared by PR and main jobs** (`.forgejo/workflows/ci.yml`).
#   When two run in the same place, one rebuilds and deletes or replaces test executables and rlibs
#   the other built. Symptoms differ every time (`could not execute process … (never executed)`,
#   `extern location … does not exist`, Doc-tests `unresolved import`, `VersionMissing`),
#   and the run goes red while every test itself is ok (5 times in PR #23, #24, #25 on 2026-09-16).
#   ⚠ **cargo's own lock does not prevent this.** cargo holds it only while building; while finished
#   tests are running, another job's cargo can rewrite the same executables.
#
# There are 3 places (`/cache/target-1` to `-3`; there are 3 runner hosts, so a 4th is not needed).
# Until 2026-10-28 one place was used one at a time with a per-step lock, and with 3 PRs queued the last
# waited about 26 minutes (https://task.nolumia.com/issues/702).
#
# - `--take` takes a free slot and **keeps holding it until the job's container goes away** (the holder is a
#   detached `sleep`; when the container goes, it goes too and the slot frees). The slot is passed to later
#   steps via `$GITHUB_ENV` -- ⚠ **one job keeps using the same slot**, so executables built by an earlier
#   step are not deleted when a later step uses them.
# - If every slot is taken, wait until one frees (limit `TARGET_SLOT_WAIT_SECONDS`).
# - If the slot taken exceeds `TARGET_SLOT_MAX_BYTES` (default 20 GB), empty it before use.
#   cargo never cleans old artifacts itself; one place had piled up 52 GB (one build is about 11 GB).
# - The form with a command checks that this step's job holds the slot before running it.
#   If not held, stop (catches touching the shared place with bare cargo here).
#
# ⚠ The lock is taken on the place itself (a file inside each slot's volume). The volumes are on
#   nolumialab's local disk, so flock works across containers.
set -Eeuo pipefail

usage() {
  echo "usage: $0 --take | <command> [args...]" >&2
  exit 2
}
[[ $# -gt 0 ]] || usage

read -r -a slots <<<"${TARGET_SLOTS:-/cache/target-1 /cache/target-2 /cache/target-3}"
max_bytes="${TARGET_SLOT_MAX_BYTES:-20000000000}"
wait_seconds="${TARGET_SLOT_WAIT_SECONDS:-3000}"
# Upper limit of holding time. Anything over `timeout-minutes` (60 min) suffices. The slot comes back even if a container lingers.
hold_seconds="${TARGET_SLOT_HOLD_SECONDS:-7200}"

say() { echo "[with-target-lock] $*" >&2; }

# Try to take one slot. If taken, print the holder's pid and return 0; if taken by someone else, 1.
try_slot() {
  local dir="$1"
  mkdir -p "$dir"
  exec 9>"$dir/.ci-target.lock"
  if ! flock -n 9; then
    exec 9>&-
    return 1
  fi
  # The holder inherits fd 9. ⚠ Close stdin/stdout -- left open, the step never finishes.
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
      say "no slot freed after waiting ${wait_seconds} seconds (${slots[*]})"
      exit 1
    fi
    [[ -n "$said" ]] || say "all slots are taken (${slots[*]}); waiting for one to free"
    said=1
    sleep "${TARGET_SLOT_POLL_SECONDS:-10}"
  done
  local waited=$(($(date +%s) - started))
  say "took slot $dir (waited ${waited} seconds)"

  local size
  size="$(du -sb --exclude=.ci-target.lock --exclude=.ci-target.owner "$dir" | cut -f1)"
  if ((size > max_bytes)); then
    say "slot $dir is ${size} bytes, over the limit ${max_bytes}; emptying it before use"
    find "$dir" -mindepth 1 -maxdepth 1 ! -name .ci-target.lock -exec rm -rf {} +
  else
    say "slot $dir is ${size} bytes (limit ${max_bytes})"
  fi

  local token="$holder-$RANDOM$RANDOM-$started"
  echo "$token" >"$dir/.ci-target.owner"
  if [[ -n "${GITHUB_ENV:-}" ]]; then
    {
      echo "CARGO_TARGET_DIR=$dir"
      echo "TARGET_SLOT_TOKEN=$token"
    } >>"$GITHUB_ENV"
  fi
  # Also print the slot taken to stdout, for tests and logs.
  printf '%s %s %s\n' "$dir" "$token" "$holder"
}

run() {
  local dir="${CARGO_TARGET_DIR:-}" token="${TARGET_SLOT_TOKEN:-}"
  if [[ -z "$dir" || -z "$token" ]]; then
    say "no slot taken; put \`$0 --take\` at the start of the job"
    exit 1
  fi
  if [[ "$(cat "$dir/.ci-target.owner" 2>/dev/null)" != "$token" ]]; then
    say "slot $dir no longer belongs to this job (the holder went away and another job took it)"
    exit 1
  fi
  # If the holder is alive, the lock cannot be taken here.
  if flock -n "$dir/.ci-target.lock" true; then
    say "nobody holds slot $dir (the holder went away)"
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
