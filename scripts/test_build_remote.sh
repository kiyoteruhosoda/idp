#!/usr/bin/env bash
# scripts/test_build_remote.sh — verifies build-remote.sh's fetch, self-update and build/deploy delegation (for CI).
# Uses real git (clones a local origin repository) and replaces build.sh / deploy.sh / docker with stubs.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.com
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.com

# --- origin repository (contains the "latest" build-remote.sh + a build.sh stub) ---------
origin="$TMP/origin"
mkdir -p "$origin/scripts"
cp "$ROOT/scripts/build-remote.sh" "$origin/scripts/build-remote.sh"
chmod +x "$origin/scripts/build-remote.sh"

# build.sh stub: generates dist/deploy.sh (stub) and records the call.
cat >"$origin/scripts/build.sh" <<'BUILD'
#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$root/dist"
cat >"$root/dist/deploy.sh" <<'DEPLOY'
#!/usr/bin/env bash
echo "DEPLOY-STUB mode=${1:-}" >>"${BUILD_REMOTE_TEST_LOG:?}"
DEPLOY
chmod +x "$root/dist/deploy.sh"
echo "BUILD-STUB tag=${IMAGE_TAG:-none}" >>"${BUILD_REMOTE_TEST_LOG:?}"
BUILD
chmod +x "$origin/scripts/build.sh"

git -C "$origin" init -q -b main
git -C "$origin" add -A
git -C "$origin" commit -qm "initial"

# --- docker stub (only satisfies build-remote.sh's existence check) -----------------------
mkdir -p "$TMP/bin"
cat >"$TMP/bin/docker" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
chmod +x "$TMP/bin/docker"
export PATH="$TMP/bin:$PATH"

# --- Deployment target host: place a single "old" build-remote.sh ---------------------
host="$TMP/host"
mkdir -p "$host"
cp "$ROOT/scripts/build-remote.sh" "$host/build-remote.sh"
printf '# stale local copy marker\n' >>"$host/build-remote.sh"  # differ from origin to trigger self-update
chmod +x "$host/build-remote.sh"

export BUILD_REMOTE_TEST_LOG="$TMP/calls.log"
export IDP_REPO_URL="$origin"
export IDP_SRC_DIR="$host/src"
export IMAGE_TAG="test-tag"

# --- 1) First run: clone -> self-update (old != latest) -> build -> deploy app --------------------
: >"$BUILD_REMOTE_TEST_LOG"
"$host/build-remote.sh" app >"$TMP/run1.out" 2>&1 || { echo "first run failed" >&2; cat "$TMP/run1.out" >&2; exit 1; }

[[ -d "$host/src/.git" ]] || { echo "source was not cloned" >&2; exit 1; }
grep -q 'updating ourselves and re-running' "$TMP/run1.out" || { echo "self-update did not happen" >&2; cat "$TMP/run1.out" >&2; exit 1; }
cmp -s "$host/build-remote.sh" "$host/src/scripts/build-remote.sh" \
  || { echo "local copy still differs from the latest after self-update" >&2; exit 1; }
grep -q 'BUILD-STUB tag=test-tag' "$BUILD_REMOTE_TEST_LOG" || { echo "build.sh was not called with IMAGE_TAG" >&2; cat "$BUILD_REMOTE_TEST_LOG" >&2; exit 1; }
grep -q 'DEPLOY-STUB mode=app' "$BUILD_REMOTE_TEST_LOG" || { echo "deploy.sh was not called with app" >&2; cat "$BUILD_REMOTE_TEST_LOG" >&2; exit 1; }
# Self-update happens only once (no infinite loop).
[[ "$(grep -c 'BUILD-STUB' "$BUILD_REMOTE_TEST_LOG")" -eq 1 ]] || { echo "build ran more than once (suspected re-run loop)" >&2; exit 1; }

# --- 2) Second run: already latest, so no self-update. Fetch the existing clone and delegate migrate --------
: >"$BUILD_REMOTE_TEST_LOG"
"$host/build-remote.sh" migrate >"$TMP/run2.out" 2>&1 || { echo "second run failed" >&2; cat "$TMP/run2.out" >&2; exit 1; }
if grep -q 'updating ourselves and re-running' "$TMP/run2.out"; then
  echo "self-update ran although already latest" >&2; exit 1
fi
grep -q 'updating source' "$TMP/run2.out" || { echo "existing clone was not updated (fetch)" >&2; cat "$TMP/run2.out" >&2; exit 1; }
grep -q 'DEPLOY-STUB mode=migrate' "$BUILD_REMOTE_TEST_LOG" || { echo "deploy.sh was not called with migrate" >&2; exit 1; }

# --- 3) Follow an IDP_REPO_URL change (replace the existing clone's origin and fetch) -------------
origin2="$TMP/origin2"
cp -a "$origin" "$origin2"
printf 'origin2\n' >"$origin2/MARKER"
git -C "$origin2" add -A
git -C "$origin2" commit -qm "origin2 marker"
: >"$BUILD_REMOTE_TEST_LOG"
IDP_REPO_URL="$origin2" "$host/build-remote.sh" app >"$TMP/run3.out" 2>&1 \
  || { echo "run after changing IDP_REPO_URL failed" >&2; cat "$TMP/run3.out" >&2; exit 1; }
[[ -f "$host/src/MARKER" ]] || { echo "origin replacement not applied (could not fetch from the new repository)" >&2; exit 1; }

# --- 4) Cloning into an existing empty directory works (refused only when non-empty and not git) -----------------
host2="$TMP/host2"
mkdir -p "$host2/src"   # case where an empty checkout location is prepared in advance
cp "$ROOT/scripts/build-remote.sh" "$host2/build-remote.sh"
chmod +x "$host2/build-remote.sh"
: >"$BUILD_REMOTE_TEST_LOG"
IDP_SRC_DIR="$host2/src" "$host2/build-remote.sh" app >"$TMP/run4.out" 2>&1 \
  || { echo "clone into an empty directory failed" >&2; cat "$TMP/run4.out" >&2; exit 1; }
[[ -d "$host2/src/.git" ]] || { echo "not cloned into the empty directory" >&2; exit 1; }

# Refuse a checkout location that is non-empty and not git.
host3="$TMP/host3"
mkdir -p "$host3/src"
touch "$host3/src/stray-file"
cp "$ROOT/scripts/build-remote.sh" "$host3/build-remote.sh"
chmod +x "$host3/build-remote.sh"
if IDP_SRC_DIR="$host3/src" "$host3/build-remote.sh" app >"$TMP/run5.out" 2>&1; then
  echo "a non-empty, non-git checkout location should be refused" >&2; exit 1
fi
grep -q 'not empty either' "$TMP/run5.out" || { echo "no error message for a non-empty checkout location" >&2; cat "$TMP/run5.out" >&2; exit 1; }

# --- 5) An unknown mode fails ------------------------------------------------------------
if "$host/build-remote.sh" bogus >"$TMP/run6.out" 2>&1; then
  echo "an unknown mode should fail" >&2; exit 1
fi
grep -q 'unknown mode' "$TMP/run6.out" || { echo "no error message for an unknown mode" >&2; exit 1; }

echo "build-remote script tests passed"
