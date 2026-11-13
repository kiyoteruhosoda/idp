#!/usr/bin/env bash
# scripts/build-remote.sh — on the deployment target (remote), runs "fetch -> self-update -> build -> deploy" end to end.
#
# Unlike the two-host method (build.sh -> dist/ on the build side, transferred to the deployment target), this script
# provides a **one-host method completed on the deployment target alone**. Only this one
# build-remote.sh needs to be placed on the deployment target at first. The source is fetched from git, so no dist/ transfer is needed.
# Even if the script itself is updated later, at run time it rewrites itself to the latest version in git and re-runs (self-update).
#
# Usage (on the deployment target; the mode is passed to deploy.sh as is; default app):
#   ./build-remote.sh            # app: fetch -> build -> deploy.sh app (initial setup and updates alike)
#   ./build-remote.sh migrate    # migrate: fetch -> build -> deploy.sh migrate
#   ./build-remote.sh reset      # reset: fetch -> build -> deploy.sh reset (destructive)
#
# Settings (environment variables; works with the defaults):
#   IDP_REPO_URL   git URL to fetch from   (default https://github.com/kiyoteruhosoda/idp.git)
#   IDP_BRANCH     branch to fetch         (default main)
#   IDP_SRC_DIR    source checkout DIR     (default <this script's location>/src)
#   IMAGE_TAG      image tag               (passed on to build.sh / deploy; default latest)
#
# Requires: git, docker (Compose v2 or v1), openssl.
set -euo pipefail

log() { printf '[idp:build-remote] %s\n' "$*" >&2; }
die() { printf '[idp:build-remote][error] %s\n' "$*" >&2; exit 1; }

# --- Resolve our canonical path and the source checkout location ------------------------------------------
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
  *) die "unknown mode: $mode (one of app / migrate / reset)" ;;
esac

command -v git >/dev/null 2>&1 || die "git not found."
command -v docker >/dev/null 2>&1 || die "docker not found."

# --- Fetch the source (clone / update) -------------------------------------------------
fetch_source() {
  if [[ -d "$src_dir/.git" ]]; then
    log "updating source: $src_dir (branch=$branch)"
    # Follow changes to IDP_REPO_URL (switching from a fork/mirror to the production repository etc.). Align the URL
    # before fetching so an existing clone does not keep using an old origin and deploy from the wrong repository.
    if git -C "$src_dir" remote get-url origin >/dev/null 2>&1; then
      git -C "$src_dir" remote set-url origin "$repo_url"
    else
      git -C "$src_dir" remote add origin "$repo_url"
    fi
    git -C "$src_dir" fetch --depth 1 origin "$branch"
    git -C "$src_dir" reset --hard FETCH_HEAD
  else
    # Even an existing directory can be git-cloned into if empty. Refuse only when non-empty and not git.
    if [[ -e "$src_dir" && -n "$(ls -A "$src_dir" 2>/dev/null)" ]]; then
      die "$src_dir is not a git repository and not empty either. Check IDP_SRC_DIR or specify an empty directory."
    fi
    log "fetching source: $repo_url -> $src_dir (branch=$branch)"
    git clone --depth 1 --branch "$branch" "$repo_url" "$src_dir"
  fi
}

# --- Self-update (rewrite ourselves and re-run if different from the repository's build-remote.sh) ----
self_update_and_reexec() {
  [[ -f "$repo_script" ]] || die "$repo_script not found (the repository layout is not as expected)."
  # When running the same file (run directly from inside the source checkout), there is nothing to update.
  [[ "$(resolve_path "$repo_script")" == "$self" ]] && return 0
  if cmp -s "$repo_script" "$self"; then
    return 0
  fi
  log "build-remote.sh differs from the latest in the repository; updating ourselves and re-running."
  cp -f "$repo_script" "$self"
  chmod +x "$self"
  export IDP_BUILD_REMOTE_UPDATED=1
  exec "$self" "$mode"
}

# Fetch and self-update only the first time (after re-running, IDP_BUILD_REMOTE_UPDATED=1 skips them to avoid fetching twice).
if [[ "${IDP_BUILD_REMOTE_UPDATED:-0}" != 1 ]]; then
  fetch_source
  self_update_and_reexec
fi

# --- Build -> deploy ----------------------------------------------------------
[[ -x "$src_dir/scripts/build.sh" ]] || die "$src_dir/scripts/build.sh not found."
log "building images (build.sh)..."
IMAGE_TAG="${IMAGE_TAG:-latest}" "$src_dir/scripts/build.sh"

deploy_script="$src_dir/dist/deploy.sh"
[[ -x "$deploy_script" ]] || die "$deploy_script not found (check build.sh's output)."
log "deploying (deploy.sh $mode)..."
"$deploy_script" "$mode"

log "done (mode: $mode)."
