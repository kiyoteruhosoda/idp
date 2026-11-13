#!/usr/bin/env bash
# scripts/build-remote-container.sh — one-host method for deployment targets without git (e.g. Synology DSM).
#
# Fetching the source and building images happen inside a "dev container" (assumed to have git and the toolchain);
# the generated dist/ is pulled from the container's workspace (a path visible from the host) into the deployment target,
# and the bundled deploy.sh is run. **No git is needed on the deployment target** (for environments where build-remote.sh's git version cannot be used).
#
# Runs 4 steps in one go (the former separate pick.sh has been merged into this script):
#   SYNC   … git pull inside the dev container (fetch the latest source)
#   BUILD  … scripts/build.sh inside the dev container (generates dist/)
#   PICK   … pull the built dist/ into the deployment target
#   DEPLOY … run the pulled deploy.sh
#
# Self-update: this script itself is a hand-placed bootstrap not included in dist/, so
# git pull does not update it. So after SYNC it byte-compares itself with the latest build-remote-container.sh
# in the dev container and, if different, replaces itself with the latest and re-runs with the same arguments (every time, not only the first).
# Note: this auto-update works only if "this script is already a self-update capable version". If an old
#   version without it is on the deployment target, replace it with the latest by hand once (automatic afterwards).
#
# Usage (on the deployment target; the mode is picked up from any argument position; default migrate):
#   ./build-remote-container.sh            # migrate
#   ./build-remote-container.sh app
#   ./build-remote-container.sh reset
#
# Configure via environment variables or the `build-remote-container.env` below.
# **Do not edit the defaults at the top of the script directly** (self-update replaces this whole file with the
# latest, so directly edited values are lost on the next run; always configure via the env file / environment variables):
#   IDP_PROJECT        project name (if omitted, taken from the deployment directory's parent; see below)
#   IDP_DEV_CONTAINER  name of the dev container that builds
#   IDP_DEV_USER       user that runs the build inside the container
#   IDP_DEV_WORKDIR    repository working dir inside the container (where scripts/build.sh lives)
#   IDP_DIST_DIR       absolute path of the built dist/ as seen from the host (required; error if unset)
#   IDP_TARGET_DIR     deployment directory (default: this script's location)
#
# The directory layout is assumed to be **/<project name>/<environment>** (e.g. /volume1/docker/idp/prod).
#   * environment (stg/prod etc.)  … taken from the deployment directory name
#   * project name                 … taken from the deployment directory's parent directory name
# Project name precedence: IDP_PROJECT > config file PROJECT > parent directory name > default idp.
# Following this layout, PROJECT need not be set. Otherwise set it explicitly via IDP_PROJECT / PROJECT.
#
# Besides the environment variables above, settings can be written in **`build-remote-container.env` next to the script**
# (KEY=VALUE format; no commands like `export` needed). `{PROJECT}` in each path expands to the resolved project value. Example:
#     IDP_DEV_CONTAINER=ubuntu-dev
#     IDP_DEV_WORKDIR=/work/project/{PROJECT}
#     IDP_DIST_DIR=/var/services/homes/kyon/.../work/project/{PROJECT}/dist
# Note: this is separate from the deployment `.env` (the secrets file read by deploy.sh / Compose). Writing here has no effect there.
#
# Requires: docker (on the deployment target) and a running dev container for building.
set -euo pipefail

# ---- Load the (optional) config file: <next to the script>/build-remote-container.env -----
# Safely imports only KEY=VALUE lines (no source/eval). Already-set environment variables take precedence;
# only unset ones are filled from the config file. Leading-# comments, blank lines and invalid keys are ignored; values have
# surrounding whitespace and inline comments after whitespace (` # ...`) removed (a `#` not preceded by whitespace is kept).
_config_file="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/build-remote-container.env"
_config_loaded_keys=()   # keys actually imported from the config file (for the startup info display)
if [[ -f "$_config_file" ]]; then
  while IFS= read -r _line || [[ -n "$_line" ]]; do
    _line="${_line%$'\r'}"
    [[ "$_line" =~ ^[[:space:]]*# ]] && continue
    [[ "$_line" == *=* ]] || continue
    _key="${_line%%=*}"
    _val="${_line#*=}"
    _key="${_key//[[:space:]]/}"
    _val="${_val%%[[:space:]]#*}"                 # remove inline comments after whitespace+#
    _val="${_val#"${_val%%[![:space:]]*}"}"       # remove leading whitespace
    _val="${_val%"${_val##*[![:space:]]}"}"       # remove trailing whitespace
    [[ "$_key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
    if [[ -z "${!_key:-}" ]]; then
      export "$_key=$_val"
      _config_loaded_keys+=("$_key")
    fi
  done <"$_config_file"
fi

log() { printf '[idp:container] %s\n' "$*" >&2; }
die() { printf '[idp:container][error] %s\n' "$*" >&2; exit 1; }

# ---- Settle the target directory and our own path first ---------------------------
# The expected layout is /<project name>/<environment> (e.g. /volume1/docker/idp/prod).
# The environment comes from the target directory name, the project name from its parent directory name (below).
target_dir="${IDP_TARGET_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
# So the parent can be derived correctly even from relative or non-normalized paths (e.g. IDP_TARGET_DIR=stg or a trailing /.),
# resolve to an absolute, normalized path before taking the parent (cd folds . / ..). Explicit error if it does not exist.
target_dir="$(cd "$target_dir" 2>/dev/null && pwd)" \
  || die "IDP_TARGET_DIR directory does not exist: ${IDP_TARGET_DIR:-(script location)}"
# Self-update replaces ourselves, so settle the absolute path once here (before the cd).
# Re-resolving a relative BASH_SOURCE[0] after cd "$target_dir" would point to another directory
# (e.g. started as ./stg/build-remote-container.sh, after cd into target_dir ./stg would be expanded twice).
self_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"

# ---- Defaults (override with the config file build-remote-container.env / environment variables) ---------
# Do not edit the defaults here directly (self-update replaces this file, so edits are lost;
# give environment-specific settings via build-remote-container.env or environment variables).
# Settle the project name once. Precedence: environment variable IDP_PROJECT > config file PROJECT >
# the target directory's parent directory name (assuming /<project name>/<environment>) > default idp.
_project_from_dir="$(basename "$(dirname "$target_dir")")"
case "$_project_from_dir" in '' | '/' | '.' | '..') _project_from_dir='' ;; esac
project="${IDP_PROJECT:-${PROJECT:-${_project_from_dir:-idp}}}"
# Where the project name came from (shown in the startup log so "why this value" is clear).
if   [[ -n "${IDP_PROJECT:-}" ]]; then project_source="environment variable IDP_PROJECT"
elif [[ -n "${PROJECT:-}"     ]]; then project_source="config file PROJECT"
elif [[ -n "$_project_from_dir" ]]; then project_source="directory (parent of $target_dir)"
else                                    project_source="default"
fi
dev_container="${IDP_DEV_CONTAINER:-ubuntu-dev}"
dev_user="${IDP_DEV_USER:-sshuser}"
dev_workdir="${IDP_DEV_WORKDIR:-/work/project/$project}"
dist_dir="${IDP_DIST_DIR:-}"

# Expand {PROJECT} in paths to the project value (single source for the project name).
# In the replacement string, bash 5.2's patsub_replacement treats `&` (the whole match) and `\`
# specially, so escape both before inserting the project value literally.
_project_repl="${project//\\/\\\\}"
_project_repl="${_project_repl//&/\\&}"
dev_workdir="${dev_workdir//\{PROJECT\}/$_project_repl}"
dist_dir="${dist_dir//\{PROJECT\}/$_project_repl}"

# The mode is picked up wherever it is in the arguments (works even with extra words before it). Default migrate.
mode=migrate
for arg in "$@"; do
  case "$arg" in app | migrate | reset) mode="$arg" ;; esac
done

# Classify the deployment environment from the target directory name (stg / prod / other). Shared source for display and
# for choosing the default image tag on first run (so the same classification is not written in two places).
classify_target_env() {
  case "$(basename "$target_dir")" in
    stg | staging | *-stg | *-staging) printf 'stg\n' ;;
    prod | production | *-prod | *-production) printf 'prod\n' ;;
    *) printf 'other\n' ;;
  esac
}
env_class="$(classify_target_env)"
# Environment label for display. stg/prod as is; anything else shows the directory name as is.
case "$env_class" in
  stg | prod) environment="$env_class" ;;
  *) environment="$(basename "$target_dir")" ;;
esac

# ---- Startup info (shows which environment, which mode, which settings were loaded and how they were resolved) ----
log "══════════════════════════════════════════════"
log "  Environment (ENV) : $environment"
log "  Mode              : $mode"
log "  project    : $project"
log "══════════════════════════════════════════════"
log "  Arguments   : $([[ $# -gt 0 ]] && printf '%q ' "$@" || printf '(none -> default %s)' "$mode")"
if [[ -f "$_config_file" ]]; then
  if [[ ${#_config_loaded_keys[@]} -gt 0 ]]; then
    log "  Config file : $_config_file (loaded: ${_config_loaded_keys[*]})"
  else
    log "  Config file : $_config_file (no keys imported = environment variables take precedence for all)"
  fi
else
  log "  Config file : none ($_config_file absent; environment variables and defaults only)"
fi
log "  Resolved settings:"
log "    PROJECT           = $project (source: $project_source)"
log "    IDP_DEV_CONTAINER = $dev_container"
log "    IDP_DEV_USER      = $dev_user"
log "    IDP_DEV_WORKDIR   = $dev_workdir"
log "    IDP_DIST_DIR      = ${dist_dir:-(unset)}"
log "    IDP_TARGET_DIR    = $target_dir (environment=$environment)"

command -v docker >/dev/null 2>&1 || die "docker not found."
[[ -n "$dist_dir" ]] || die "set IDP_DIST_DIR (absolute path of the built dist/ as seen from the host)."

cd "$target_dir"

# Carry the deployment target .env's image settings (IMAGE_TAG / IMAGE_PREFIX) into the build. Without aligning them
# build.sh builds with the defaults (idp/*:latest) while docker-compose.deploy.yml requires the .env's tag, and
# startup fails with an image mismatch (supports stg/prod tags and custom prefixes). Explicit environment variables
# take precedence; otherwise read from the existing .env (on first run .env is not generated yet, so defaults).
read_env_value() {
  local key="$1"
  [[ -f "$target_dir/.env" ]] || return 0
  # Returns empty if the key is missing. `|| true` so grep's no-match (1) does not abort under set -o pipefail.
  { grep -E "^${key}=" "$target_dir/.env" | tail -n1 | cut -d= -f2- | tr -d '\r'; } || true
}
# Decide the default image tag for the first run (no .env yet) from the deployment environment. For stg/prod directories, match
# the build tag with the IMAGE_TAG (stg/prod) that deploy.sh generates from .env.<env>.example, preventing "built as latest ->
# .env requires stg -> image mismatch". Other environments use latest. Reuses env_class for the classification.
image_tag="${IMAGE_TAG:-$(read_env_value IMAGE_TAG)}"
image_prefix="${IMAGE_PREFIX:-$(read_env_value IMAGE_PREFIX)}"
if [[ -z "$image_tag" ]]; then
  case "$env_class" in
    stg | prod) image_tag="$env_class" ;;
    *) image_tag=latest ;;
  esac
fi
image_prefix="${image_prefix:-idp}"

# --- SYNC (only git pull inside the dev container first; build.sh is not run yet) -------
# Fetching the latest source before self-update (below) lets us then take the latest
# build-remote-container.sh out of the dev container and compare it with ourselves.
log "SYNC   git pull in dev container '$dev_container' ($dev_workdir)..."
docker exec -u "$dev_user" "$dev_container" bash -lc "
  set -e
  cd '$dev_workdir'
  git pull --ff-only
" || die "git pull inside the dev container failed."

# --- SELF-UPDATE (if this script is stale, replace it with the latest and re-run; every time, not only the first) ---
# build-remote-container.sh on the deployment target is a "hand-placed bootstrap" not included in dist/, so
# git pull does not update it. Compare byte by byte with the latest in the dev container here and, if different,
# replace ourselves with the latest and re-run with the same arguments. IDP_SELF_UPDATED limits re-runs to one,
# preventing infinite loops (after re-running, git pull is a no-op and self-update is skipped, going straight to BUILD).
if [[ "${IDP_SELF_UPDATED:-0}" != "1" ]]; then
  if _self_tmp="$(mktemp "$(dirname "$self_path")/.build-remote-container.XXXXXX" 2>/dev/null)"; then
    if docker exec -u "$dev_user" "$dev_container" \
          bash -lc "cat '$dev_workdir/scripts/build-remote-container.sh'" >"$_self_tmp" 2>/dev/null \
        && [[ -s "$_self_tmp" ]] && ! cmp -s "$_self_tmp" "$self_path"; then
      log "SELF-UPDATE  build-remote-container.sh has been updated. Replacing with the latest and re-running."
      # mktemp creates with 0600, so after replacement other users or another automation account could not run it.
      # Inherit the existing script's permissions (if unavailable, explicitly grant 0755 needed for execution).
      chmod --reference="$self_path" "$_self_tmp" 2>/dev/null \
        || chmod "$(stat -c '%a' "$self_path" 2>/dev/null || echo 755)" "$_self_tmp" 2>/dev/null \
        || chmod 0755 "$_self_tmp"
      # Replace atomically by rename within the same directory (the running process's fd keeps the old inode, and
      # the following exec reopens the new inode via the path, so the running script is not corrupted).
      mv -f "$_self_tmp" "$self_path"
      export IDP_SELF_UPDATED=1
      exec "$self_path" "$@"
    fi
    rm -f "$_self_tmp"
  else
    log "SELF-UPDATE  skipped because a temp file could not be created (check write permission on $self_path's directory)."
  fi
fi

# --- BUILD (build.sh inside the dev container; git pull already done in SYNC) ---------------------
log "BUILD  building in dev container '$dev_container' ($dev_workdir, image=${image_prefix}/*:${image_tag})..."
docker exec \
  -e IMAGE_TAG="$image_tag" -e IMAGE_PREFIX="$image_prefix" \
  -u "$dev_user" "$dev_container" bash -lc "
  set -e
  cd '$dev_workdir'
  ./scripts/build.sh
" || die "build inside the container failed."

# --- PICK (pull the built dist into the deployment target; equivalent to the old pick.sh) --------------
log "PICK   $dist_dir → $target_dir"
[[ -d "$dist_dir" ]] || die "dist not found: $dist_dir (check build.sh's output dir or IDP_DIST_DIR)."
# Never break the deployment target's .env when pulling (preserve secrets). Even if a .env sneaks into dist,
# back it up before copying and restore it afterwards so it is not overwritten (.env is managed solely by deploy.sh).
env_backup=""
if [[ -f "$target_dir/.env" ]]; then
  env_backup="$(mktemp)"
  cp -a "$target_dir/.env" "$env_backup"
fi
cp -a "$dist_dir/." "$target_dir/"
if [[ -n "$env_backup" ]]; then
  mv -f "$env_backup" "$target_dir/.env"
fi
[[ -f "$target_dir/deploy.sh" ]] || die "deploy.sh was not pulled in (check build.sh's output)."
chmod +x "$target_dir"/*.sh 2>/dev/null || true

# --- DEPLOY (.env is managed by deploy.sh: generated on first run, afterwards only missing keys appended, secrets unchanged) ----
log "DEPLOY ./deploy.sh $mode"
"$target_dir/deploy.sh" "$mode"

log "END    environment=$environment  mode=$mode (done)"
