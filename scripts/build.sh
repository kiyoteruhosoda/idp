#!/usr/bin/env bash
# scripts/build.sh — builds on the source side (a host separate from the deployment target; nothing is started here).
#
# Builds the Docker images (api / web / migrate) and writes the tars plus everything needed for deployment
# to an output directory (default dist/). Transfer dist/ as a whole to the deployment target and
# just run the deploy.sh inside (no registry needed).
#
# Usage:
#   ./scripts/build.sh [OUTPUT_DIR]     # default dist/
#   IMAGE_TAG=1.0.0 ./scripts/build.sh  # set the image tag (default latest)
#
# Output (= deployment bundle):
#   assay-api.tar assay-web.tar assay-migrate.tar   prebuilt images
#   docker-compose.yml                        deployment Compose (image: references only)
#   docker/nginx.conf                         reverse proxy config
#   .env.example .env.staging.example .env.production.example
#                                               config templates (deploy.sh generates .env)
#   deploy.sh                                 deployment entry point (initial setup, update and reset all use this one)
#   manifest.env manifest.sha256              metadata for verification
#
# Requires: docker.
set -euo pipefail

log() { printf '[idp] %s\n' "$*" >&2; }
die() { printf '[idp][error] %s\n' "$*" >&2; exit 1; }

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

out_dir="dist"
case "${1:-}" in
  -h | --help) sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
  "") ;;
  *) out_dir="$1" ;;
esac

command -v docker >/dev/null 2>&1 || die "docker not found."

git_commit="$(git rev-parse HEAD 2>/dev/null || printf unknown)"
git_version="$(git describe --always --dirty --tags 2>/dev/null || printf unknown)"
# The build number uses CI's run number (GITHUB_RUN_NUMBER on GitHub Actions). Empty for local builds.
build_number="${IDP_BUILD_NUMBER:-${GITHUB_RUN_NUMBER:-}}"
version="${IMAGE_TAG:-latest}"
# IMAGE_PREFIX/IMAGE_TAG share name resolution with Compose (docker-compose.deploy.yml). Normally keep the defaults.
image_ref() { printf '%s/%s:%s' "${IMAGE_PREFIX:-idp}" "$1" "$version"; }

write_manifest_kv() {
  local key="$1" value="$2" quoted
  printf -v quoted '%q' "$value"
  printf '%s=%s\n' "$key" "$quoted"
}

# --- Image build ----------------------------------------------------------------
# Service name -> Dockerfile stage mapping.
declare -A stages=([api]=runtime-api [web]=runtime-web [migrate]=migrate)
for svc in api web migrate; do
  ref="$(image_ref "$svc")"
  log "building image: $ref (stage=${stages[$svc]})..."
  docker build --target "${stages[$svc]}" \
    --build-arg "IDP_GIT_VERSION=${git_version}" \
    --build-arg "IDP_BUILD_NUMBER=${build_number}" \
    --label "org.opencontainers.image.revision=${git_commit}" \
    --label "org.opencontainers.image.version=${version}" \
    -t "$ref" -f Dockerfile .
done

# --- Deployment bundle output --------------------------------------------------------
mkdir -p "$out_dir/docker"
manifest="$out_dir/manifest.sha256"
: >"$manifest"
{
  write_manifest_kv commit "$git_commit"
  write_manifest_kv git_version "$git_version"
  write_manifest_kv version "$version"
  write_manifest_kv image_tag "$version"
} >"$out_dir/manifest.env"

for svc in api web migrate; do
  ref="$(image_ref "$svc")"
  out="$out_dir/assay-${svc}.tar"
  image_id="$(docker image inspect -f '{{.Id}}' "$ref")"
  log "saving: $ref -> $out ..."
  docker save "$ref" -o "$out"
  sha256sum "$out" >>"$manifest"
  {
    write_manifest_kv "${svc}_ref" "$ref"
    write_manifest_kv "${svc}_image_id" "$image_id"
  } >>"$out_dir/manifest.env"
done

cp "$repo_root/docker-compose.deploy.yml" "$out_dir/docker-compose.yml"
cp "$repo_root/docker/nginx.conf" "$out_dir/docker/nginx.conf"
# The override set for domain-split publishing (ADR-0015). deploy.sh layers these when PUBLISH_TOPOLOGY is
# domain-split (the default; ADR-0016), so the bundle always needs them. Always included so both topologies
# can be deployed from the bundle alone.
cp "$repo_root/docker-compose.domain-split.yml" "$out_dir/docker-compose.domain-split.yml"
cp "$repo_root/docker/nginx.domain-split.conf" "$out_dir/docker/nginx.domain-split.conf"
cp "$repo_root/.env.example" "$out_dir/.env.example"
cp "$repo_root/.env.staging.example" "$out_dir/.env.staging.example"
cp "$repo_root/.env.production.example" "$out_dir/.env.production.example"
cp "$repo_root/scripts/deploy.sh" "$out_dir/deploy.sh"
chmod +x "$out_dir/deploy.sh"

log "done. Transfer $out_dir/ to the deployment target and run ./deploy.sh there."
