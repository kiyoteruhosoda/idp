#!/usr/bin/env bash
# scripts/build.sh — ソース側でビルドする（デプロイ先とは別ホスト。ここでは起動しない）。
#
# Docker イメージ（api / web / migrate）をビルドし、tar ＋デプロイに必要な一式を
# 出力ディレクトリ（既定 dist/）へ書き出す。デプロイ先へは dist/ をディレクトリごと転送し、
# 中の deploy.sh を実行するだけでよい（レジストリ不要）。
#
# 使い方:
#   ./scripts/build.sh [出力DIR]        # 既定 dist/
#   IMAGE_TAG=1.0.0 ./scripts/build.sh  # イメージタグ指定（既定 latest）
#
# 出力（＝デプロイバンドル）:
#   idp-api.tar idp-web.tar idp-migrate.tar   ビルド済みイメージ
#   docker-compose.yml                        デプロイ用 Compose（image: 参照のみ）
#   docker/nginx.conf                         リバースプロキシ設定
#   .env.example                              設定テンプレート（deploy.sh が .env を生成）
#   deploy.sh                                 デプロイ入口（初回・更新・reset すべてこれ 1 本）
#   manifest.env manifest.sha256              照合用メタデータ
#
# 前提: docker。
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

command -v docker >/dev/null 2>&1 || die "docker が見つかりません。"

git_commit="$(git rev-parse HEAD 2>/dev/null || printf unknown)"
version="${IMAGE_TAG:-latest}"
# IMAGE_PREFIX/IMAGE_TAG は Compose（docker-compose.deploy.yml）と共通の名前解決。通常は既定のままでよい。
image_ref() { printf '%s/%s:%s' "${IMAGE_PREFIX:-idp}" "$1" "$version"; }

# --- イメージビルド --------------------------------------------------------------
# サービス名 → Dockerfile ステージ の対応。
declare -A stages=([api]=runtime-api [web]=runtime-web [migrate]=migrate)
for svc in api web migrate; do
  ref="$(image_ref "$svc")"
  log "イメージをビルドします: $ref（stage=${stages[$svc]}）..."
  docker build --target "${stages[$svc]}" \
    --label "org.opencontainers.image.revision=${git_commit}" \
    --label "org.opencontainers.image.version=${version}" \
    -t "$ref" -f Dockerfile .
done

# --- デプロイバンドル出力 --------------------------------------------------------
mkdir -p "$out_dir/docker"
manifest="$out_dir/manifest.sha256"
: >"$manifest"
printf 'commit=%s\nversion=%s\nimage_tag=%s\n' \
  "$git_commit" "$version" "$version" >"$out_dir/manifest.env"

for svc in api web migrate; do
  ref="$(image_ref "$svc")"
  out="$out_dir/idp-${svc}.tar"
  image_id="$(docker image inspect -f '{{.Id}}' "$ref")"
  log "保存します: $ref → $out ..."
  docker save "$ref" -o "$out"
  sha256sum "$out" >>"$manifest"
  printf '%s_ref=%s\n%s_image_id=%s\n' "$svc" "$ref" "$svc" "$image_id" >>"$out_dir/manifest.env"
done

cp "$repo_root/docker-compose.deploy.yml" "$out_dir/docker-compose.yml"
cp "$repo_root/docker/nginx.conf" "$out_dir/docker/nginx.conf"
cp "$repo_root/.env.example" "$out_dir/.env.example"
cp "$repo_root/scripts/deploy.sh" "$out_dir/deploy.sh"
chmod +x "$out_dir/deploy.sh"

log "完了。$out_dir/ をデプロイ先へ転送し、デプロイ先で ./deploy.sh を実行してください。"
