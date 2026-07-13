#!/usr/bin/env bash
# 互換ラッパー。新しい入口は deploy.sh app。
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$repo_root/scripts/deploy.sh" app "$@"
