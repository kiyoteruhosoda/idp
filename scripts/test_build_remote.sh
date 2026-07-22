#!/usr/bin/env bash
# scripts/test_build_remote.sh — build-remote.sh の取得・自己更新・ビルド/デプロイ委譲を検証する（CI 用）。
# git は実物を使い（ローカルの origin リポジトリを clone）、build.sh / deploy.sh / docker はスタブに差し替える。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.com
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.com

# --- origin リポジトリ（build-remote.sh の「最新版」＋ build.sh スタブを含む） ---------
origin="$TMP/origin"
mkdir -p "$origin/scripts"
cp "$ROOT/scripts/build-remote.sh" "$origin/scripts/build-remote.sh"
chmod +x "$origin/scripts/build-remote.sh"

# build.sh スタブ: dist/deploy.sh（スタブ）を生成し、呼び出しを記録する。
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

# --- docker スタブ（build-remote.sh の存在チェックを満たすだけ） -----------------------
mkdir -p "$TMP/bin"
cat >"$TMP/bin/docker" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
chmod +x "$TMP/bin/docker"
export PATH="$TMP/bin:$PATH"

# --- デプロイ先ホスト: build-remote.sh の「旧版」を 1 本だけ配置する ---------------------
host="$TMP/host"
mkdir -p "$host"
cp "$ROOT/scripts/build-remote.sh" "$host/build-remote.sh"
printf '# stale local copy marker\n' >>"$host/build-remote.sh"  # origin と差分を作り自己更新を誘発
chmod +x "$host/build-remote.sh"

export BUILD_REMOTE_TEST_LOG="$TMP/calls.log"
export IDP_REPO_URL="$origin"
export IDP_SRC_DIR="$host/src"
export IMAGE_TAG="test-tag"

# --- 1) 初回: clone → 自己更新（旧版≠最新版）→ build → deploy app --------------------
: >"$BUILD_REMOTE_TEST_LOG"
"$host/build-remote.sh" app >"$TMP/run1.out" 2>&1 || { echo "初回実行に失敗しました" >&2; cat "$TMP/run1.out" >&2; exit 1; }

[[ -d "$host/src/.git" ]] || { echo "ソースが clone されていません" >&2; exit 1; }
grep -q '自身を更新して再実行します' "$TMP/run1.out" || { echo "自己更新が行われていません" >&2; cat "$TMP/run1.out" >&2; exit 1; }
cmp -s "$host/build-remote.sh" "$host/src/scripts/build-remote.sh" \
  || { echo "自己更新後もローカルコピーが最新版と一致していません" >&2; exit 1; }
grep -q 'BUILD-STUB tag=test-tag' "$BUILD_REMOTE_TEST_LOG" || { echo "build.sh が IMAGE_TAG 付きで呼ばれていません" >&2; cat "$BUILD_REMOTE_TEST_LOG" >&2; exit 1; }
grep -q 'DEPLOY-STUB mode=app' "$BUILD_REMOTE_TEST_LOG" || { echo "deploy.sh が app で呼ばれていません" >&2; cat "$BUILD_REMOTE_TEST_LOG" >&2; exit 1; }
# 自己更新は 1 回だけ（無限ループしない）。
[[ "$(grep -c 'BUILD-STUB' "$BUILD_REMOTE_TEST_LOG")" -eq 1 ]] || { echo "build が複数回実行されました（再実行ループの疑い）" >&2; exit 1; }

# --- 2) 2 回目: 既に最新版なので自己更新なし。既存 clone を fetch し migrate を委譲 --------
: >"$BUILD_REMOTE_TEST_LOG"
"$host/build-remote.sh" migrate >"$TMP/run2.out" 2>&1 || { echo "2 回目の実行に失敗しました" >&2; cat "$TMP/run2.out" >&2; exit 1; }
if grep -q '自身を更新して再実行します' "$TMP/run2.out"; then
  echo "最新版なのに自己更新が走りました" >&2; exit 1
fi
grep -q 'ソースを更新します' "$TMP/run2.out" || { echo "既存 clone の更新（fetch）が行われていません" >&2; cat "$TMP/run2.out" >&2; exit 1; }
grep -q 'DEPLOY-STUB mode=migrate' "$BUILD_REMOTE_TEST_LOG" || { echo "deploy.sh が migrate で呼ばれていません" >&2; exit 1; }

# --- 3) IDP_REPO_URL 変更に追従（既存 clone の origin を差し替えて取得する） -------------
origin2="$TMP/origin2"
cp -a "$origin" "$origin2"
printf 'origin2\n' >"$origin2/MARKER"
git -C "$origin2" add -A
git -C "$origin2" commit -qm "origin2 marker"
: >"$BUILD_REMOTE_TEST_LOG"
IDP_REPO_URL="$origin2" "$host/build-remote.sh" app >"$TMP/run3.out" 2>&1 \
  || { echo "IDP_REPO_URL 変更後の実行に失敗しました" >&2; cat "$TMP/run3.out" >&2; exit 1; }
[[ -f "$host/src/MARKER" ]] || { echo "origin 差し替えが反映されていません（新リポジトリから取得できていない）" >&2; exit 1; }

# --- 4) 既存の空ディレクトリへは clone できる（非空・非 git のときだけ拒否） -----------------
host2="$TMP/host2"
mkdir -p "$host2/src"   # 事前に空の取得先が用意されているケース
cp "$ROOT/scripts/build-remote.sh" "$host2/build-remote.sh"
chmod +x "$host2/build-remote.sh"
: >"$BUILD_REMOTE_TEST_LOG"
IDP_SRC_DIR="$host2/src" "$host2/build-remote.sh" app >"$TMP/run4.out" 2>&1 \
  || { echo "空ディレクトリへの clone に失敗しました" >&2; cat "$TMP/run4.out" >&2; exit 1; }
[[ -d "$host2/src/.git" ]] || { echo "空ディレクトリへ clone されていません" >&2; exit 1; }

# 非空かつ非 git の取得先は拒否する。
host3="$TMP/host3"
mkdir -p "$host3/src"
touch "$host3/src/stray-file"
cp "$ROOT/scripts/build-remote.sh" "$host3/build-remote.sh"
chmod +x "$host3/build-remote.sh"
if IDP_SRC_DIR="$host3/src" "$host3/build-remote.sh" app >"$TMP/run5.out" 2>&1; then
  echo "非空・非 git の取得先は拒否すべきです" >&2; exit 1
fi
grep -q '空でもありません' "$TMP/run5.out" || { echo "非空取得先のエラーメッセージがありません" >&2; cat "$TMP/run5.out" >&2; exit 1; }

# --- 5) 不明モードは失敗する ------------------------------------------------------------
if "$host/build-remote.sh" bogus >"$TMP/run6.out" 2>&1; then
  echo "不明モードは失敗すべきです" >&2; exit 1
fi
grep -q '不明なモード' "$TMP/run6.out" || { echo "不明モードのエラーメッセージがありません" >&2; exit 1; }

echo "build-remote script tests passed"
