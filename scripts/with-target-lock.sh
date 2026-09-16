#!/usr/bin/env bash
# scripts/with-target-lock.sh — cargo の中間物置き場（target/）を独占してからコマンドを実行する（CI 用）。
#
#   ./scripts/with-target-lock.sh cargo test --workspace --locked
#
# ⚠ **CI は `target/` を名前付きボリュームで共有している**（`.forgejo/workflows/ci.yml`）。
#   別の PR や main のジョブと並んで走ると、片方が組んだ試験の実行ファイルや rlib を、もう片方が
#   組み直して消す・差し替える。症状は毎回違い（`could not execute process … (never executed)`、
#   `extern location … does not exist`、Doc-tests の `unresolved import`、`VersionMissing`）、
#   試験の中身はどれも ok のまま赤になる（2026-09-16 に PR #23・#24・#25 で計 5 回）。
#   ⚠ **cargo 自身のロックでは防げない。** cargo が握るのは組み立てている間だけで、組み終えた
#   試験を走らせている間に、別のジョブの cargo が同じ実行ファイルを書き換えられる。
#
# そこで「組んで、走らせ終える」までを 1 つのロックの中に入れる。ロックは target/ の中の
# ファイルに置く ——共有しているもの自体に掛けるので、ワークフローや枝が増えても同じ規則が効く。
#
# ⚠ **1 回の実行の中で、組んだものを使い切ること。** ロックは段（step）ごとに解けるので、
#   前の段が組んだ実行ファイルを次の段で当てにすると、その間に他のジョブに消される。
#   `e2e.sh` が自分で `cargo build` してから起動しているのはこのため。
set -Eeuo pipefail

if [[ $# -eq 0 ]]; then
  echo "usage: $0 <command> [args...]" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target_dir="${CARGO_TARGET_DIR:-$ROOT/target}"
mkdir -p "$target_dir"
lock="$target_dir/.ci-target.lock"

# 待つかどうかを先に見て、待つときだけ知らせる（ログで「止まっている」と見分けるため）。
# ここで取れたロックはすぐ閉じて手放し、下の flock で取り直す。間に割り込まれても待つだけで害は無い。
exec 9>"$lock"
if ! flock -n 9; then
  echo "[with-target-lock] 他のジョブが $target_dir を使っています。終わるまで待ちます" >&2
fi
exec 9>&-

# ⚠ **`-o` を外さない。** 外すとロックのファイル記述子がコマンドの子へ引き継がれ、
#   `e2e.sh` が起こした api・web のように後に残るプロセスがロックを握り続ける
#   （同じジョブの次の段が自分自身を待って時間切れになる）。
started="$(date +%s)"
exec flock -o "$lock" bash -c '
  waited=$(( $(date +%s) - $1 )); shift
  [[ $waited -eq 0 ]] || echo "[with-target-lock] ${waited} 秒待ってロックを取りました" >&2
  exec "$@"
' with-target-lock "$started" "$@"
