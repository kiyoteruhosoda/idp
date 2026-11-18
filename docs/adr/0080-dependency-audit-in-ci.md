# ADR-0080: 依存の弱点を CI で調べる（Cargo.lock と画面の npm）

- Status: Accepted
- Date: 2026-11-18
- 関連: task #1016（親 #1012「依存の弱点が公表されたら main の CI が赤くなる」）、deploy-repo ADR-0002（型）・ADR-0003（npm の 2 段）

## 背景

kyon/* のリポジトリすべてに、lock した依存の弱点の検査（`.forgejo/workflows/security-audit.yml`）を置くことになった
（deploy-repo ADR-0002）。idp は Cargo.lock と `crates/web/frontend/package-lock.json` の 2 つを持つ。

置こうとした時点（11/15）で Cargo.lock に 2 件があった。

- **libsqlite3-sys 0.37.0**（RUSTSEC-2026-0459、C の SQLite の弱点）。idp は sqlx の `mysql` だけを使い、SQLite は
  組み込まれない（`cargo tree -i libsqlite3-sys` は空）。それでも sqlx-macros-core の弱い feature（`sqlx-sqlite?/…`）のために
  lock には載る。osv-scanner は lock を全部読むので赤になる。当時の sqlx-sqlite 0.9.0 は `libsqlite3-sys <0.38` で縛っていた
- **basic-toml 0.1.10**（RUSTSEC-2026-0374「保守されていない」。直る版なし）。askama の既定の feature `config` が
  `askama.toml` を読むために引き込む

## 決定

1. `security-audit.yml` を ADR-0002 の型で置く。Rust は osv-scanner で Cargo.lock、npm は ADR-0003 の 2 段
   （`--omit=dev` の high 以上で止め、全部は知らせるだけ）
2. **例外は作らず、2 件とも lock から消す。**
   - sqlx を 0.9.1 へ（同じ `0.9` の範囲。sqlx-sqlite 0.9.1 が `<0.41` を許す）、libsqlite3-sys は 0.40.0
   - askama の既定の feature から `config` だけを外す（`derive`・`std`・`urlencode` は残す）。idp に `askama.toml` は無く、
     テンプレートは既定の `templates/` に置いているので、描画は変わらない。basic-toml と glob が lock から消える
3. 画面の npm は、ビルドの道具（vite・@vitejs/plugin-react・typescript）を `devDependencies` へ移す。利用者に届くのは
   `crates/web/assets/react` に束ねられる react・react-dom だけ。ビルドは手で `npm run build` するもので、CI と像の
   組み立ては npm を使わない

## 理由

- 例外（`osv-scanner.toml`）は見直す日が来るたびに判断が要る。上の部品の新しい版と、使っていない feature を外すことで
  直せるなら、そのほうが後に何も残らない
- 道具を `dependencies` に書いたままだと、`--omit=dev` の止める段に道具の奥の弱点（vite の中の picomatch など）が入り、
  利用者に届かないもので main が赤くなる

## 影響

- 弱点が公表されれば main が赤くなり、ci-fixer（task #995）が直しに行く
- askama で `askama.toml` を使いたくなったら、`config` を戻し、basic-toml の扱いをそのとき決める
- 画面の部品を足すとき、ブラウザに届くものは `dependencies`、ビルドだけで使うものは `devDependencies` に書く
