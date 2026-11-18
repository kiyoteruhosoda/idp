# ADR-0082: 日時の部品を chrono から time へ置き換える

- Status: Accepted
- Date: 2026-11-18
- 関連: task #1016（依存の弱点の検査）、ADR-0080、ADR-0081

## 背景

chrono に RUSTSEC-2026-0543（保守されなくなった。直る版なし）が出た。idp は約 190 ファイルで chrono を使っていた
（日時の型・DB の DATETIME の読み書き・トークンの期限・API の応答の文字）。

置き換えても、パスキーの部品（webauthn-rs → serde_with）が chrono を「あれば使う」形（任意の依存と弱い feature
`chrono_0_4?/alloc`）で名指ししているため、chrono は Cargo.lock に残る（組み込まれはしない）。弱点の検査は
Cargo.lock を読むので、それだけでは赤が消えない。

持ち主の決定（11/18）: この課題で time へ置き換え、serde_with も手直しして Cargo.lock からも消す。

## 決定

1. 日時は `time::OffsetDateTime`（UTC）、期間は `time::Duration`。sqlx・utoipa は `time` の feature を使う
2. DB の `DATETIME(6)` は今までどおり UTC の壁時計で書き読みする（`UtcInstant::naive_utc` / `from_naive_utc`。
   chrono の `naive_utc()` / `Utc.from_utc_datetime()` と同じ形）
3. **外へ出す文字の形は 1 文字も変えない。** `assay_contracts::utc` が chrono の形を作る:
   `to_rfc3339()`（`+00:00`・小数は 0/3/6/9 桁）、`to_rfc3339_seconds_z()`（秒まで・`Z`）、`to_rfc3339_micros_z()`、
   serde の `serde_rfc3339`（`Z`・小数 0/3/6/9 桁）。読むほうは `parse_rfc3339`（どのオフセットでも UTC に直す）
4. **time の `serde` feature は有効にしない。** JSON に書き出す日時の欄は `#[serde(with = "...serde_rfc3339")]` を
   書かないとコンパイルが通らない。書き忘れて黙って JSON の形（time の既定は配列）が変わる事故を防ぐ
5. serde_with 3.24.0 の公開版を `vendor/serde_with/` に写し、`Cargo.toml` から chrono の任意の依存と弱い feature を
   外して `[patch.crates-io]` で使う（`vendor/serde_with/PATCHED.md`）。ソースは変えない

## 理由

- 保守されない部品を、認証の期限の計算や DB の読み書きに使い続けない
- 文字の形を変えると、API の利用者・保存した文字・試験の期待値のどれかが壊れる。形を作る所を 1 か所にまとめ、
  chrono と同じ形を単体試験で固定した
- serde_with の写しの差分は依存の指定だけで、上流を追う手間が小さい

## 影響

- 新しく日時を JSON に出すときは `assay_contracts::utc::serde_rfc3339`（`Option` は `::option`）を付ける
- `time::Duration::days` などは範囲を超えると panic する（chrono の `try_days` に当たる `Option` の口は無い）。
  利用者の入力から期間を作るときは `checked_add` など範囲を確かめる形で書く
- serde_with の上流の修正は自動では入らない（Renovate は path の依存を上げない）。chrono を名指ししなくなった版が
  出たら写しと patch を消す
