# ADR-0081: crypto-glue を手直しした写しで rsa 0.10.0 へ上げる

- Status: Accepted
- Date: 2026-11-18
- 関連: task #1016（依存の弱点の検査）、ADR-0080

## 背景

rsa 0.10.0-rc.19 に RUSTSEC-2023-0071（Marvin attack: 秘密鍵の計算の時間差から鍵を推測される）がある。直った版は
rsa 0.10.0（2026-11-08）。idp では rsa は webauthn-rs 0.6 → webauthn-rs-core / webauthn-attestation-ca →
crypto-glue 0.2.2 の奥にだけあり、パスキーの署名の確かめ（公開鍵）に使われる。idp 自身の署名は aws-lc-rs。

crypto-glue の最新 0.2.2 は rsa を `^0.10.0-rc.18` と `features = ["sha2"]` で求める。0.10.0 は `sha2` の feature を
無くした（SHA-2 は常に入る）ので、lock を 0.10.0 へ動かせない。上流がいつ追随するかは分からない。

## 決定

1. crypto-glue 0.2.2 の公開版をそのまま `vendor/crypto-glue/` に写し、`Cargo.toml` の rsa の行だけを
   `version = "0.10"`・`features = ["pkcs1v15"]` に直す（PKCS#1 v1.5 の署名は 0.10.0 から opt-in）。
   ワークスペースの `[patch.crates-io]` で差し替える。`vendor/` はワークスペースの member から外す（`exclude`）
2. Docker の組み立ては依存のビルドの前に `vendor/` を写す
3. crypto-glue の新しい版が rsa 0.10 を受け付けたら、`vendor/crypto-glue/` と patch を消す

## 理由

- 例外（見直す日つき）にしても、上流が動かない限り見直す日ごとに同じ判断が残る。直した版が出ているので、
  中継ぎの 1 行を直せば弱点そのものが消える
- 中継ぎの写しはソースの変更が無く、差分は依存の指定 1 行だけ。上流を追うときの手間が小さい

## 影響

- crypto-glue の上流の修正は自動では入らない。Renovate は path の依存を上げないので、上流の新しい版は
  手で見に行く（`vendor/crypto-glue/PATCHED.md` に外す条件を書いた）
- crypto-glue は MPL-2.0。写しは手を入れたファイル（`Cargo.toml`）を含めてソースのままリポジトリにある
