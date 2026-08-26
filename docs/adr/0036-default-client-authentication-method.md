# ADR-0036: クライアント認証方式の既定を private_key_jwt にする

- Status: Accepted
- Date: 2026-08-26
- 関連: `docs/adr/0030-machine-authentication-private-key-jwt.md`、`docs/adr/0032-client-usage-drives-the-registration-form.md`

## 背景

ADR-0030 で `private_key_jwt`（RFC 7523）を実装し、管理コンソールの登録フォームでは推奨として
先頭・初期選択に置いた。一方 `POST /{tenant_id}/admin/clients` は、`token_endpoint_auth_method` を
**省略したとき** `client_secret_basic` を採っていた。

これは OIDC Dynamic Client Registration 1.0 §2（および RFC 7591 §2）が定める既定値そのままである。
つまり「画面から作ると公開鍵方式、API から何も書かずに作ると共有秘密方式」という食い違いが、
同じ IdP の中に 2 つの既定として並んでいた。

## 決定

### 1. 省略時の既定を `private_key_jwt` に揃える

**既定は、選ぶ人が何も考えなかったときに置かれる値である。** そこには弱いほうではなく強いほうを
置く。`client_secret_basic` の共有秘密は IdP 側の DB にも、呼び出し元の設定ファイルにも保存され、
要求のたびにネットワークを流れる。`private_key_jwt` では秘密は呼び出し元にしか存在しない
（ADR-0030）。弱いほうを選ぶ判断は、明示的に書いたときにだけ成立させる。

FAPI 2.0 Security Profile がクライアント認証を `private_key_jwt` か mTLS に限っているとおり、
共有秘密を既定から外す方向は業界の流れとも一致する。

### 2. 仕様の既定から意図的に外れることを認める

規格の既定値を変えるので、`token_endpoint_auth_method` を書かない既存の呼び出しは挙動が変わる。
それでもこちらを採るのは、**規格の既定は 2012 年（RFC 6749）当時の互換性を背負った値**であり、
本 IdP が新規に登録を受け付ける相手に対して守るべき互換性ではないからである。省略した登録は
黙って別の方式になるのではなく、後述の 400 で止まるので、気付かないまま弱い方式になることはない。

破壊的変更であることは `docs/CHANGELOG.md` に記す。

### 3. 方式も検証鍵も無い登録は、専用のメッセージで 400 にする

`private_key_jwt` は検証鍵（`jwks`）が要る。省略時の既定がこれになると、方式も鍵も書かない登録は
`api-client-jwks-required`（「private_key_jwt 認証には JWK Set が必要です」）で落ちる。しかし
`private_key_jwt` と**書いた覚えの無い**呼び出し元には、この文面では理由が伝わらない。

そこで「方式も鍵も無い」場合だけ `api-client-auth-method-unspecified` を返し、既定が何であるかと、
取れる手が 2 つ（鍵を登録する／方式を明示する）あることを本文に含める。

### 4. `PATCH` の省略時は従来どおり「変更しない」

更新で省略された項目は「変更しない」であって「既定に戻す」ではない。ここは変えない。既定が関わるのは
新規登録だけである。

## 影響

- `POST /{tenant_id}/admin/clients` で `token_endpoint_auth_method` を書かず `jwks` も送らない
  呼び出しは 400 になる。共有秘密のクライアントを作るには
  `"token_endpoint_auth_method": "client_secret_basic"` を明示する。
- 管理コンソールのフォームは常にこの項目を送るため、画面の挙動は変わらない。
- 入力エラーでフォームを描き直すときの既定（`auth_method_or_default`）も `private_key_jwt` に揃えた。
  画面の初期選択・api の省略時・再描画の 3 か所が同じ値を指す。

## 代替案

- **api の既定を `client_secret_basic` のまま、画面だけ推奨を出す。** 規格どおりで破壊的変更も無いが、
  「同じ IdP に 2 つの既定がある」状態が残る。どちらが本当の既定かは、登録経路を知らないと分からない。
- **省略時は方式を決めず必須項目にする。** 曖昧さは消えるが、`redirect_uris` を省略できるようにした
  ADR-0032 と逆向きで、「書かなくてよいものは書かせない」という登録 API の性格に合わない。
