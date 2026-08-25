# ADR-0032: クライアントの用途を先に選ばせ、grant_types はそこから導出する

- Status: Accepted
- Date: 2026-08-25
- 関連: `docs/adr/0030-machine-authentication-private-key-jwt.md`（システムの認証）、
  `docs/OIDC_INPUT.md` §5（Authorization Code Flow）、G3・G4

## 背景

ADR-0030 で `private_key_jwt` を入れ、システム（CI・バッチ・AI エージェント）が
`client_credentials` で `/token` を叩けるようにした。ところが**そのシステムを登録できなかった**。

`register` は種別に関わらず redirect_uri を 1 つ以上要求する。

```rust
let redirect_uris = validate_redirect_uris(&cmd.redirect_uris)?;   // 無条件
if uris.is_empty() { return Err("api-client-redirect-uris-empty") }
```

ブラウザのリダイレクト先を持たない呼び出し元に、使いもしない URL を捏造させていた。
`docs/OPERATIONS.md` の手順書に `"redirect_uris": []` と書いてあったが、これは通らない
（ADR-0030 の作業時に登録経路を実際に叩いて確かめていなかった）。

さらに `grant_types_for` は常に `authorization_code` を付けていた。システム用のつもりで登録しても
認可フローの許可が残り、捏造した redirect_uri と合わせて「使わないのに開いている経路」ができる。

画面側も噛み合っていなかった。管理者が決めたいのは「何に使うクライアントか」1 つなのに、
フォームは **「redirect_uri を書く」と「client_credentials のチェックを入れる」という独立した 2 操作**
に分かれ、しかもチェックボックスは最下部にあった。**画面の一番下の操作が、一番上の入力欄が
必須かどうかを決めていた。**

## 決定

### 1. `grant_types` は登録内容から導出する値であって、独立した設定ではない

```rust
fn grant_types_for(client_type, allow_client_credentials, has_redirect_uris) -> Vec<String>
```

- `authorization_code` は **redirect_uri を持つときだけ**付ける。持たないクライアントで認可フローは
  成立しない（`/authorize` は要求された redirect_uri を登録値と突き合わせる）ので、付けても
  使えない許可が残るだけである。
- `client_credentials` は従来どおり confidential かつ明示的に許可したときだけ。

更新時も毎回引き直す。redirect_uri を消したのに `authorization_code` が残る、といった実態と
合わない組み合わせが生まれないようにするため。

### 2. redirect_uri を省略できるのはシステム用クライアントだけ

空を無条件に許すと、認可フローも `client_credentials` も使えない「何もできないクライアント」が作れてしまう。
`client_credentials` を許可した confidential クライアントに限って空を許す。

エラー文言にも逃げ道を書く（「`client_credentials` のみを使うクライアントでは省略できます」）。
**制約だけを告げて回避策を書かない検証は、利用者を手順書探しへ追いやる。**

### 3. 画面は「用途」を最初に選ばせ、以降の入力欄をそれで変える

| 用途 | redirect_uri | client_type | 送る値 |
|---|---|---|---|
| ブラウザで利用者をログインさせる | 必須 | 選ばせる | `allow_client_credentials: false` |
| システムが API を呼ぶ（利用者不在） | **欄ごと非表示** | **非表示（confidential 固定）** | `allow_client_credentials: true`・`redirect_uris: []` |

用途は 2 つだけで、1 つのクライアントに両方を持たせる選択肢は置かない。用途ごとに分けたほうが、
事故時の失効範囲と監査の粒度を分離できる。

**api も両立を拒否する。** 画面が 2 択なのに api が 3 状態（ログインのみ／システムのみ／両方）を
作れると、api で作った「両方」のクライアントをコンソールで開いて保存しただけで片方が黙って
消える。表せない状態を作らせないことで、用途は登録内容から一意に決まる。

用途は **api のモデルには無い**。api は `redirect_uris` の有無と `client_credentials` の可否という
2 値を持ち、web がその 2 値へ翻訳する。1 つの決定を 2 つの入力に分けて見せないための、
画面側の語彙である。

システム用で `client_type` を隠すのは、confidential 以外あり得ないため（public は秘密を秘匿できず、
`client_credentials` も `private_key_jwt` も成立しない）。**選べないものを見せない。**

検証鍵（JWKS）も `private_key_jwt` を選んだときだけ出す。他の方式で送れば api が拒否するので、
出しておくと必ず失敗する入力欄になる。

## 影響

- **システム用クライアントを redirect_uri なしで登録できるようになった。** 手順書の
  `"redirect_uris": []` が実際に動く。
- **システム用クライアントの `grant_types` から `authorization_code` が消える。** `/authorize` は
  この種のクライアントを明示的に拒否する（`authorize.rs` の既存判定）。
- 既存クライアントの `grant_types` は変わらない。redirect_uri を持つものは
  `authorization_code` を持ち続ける。
- コンソールのフォームで `allow_client_credentials` チェックボックスが `usage` select に変わった。
  入力欄の出し分けは自オリジンの `client-form.js` で行う（CSP が `script-src 'self'` のため
  インライン JS は使えない。SEC12）。**JS が無効でも初期状態はサーバ側の描画で正しい。**

## 却下した案

- **redirect_uri を無条件に省略可にする。** 何もできないクライアントが作れてしまう。
- **用途を api のモデルにも持たせる。** `grant_types` と二重管理になり、「用途はシステム用なのに
  `authorization_code` を持つ」という不整合を作れる余地が残る。導出できるものは持たない。
- **システム用にダミーの redirect_uri を既定値として入れておく。** 登録は通るが、使わない URL が
  登録済みリダイレクト先として残る。認可フローの入口を開けたままにする点は何も解決しない。
- **用途を 3 択（ログイン／システム／両方）にする。** 1 クライアントに 2 用途を持たせる登録を
  勧めることになる。用途ごとに分ける。
