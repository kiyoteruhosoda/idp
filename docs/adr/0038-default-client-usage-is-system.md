# ADR-0038: クライアント新規登録の既定の用途を「システムが API を呼ぶ」にする

- Status: Accepted
- Date: 2026-08-27
- 関連: `docs/adr/0032-client-usage-drives-the-registration-form.md`（用途で入力欄を変える）、
  `docs/adr/0030-machine-authentication-private-key-jwt.md`、
  `docs/adr/0036-default-client-authentication-method.md`（既定の置き方）、
  `docs/adr/0037-management-api-access-tokens-and-permission-set.md`

## 背景

ADR-0032 で登録フォームの先頭に「用途」を置き、以降の入力欄をその選択で変えるようにした。
用途は 2 つ（ブラウザで利用者をログインさせる／システムが API を呼ぶ）で、初期選択は
**ブラウザログイン**だった。これは「先に並べた選択肢がそのまま初期選択になった」もので、
どちらを既定にするかを判断した記録は無い。

その後 ADR-0030（`private_key_jwt`）と ADR-0037（管理 API のアクセストークンと権限セット）で、
CI・バッチ・AI エージェントが IdP を呼ぶ経路が一通り揃った。`docs/OPERATIONS.md` の
クライアント登録手順も、この用途を前提に書かれている。

## 決定

### 1. 新規登録フォームの用途の初期選択をシステム用にする

`ClientFormValues::default_new()` の `usage` を `client_usage::SYSTEM` にする。選択肢の並びも
認証方式（ADR-0036）と同じく、**既定にするものを先頭へ置く**。

既定をこちら側にするのは、**選び違えたときの後始末が軽いほう**だからである。システム用は
redirect_uri を持たず、`client_type` は confidential 固定で、認可フローの入口を開けない。
用途を選び直せば入力欄は追随する（JS が無い環境でも、再描画後の初期状態はサーバ側が正しく出す）。

逆向きの既定は、ADR-0032 が問題にした失敗をそのまま招く。システムを登録しに来た管理者に
初期状態で必須の「リダイレクト URI」を見せると、**使いもしない URL を捏造させる**。捏造された
URI は登録済みリダイレクト先として残り、`authorization_code` の許可も付いたままになる。

### 2. api の省略時（`allow_client_credentials`）は変えない

ADR-0036 では画面の初期選択と api の省略時を同じ値へ揃えたが、ここは揃えない。

画面の初期選択は**管理者が見て、変えられる**値である。一方 JSON で省略された項目は誰の目にも
触れない。省略を「`client_credentials` を許す」と読むと、書いていない呼び出しに対して**求められて
いない能力**を黙って付ける。既定に置いてよいのは、見える選択のときだけである。

`POST /{tenant_id}/admin/clients` は従来どおり `allow_client_credentials` の省略を `false` と読み、
システム用クライアントは `true` を明示して登録する。

## 影響

- 管理コンソールの `/{tenant_id}/admin/clients/new` を開くと、用途がシステム用で、リダイレクト URI と
  client type の欄は初めから隠れている。ブラウザログイン用の RP を登録するときは用途を選び直す。
- 登録される値は変わらない。用途は画面の語彙であって api のモデルには無く（ADR-0032）、
  送る内容は選択から導出される。
- api・E2E スクリプト（`scripts/e2e.sh`）は `usage` を明示して送るため影響を受けない。

## 却下した案

- **api の省略時も `allow_client_credentials: true` へ揃える。** 決定 2 のとおり。省略は選択ではない。
- **既定を置かず、未選択で始める。** 用途は以降の入力欄を決めるので、未選択の間はフォームが
  どの形にもならない。「必須なのに既定が無い」項目を先頭に置くと、何も入力できない画面になる。
- **並びは変えず `selected` だけ移す。** 既定を先頭に置く並べ方は認証方式で既に採っている
  （ADR-0036）。同じ画面で規則を分けない。
