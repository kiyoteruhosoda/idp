# ADR-0030: 機械の同一性はクライアントに持たせ、資格情報として `private_key_jwt` を足す

- Status: Accepted
- Date: 2026-08-24
- 関連: `CLAUDE.md`「権限管理」「DB モデリング」、`docs/adr/0006-admin-permission-model.md`（利用者権限）、
  `docs/adr/0009-multi-tenant-architecture.md`（テナント独立・issuer 合成）、
  RFC 7521（Assertion Framework）／RFC 7523（JWT Bearer client authentication）／
  OIDC Core §9（Client Authentication）

## 背景

「人ではない呼び出し元」＝ CI・バッチ・サーバ間連携に、利用者アカウントを 1 つ作って
パスワードを共有する運用は避けたい。人のアカウントは MFA・パスワード有効期限・ロックアウト・
セッションといった**人向けの前提**の上に組まれており、機械がそこへ入ると必ずどれかを無効化する
ことになる（MFA を外した「サービス用ユーザー」が典型）。

本 IdP には既に `client_credentials` grant（G4）があり、利用者の居ないトークンを発行できる。
発行されるアクセストークンの `sub` はクライアント自身で、`sub_type` クレームで利用者主体の
トークンと区別している。つまり**機械の同一性を表す主体は既に存在する**。

足りていないのは資格情報の側である。現状の confidential client は `client_secret_basic` /
`client_secret_post` の 2 方式しか持たず、どちらも**共有秘密**である。共有秘密は

- IdP 側にも（ハッシュとはいえ）保存され、
- クライアント側では設定ファイル・環境変数・CI のシークレットストアに平文で置かれ、
- ネットワーク上をリクエストごとに流れる

という性質を持つ。人が対話的に使う RP なら許容できても、無人で長期間動き続ける機械では
漏洩経路が積み上がる。

## 決定

### 1. 機械の同一性はクライアントに持たせる（`service_accounts` を新設しない）

機械のプリンシパルは **`clients` の行そのもの**とする。クライアントとは別に
`service_accounts` テーブルを置き「クライアントは資格情報の入れ物」とする形（Google 型）は採らない。

理由は同一性の軸を二重にしないため。本 IdP のトークン発行・監査・テナント境界はすべて
`(tenant_id, client_id)` を主体として組まれている（`audit_log` の `client_id`、
`clients_tenant_client_id_uk`、`sub_type=client` の access token）。ここへ第 2 の主体表を足すと、
`sub` に何を入れるか・監査にどちらを記録するか・テナント移動時にどちらを追うかが、
経路ごとに判断の分かれる問題として増える。1 つの機械に複数の資格情報を持たせたい要求は、
JWKS に鍵を複数入れることで足りる（決定 4）。

したがって本 ADR の変更は**新しい主体の追加ではなく、既存主体の資格情報の強化**である。

### 2. `private_key_jwt`（RFC 7523）を追加する

confidential client の `token_endpoint_auth_method` に `private_key_jwt` を加える。
クライアントは秘密鍵で署名した JWT（client assertion）を提示し、IdP は登録済みの公開鍵で検証する。

```
POST /{tenant_id}/token
grant_type=client_credentials
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=<署名済み JWT>
```

秘密は**クライアント側にしか存在しない**。IdP の DB が漏れてもクライアントには成りすませず、
リクエストを傍受しても再利用できる秘密は流れていない（署名は決定 5 の条件で 1 回きり）。

方式はクライアント登録値で 1 つに固定する（既存の `client_secret_basic` / `client_secret_post` と
同じ扱い）。「登録は `private_key_jwt` だが secret でも通る」という併存は認めない。強い方式を
登録した意味が、弱い方式の残存で消えるため。

### 3. 検証鍵は登録済みの JWKS のみを見る（`jwks_uri` を採らない）

公開鍵は `clients.jwks` 列に **JWK Set をそのまま保存**し、検証時はこれだけを見る。
クライアントの `jwks_uri` を取りに行く形は採らない。

- トークンエンドポイントが外部 HTTP に依存すると、クライアント側のホスティング障害が
  こちらの認証失敗になる。認証は本 IdP の可用性の内側に閉じておきたい。
- 取得先 URL はクライアント登録者が指定する値であり、`/token` の処理中に任意 URL へ
  送信を行う経路（SSRF）を新設することになる。本リポジトリは back-channel logout の宛先で
  同じ問題を扱い、`domain/outbound_uri.rs` で内部宛先を弾いている（SEC2）。認証経路には
  そもそもその面を作らない方が単純である。

鍵は登録時に検証・正規化して保存する（`kty`・`kid` 必須、対応するのは RSA / EC P-256、
秘密鍵成分を含む JWK は拒否）。「取り込めない鍵」は登録時点で失敗させ、`/token` の時刻には
持ち込まない。

### 4. 鍵ローテーションは JWKS に複数鍵を置くことで行う

JWKS は複数の鍵を持てる。新旧を並べた状態を作ってからクライアント側を切り替え、
落ち着いてから旧鍵を消す、という無停止の入れ替えができる。IdP 側に「移行期間」の概念や
猶予つきの旧 secret を持たせる必要はない。

assertion の `kid` で鍵を選ぶ。`kid` が無い assertion は、JWKS に鍵が 1 つのときだけ
その鍵で検証する（複数あるなら選びようがないので失敗させる）。

### 5. `jti` を必須とし、有効期間内の再利用を拒否する

RFC 7523 §3 は `jti` による再生防止を任意（MAY）としているが、本 IdP は**必須**とする。
`jti` を持たない assertion は拒否し、検証を通った `(tenant_id, client_id, jti)` は
`client_assertion_jtis` へ記録して `exp` まで再受理しない。

再生防止が無いと、assertion を一度傍受した相手は `exp` までの間その assertion を使い回せる。
つまり「共有秘密を流さない」という決定 2 の利点が、有効期間の長さだけ目減りする。

併せて `exp` の上限を **5 分**とする（`exp - 現在時刻 > 5 分` の assertion を拒否）。
これは再生の窓を短く保つためであると同時に、`client_assertion_jtis` の保持期間の上限でもある。
期限切れの行は掃除して積み上がらないようにする。

### 6. `aud` はテナント issuer とトークンエンドポイント URL の両方を受理する

OIDC Core §9 は `aud` を「トークンエンドポイントの URL」とすべき（SHOULD）とし、
RFC 7523 §3 は「認可サーバを識別する値」とする。実際のクライアント実装は
issuer を入れるものとトークンエンドポイント URL を入れるものに分かれている。

本 IdP は `<基底 issuer>/<tenant_id>` と `<基底 issuer>/<tenant_id>/token` の**どちらか一方を
含むこと**を要求する（ADR-0009 §6 の合成規則をそのまま使う）。どちらもテナントを含む値なので、
A テナント宛の assertion を B テナントの `/token` へ持ち込むことはできない。

`aud` の検査そのものは省略しない。省略すると、あるサービス向けに発行させた署名済み JWT を
本 IdP の `/token` へ転送する経路が開く。

### 7. 署名アルゴリズムは RS256 / ES256 に限る

登録済み鍵の `kty` から決まるアルゴリズムだけを受け付ける。assertion のヘッダが `none` や
HMAC 系（`HS256`）を名乗る場合は、鍵の種別と一致しないので拒否される。
「ヘッダの `alg` を信じて検証方式を選ぶ」実装にしない（`alg` 混同攻撃を成立させないため）。

## 影響

- `clients.token_endpoint_auth_method` の許可値と `clients.jwks` 列、
  `client_assertion_jtis` 表がマイグレーションで増える。既存クライアントは影響を受けない
  （既定は従来どおり `client_secret_basic`）。
- `/token`・`/introspect`・`/revoke` の 3 経路は RFC 6749 §2.3.1 の同じクライアント認証を使う。
  方式を足すたびに 3 か所へ書き足すと取りこぼすため、資格情報の選択と照合を
  `application/client_authentication.rs` の 1 か所へ集約する。各経路が持つのは
  監査イベントの形とエラー応答の違いだけになる。
- Discovery の `token_endpoint_auth_methods_supported` に `private_key_jwt` が、
  `token_endpoint_auth_signing_alg_values_supported` が加わる。
- 機械が持てるのは引き続き **OIDC scope** であって**利用者権限コード**ではない。
  `client_credentials` のトークンで本 IdP の管理 API を叩くことはできない（ADR-0006 の
  権限は `user_permissions` にしか存在せず、`sub_type=client` のトークンは管理経路を通らない）。
  機械に管理操作をさせたくなった場合は別途 ADR を起こす。

## 却下した案

- **機械用の利用者アカウント（`users` に `is_service` フラグ）。** 人向けの前提
  （MFA・パスワード有効期限・ロックアウト・SSO セッション）を機械のために例外化していく
  ことになり、例外が増えるほど「人の経路」の保証が読めなくなる。
- **`service_accounts` テーブルの新設（Google 型）。** 決定 1 のとおり同一性の軸が二重になる。
  1 主体に複数の資格情報を持たせる要求は JWKS の複数鍵で足りる。
- **`jwks_uri` の取得に対応する。** 決定 3 のとおり、認証経路に外部依存と SSRF 面を作る。
  必要になれば、登録時に取得して `clients.jwks` へ取り込む（＝検証時は取りに行かない）形で
  後から足せる。
- **`jti` の再生防止を任意にする。** 決定 5 のとおり、`exp` の長さだけ再生の窓が開く。
  記録すべき行は「有効期間内の assertion」だけなので、上限 5 分なら量は高が知れている。
- **`client_secret` と `private_key_jwt` の併存を認める。** 強い方式を登録した意味が
  弱い方式の残存で消える。移行はクライアント単位の登録値の切り替えで行う。
