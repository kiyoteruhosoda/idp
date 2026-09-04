# ADR-0043: 認証の強度は予約語 2 つで名乗り、ID トークンへ `acr` を載せる

- Status: Accepted
- Date: 2026-09-04
- 関連: `docs/adr/0020-authentication-policy.md`（認証ポリシー。AP2/AP3）、
  `docs/adr/0008-mfa-design.md`（MFA 設計・充足判定）、
  `docs/adr/0033-resource-server-authorization-belongs-to-the-application.md`（業務権限は配らない）、
  `docs/adr/0042-tokens-carry-an-audience-not-a-vocabulary.md`（宛名だけを刻む）、
  OpenID Connect Core 1.0 §2 / §3.1.2.1、RFC 8176（`amr`）

## 背景

assay は認可要求の `acr_values` を**本当に強制している**。認証ポリシー（ADR-0020）の
`requested_acr` 条件が参照し、しかも SSO セッションの復元時にも評価し直す。
`crates/core/src/application/authorize.rs:367` はその理由をこう書いている。

> 復元対象のセッションが確立されたときとは、クライアントも `acr_values` も違いうる。
> 評価しないと、RP が `acr_values` で WebAuthn 必須ポリシーを起動しても、
> パスワードだけで確立された既存 SSO が黙って再利用される。

ここまでやっているのに、**満たしたことを RP へ返す口が無い。**

- `IdTokenClaims`（`crates/core/src/application/token.rs:413`）は `iss` / `sub` / `aud` /
  `exp` / `iat` / `auth_time` / `nonce` / `jti` / `sid` / `email` / `email_verified` /
  `preferred_username` / `name` だけ。
- `AuthenticationMethod::amr()`（`crates/core/src/domain/values.rs:248`）は定義されているが
  呼び出しが 1 件も無い。
- discovery は `"acr_values_supported": []`、`claims_supported` にも `acr` / `amr` は無い。

**現状の宣言そのものは正直である**（保証していないものを名乗っていない）。問題は 2 つある。

**1. 綴り違いが黙って通る。** `requested_acr` 条件は「空 = 制限しない、非空 = いずれかに一致」
なので、RP が送る文字列とポリシー行に入力された文字列が 1 文字ずれると条件が外れ、
そのポリシーは適用対象から落ちる。残るのは既定効果（`AUTH_POLICY_DEFAULT_EFFECT`、既定
`allow`）なので、**RP は MFA を要求したつもりで単要素のログインを受け取り、気付く手段が無い。**
ADR-0020 は条件の**キー**のタイポを `deny_unknown_fields` で弾いているが、**値**は弾けない。

**2. 語彙がどこにも無い。** いま値の意味を決めているのは、テナント管理者がポリシー行の
`requested_acr` 欄へ打った自由文字列である。テナントごとに違ってよく、公開もされない。
RP には「何を送ればよいか」を知る方法が無い。

RP 側（fastapitemplate へ入れる SSO）で `acr_values` を送る話が出て、この 2 つが表面化した。

## 決定

### 1. 予約語を 2 つ定義し、assay が組み込みで解釈する

`urn:assay:ac:mfa` と `urn:assay:ac:single` の 2 つ。

- RP が `acr_values` に `urn:assay:ac:mfa` を含めたら、**ポリシーの有無に関わらず** MFA を
  要求する。充足判定は ADR-0020 §3 のまま（確認済み TOTP を経る / パスキーは満たす /
  TOTP 未設定は `MfaEnrollmentRequired` で拒否）。
- `urn:assay:ac:single` は「要求しない」の明示で、送っても何も強制しない。
- **順序を含む名前にしない。** `level1` / `level2` のような名前は、後から中間を挿せない。
- 名前空間はテナントのドメイン（`nolumia`）ではなく**製品名**（`assay`）で切る。
  語彙を定義しているのは assay の実装であって、特定のテナントではない。

### 2. 実効要件は「RP の要求」と「テナントのポリシー」の強いほう

ポリシーの `require_mfa` は「**RP が要求しなくても**テナントが強制する」役割として残す。
両者は競合せず、どちらかが MFA を求めれば MFA になる。

### 3. ID トークンへ `acr` を載せる。要求の有無にかかわらず常に載せる

- 値は**実際に評価した結果**。満たしていないのに `urn:assay:ac:mfa` を返さない。
- 常に載せるのは、RP が「載っていない = 要求が届かなかった」と「載っていない = そもそも
  要求していない」を区別できるようにするため。要求したときだけ返す形にすると、
  この 2 つが同じ見え方になる。
- SSO 復元のときは、復元したセッションの `authentication_methods` を評価した結果を載せる
  （`authorize.rs` が既に持っている材料）。

### 4. `amr` も載せる。ただし強度の判断には使わせない

- 値は RFC 8176 の語彙で、`AuthenticationMethod::amr()` をそのまま繋ぐ。
- **用途は監査と表示に限る**と discovery のコメントと `docs/OIDC_INPUT.md` に明記する。
  理由は `fed`（外部 IdP 経由）で、その先で何が使われたかは assay も知らない。
  ADR-0008 が「外部 IdP は第二要素として数えない」としているのと同じ話である。
- 強度は `acr` で判断する。`amr` で分岐させると、assay が方式を増やすたびに
  RP 側の分岐が増える。

### 5. 保証できる値だけを公開する

- `acr_values_supported` に予約語 2 つを載せ、`claims_supported` に `acr` / `amr` を足す。
- **テナント独自の文字列は今までどおりポリシー条件に書けるが、`acr_values_supported` へは
  載せず、`acr` としても返さない。** 「保証できる値が無いので空配列を出す」という現在の
  コメントの方針を、値が増えた後もそのまま守る。
- 語彙は**テナントによらず同一**にする。テナントごとに変えられるようにすると、
  いまの「どこにも書いていない文字列」へ戻る。

### 「assay は語彙を配らないのでは」を検討して、これは配ると決めた

ADR-0033 は「業務権限は配らない」、ADR-0042 は「トークンには宛名だけを刻む」としている。
`acr` はこれに反しない。

- 配らないと決めたのは**受け側の語彙**（アプリの中で何をしてよいか）である。それを assay が
  持つと、アプリの数だけ語彙が assay に溜まり、アプリの都合で assay を触ることになる。
- `acr` は**assay 自身が行ったことの説明**である。定義できるのは assay しかいない。
  RP ごとに違う値にしたら、assay が RP の数だけ辞書を持つことになり、まさに ADR-0033 が
  避けた形になる。**共通にすることが、語彙を溜めないための条件**である。
- したがって「業務の語彙は配らない・認証の語彙は assay が定義して 1 つだけ公開する」で
  一貫する。2 値に絞るのも同じ理由で、ここを増やし始めると業務の語彙に近づく。

## 帰結

- **認可コードに保存先が要る。** `AuthorizationCode` は `acr` に相当する値を持たず、トークン
  発行時には認証の文脈が残っていない。`sid` を足したときと同じ形（`None` = 本列の導入前の行）で
  `auth_sessions` / `authorization_codes` / `refresh_tokens` の 3 つへ列を足す
  （マイグレーション 0049）。`auth_sessions` が要るのは同意画面を挟む経路のため、
  `refresh_tokens` が要るのは refresh で発行する ID Token も名乗るためである。
- **強度の 2 値は新設ではない。** `AuthenticationStrength`（`single_factor` / `multi_factor`）が
  既に内部の派生値としてあり、予約語はその公開名にすぎない。語彙を 2 つに留められるのは、
  新しい概念を持ち込んでいないからである。
- **公開契約になる。** `acr_values_supported` へ載せた値は、RP が依存した後は変えられない。
  2 値で始めるのはそのためで、増やすのは後からでもできるが減らせない。
- **RP 側が確認して初めて効く。** assay が返すだけでは検出にならない。RP は「要求した `acr` が
  返ってきたか」を確かめる必要がある。fastapitemplate 側にその実装を入れる（あちらの ADR-0026）。
- **既存の RP への影響は無い。** 未知のクレームは無視され、`acr_values` を送っていない RP の
  挙動は変わらない。ポリシーの `requested_acr` 条件も従来どおり使える
  （予約語を条件に書けば「MFA を要求した RP にだけ追加の `deny` を当てる」も従来どおり）。
- **`prompt=none` との組み合わせは既存の扱いのまま。** MFA が必要でセッションが満たしていない
  ときは再認証へ落ち、`prompt=none` ならそこで `login_required` を返す（`max_age` 超過と同じ
  経路。`authorize.rs` の resume が既にそうなっている）。新しい分岐は要らない。
- `docs/OIDC_INPUT.md` に RP 向けの契約として 2 値の意味と `amr` の位置づけを書く。
