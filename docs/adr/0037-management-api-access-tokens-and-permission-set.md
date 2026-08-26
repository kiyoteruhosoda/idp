# ADR-0037: IdP 自身を操作する API は、人も機械も同じアクセストークンで認可する

- Status: Accepted
- Date: 2026-08-26
- **Revised**: 2026-08-26（2）— 積み残しにしていた 2 点を決着させた。
  1. **管理コンソールのクライアント権限画面を実装した**（決定 5 の入口。#161）。
  2. **`whoami` の要求権限を `idp.tenant.admin` のままにすると決めた**（決定 8 として追記）。
     「後で決める」ではなく「これで足りる」という判断なので、`docs/Progress.md` の課題から
     本 ADR の決定へ移す（設計判断は ADR に残す。`CLAUDE.md`「ドキュメント運用」）。
- 関連: `docs/adr/0006-admin-permission-model.md`（権限コード）、
  `docs/adr/0007-api-web-service-split.md`（api/web 分割）、
  `docs/adr/0009-multi-tenant-architecture.md` §4（権限の scope）、
  `docs/adr/0030-machine-authentication-private-key-jwt.md`（システムの認証）、
  `docs/adr/0032-client-usage-drives-the-registration-form.md`（用途と登録内容）、
  `docs/adr/0033-resource-server-authorization-belongs-to-the-application.md`（権限コードの位置づけ）、
  `CLAUDE.md`「権限管理」

## 背景

この IdP には `/{tenant_id}/admin/*` という管理 API が既にある。利用者・クライアント・
テナント・鍵・監査ログ——運用で必要なものはほぼ揃っている。にもかかわらず、**この IdP を
プログラムから操作する手段が無かった。**

理由は 2 つある。

### 1. 資格情報がブラウザの Cookie しか無かった

`RequirePerms` は SSO セッション Cookie だけを読んでいた。

```rust
let sso_session_id = cookies::get(&parts.headers, cookies::SSO_SESSION_COOKIE);
state.admin_access.authorize(resolved.context(), sso_session_id.as_deref(), P::CODE)
```

Cookie を出せるのは管理コンソール（web）だけである。ADR-0030・ADR-0032 で
`client_credentials` と `private_key_jwt` を入れ、システム（CI・バッチ・AI エージェント）が
`/token` を叩けるようにしたのに、**そこで得たトークンで呼べる API がこの IdP には 1 本も無かった。**
ADR-0033 が「`client_credentials` のトークンの `scope` は空になる」と結論したとおり、
取れるトークンは `sub` を名乗る以外に使い道が無い状態だった。

副作用として、Cookie は ambient（ブラウザが自動で付ける）なので api 側にもオリジン検証が要り、
`RequirePerms` は認可の前に CSRF の心配をしていた。

### 2. 権限コードが 2 つしか無かった

`idp.system.admin` と `idp.tenant.admin` だけ。管理 API を 1 本でも呼ばせたい相手には、
**管理操作すべて**を渡すしかない。利用者の棚卸しをしたいだけのバッチに、クライアントの削除も
設定変更もできる資格情報を配ることになる。`domain/permission.rs` のコメントは当初から
「将来 `idp.clients:read`」と書いていたが、書かれただけだった。

この 2 つは独立した欠落に見えて、実は同じ 1 つの欠落である。**機械に渡せる粒度の権限が無いから
機械向けの入口を作れず、入口が無いから粒度を分ける動機も生まれない。**

## 決定

### 1. 管理 API の資格情報は、人も機械もアクセストークンに一本化する

`RequirePerms` は `Authorization: Bearer` だけを見る。Cookie は読まない。

| 主体 | トークンの取り方 |
|---|---|
| 管理コンソールの利用者 | web が SSO セッションを `POST /internal/admin/token` で交換する |
| システム用クライアント | `client_credentials` に `resource={issuer}/admin` を添えて `/token` を叩く |

ここでの `{issuer}` は**テナント毎の issuer**（`{基底 issuer}/{tenant_id}`。ADR-0009 §6）である。
したがって実際の値は `https://idp.example.com/{tenant_id}/admin` になる。

「コンソールは Cookie、機械は Bearer」の二本立てにしなかったのは、**認可経路が 2 本あると
片方にだけ効く修正が生まれる**ためである。権限の解決も、主体の有効性確認も、失効の効き方も、
経路ごとに書けば必ずずれる。入口の形（Cookie / client assertion）は違ってよいが、
**そこから先は 1 本**にする。

web の変更は `api_client` に閉じている。管理 API を呼ぶ各メソッドは今までどおり SSO セッション値を
受け取り、`admin_send` 系が交換してから Bearer で送る。**画面のハンドラは 1 つも変わらない。**

副産物として、api の管理面から CSRF の論点が消えた。Bearer は ambient ではないので、
オリジン検証をしなくても他サイトから管理 API を叩かせることができない。ブラウザ経路の CSRF は
web が同期トークンで閉じて扱う（`idp_web::csrf`。元からそうなっている）。Cookie を直接読み続ける
`AuthenticatedUser`（招待の承諾）はオリジン検証を残す。

### 2. トークンの交換はリクエスト毎に行い、キャッシュしない

管理コンソールは api を呼ぶ度に交換する。1 往復増えるが、**セッション失効・権限剥奪・ゲストの
一時停止が即座に効く**。キャッシュすると、それらがトークンの寿命だけ遅れて効く。管理コンソールの
流量は少なく、「無効化したのにまだ操作できる」窓を無くす方が価値が高い。

同じ理由で `RequirePerms` は毎回**主体がまだ使えるか**（利用者が有効か・クライアントが有効か）を
確かめる。ただし**権限そのものはトークンから読む**（引き直さない）。引き直すなら `perms` を
載せる意味が無い。機械のトークンは寿命いっぱい持ち回されるので、`MANAGEMENT_TOKEN_TTL_SECS`
（既定 300 秒）が「クライアントを止めてから実際に止まるまで」の上限になる。

### 3. 権限セットはリソース × 読み書き。`idp.tenant.admin` は上位として残す

```
idp.users:read              idp.users:write
idp.clients:read            idp.clients:write
idp.members:read            idp.members:write
idp.permissions:read        idp.permissions:write
idp.audit:read
idp.keys:read               idp.keys:write
idp.tenant-settings:read    idp.tenant-settings:write
idp.authentication-policies:read / :write
idp.external-idps:read      / :write
idp.saml-service-providers:read / :write
```

含意は 3 つだけで、**Rust 側（`domain::permission::implies`）が単一の出所**である。

1. `idp.system.admin` はすべてを含意する
2. `idp.tenant.admin` は上表すべてを含意する
3. 同一リソースの `:write` は `:read` を含意する

DB に含意表を持たせないのは、判定が DB とアプリの 2 か所に分かれるためである。

**既存の付与行は 1 行も書き換えない。** 今 `idp.tenant.admin` を持っている管理者は、含意規則に
よって細粒度で保護されたエンドポイントを今までどおり全部通る。移行作業が要らないことが、
この含意関係を入れた主な理由である。

### 4. システム管理操作は細粒度へ分割しない

テナントの作成・削除、システム設定、再起動、テナント横断のログ参照は `idp.system.admin` の
完全一致だけが通る（従来どおり）。細粒度化の目的は**テナントの中の運用を分担させること**で
あって、root の権限を切り売りすることではない。上表に `idp.tenants:*` が無いのはそのためである。

### 5. クライアントには包括的な管理権限を付与させない

`client_permissions` テーブルに `idp.system.admin` / `idp.tenant.admin` を入れられない
（DB の CHECK 制約 ＋ アプリ層の判定の二重防御）。

機械の資格情報は人の資格情報より寿命が長く、失効の導線も弱い（辞めた人のアカウントは止まるが、
CI に置いた鍵は誰も止めない）。**「とりあえず tenant.admin を付ける」を塞ぐことで、
細粒度コードを選ばせる。** これは細粒度化の趣旨そのものであり、運用の善意に任せない。

付与の入口は `/{tenant_id}/admin/clients/{client_id}/permissions` で、保護は
`idp.clients:write`（読み取りは `idp.clients:read`）。権限管理（`idp.permissions:*`）ではなく
クライアント管理の側に置くのは、**対象のライフサイクル（登録・失効）と同じ人が握るべき判断**
だからである。

### 6. 権限コードは `perms` クレームで運び、`scope` には載せない

管理トークンは `aud = {issuer}/admin`（テナント毎の issuer）に固定し、権限コードは `scope` では
なく `perms` クレームに入れる。ADR-0033 の決定——「権限コードはこの IdP 自身の API を守るためのもので、
他のリソースサーバの権限体系ではない」——はこの `aud` 固定で保たれる。外部アプリ向けの
トークン（`aud = {issuer}/userinfo`）に `perms` は載らない。

`scope` と分けるのも同じ理由である。`scope` は ID クレームの制御に使う値で、RP がその内容に
依存し得る。混ぜると管理権限が RP の認可判断へ漏れる。

宛先の指定を `resource`（RFC 8707）で**呼び出し側に書かせる**のは、クライアントの登録権限から
発行内容を暗黙に切り替えると、**権限を 1 つ付けた途端にトークンの `aud` が変わる**ためである。
権限を付ける操作が、既存の呼び出し元を黙って壊してはいけない。

`resource` を解釈するのは `client_credentials` だけで、利用者を認証した grant に付けて送ると
`invalid_target` で断る。黙って無視すると「管理トークンを頼んだのに `/userinfo` 用が返り、
管理 API で 401 になる」という、要求側から原因の見えない失敗になる。

### 7. 監査ログの主体は「利用者 or クライアント」の 1 つの型で表す

`AdminActor`（`domain::admin_actor`）が `user_id` 列と `client_id` 列への写像を持つ。
`audit_log` は元から両方の列を持っていたので、列の追加は不要である。
操作対象がクライアントの記録（クライアントの登録・更新・削除・権限付与）では `client_id` 列が
対象で埋まっているため、実行主体は `reason` の `actor_client=` に出す。

### 8. 管理コンソールの入口はテナント管理者のまま。細粒度コードは API 利用者のためのもの

`GET /admin/whoami` は `idp.tenant.admin` を要求し続ける。したがって**細粒度コードだけを持つ
利用者は、管理 API は使えるがコンソールには入れない**。

`whoami` は個々の操作の可否ではなく「**管理者としてログインしているか**」を答える判定で、
細粒度コードでは表せない。`idp.users:read` を持つことは「利用者一覧を読める」ことであって
「コンソールの利用者である」ことではない。ここを「どれか 1 つでも管理権限を持てば通す」に
広げると、入口は通るのに開いた画面のほとんどが 403 になる —— **入れるのに何もできない**という、
権限不足より分かりにくい状態を作る。

細粒度化の目的（決定 3）はテナント内の運用を分担させることだが、**分担の相手は当面
「機械」である**。人に配るなら、入口を通すだけでは足りず、画面ごと・操作ごとの出し分けと、
何が見えないのかを伝える表示が要る。それは `whoami` の要求権限を下げる話ではなく、
コンソールの情報設計をやり直す話なので、必要になった時点で改めて設計する。

それまでの割り切りを明示しておく:

| 主体 | 入口 | 与えるもの |
|---|---|---|
| 人（管理コンソール） | `idp.tenant.admin` | コンソール全体 |
| 機械（管理 API） | 細粒度コード | 付与した範囲だけ |

## 影響

- **DB**: `0045_management_api_permissions`（権限コード 19 件の seed ＋ `client_permissions`）。
  既存行は書き換えない。`down` は細粒度コードの付与行とマスタ行を消す。
- **設定**: `MANAGEMENT_TOKEN_TTL_SECS`（DbManaged・既定 300）を追加。
- **api**: `RequirePerms` が Bearer 専用に。各 `/admin/*` ルートのマーカを細粒度へ。
  `POST /internal/admin/token`・`/admin/clients/{id}/permissions` を追加。
- **web**: `api_client` の管理 API 経路が Cookie 転送から管理トークンへ。画面側は変更なし。
- **application 層**: 管理系ユースケースの `actor: Uuid` が `actor: &AdminActor` に。
- **手順**: システム用クライアントから IdP を操作する手順は `docs/OPERATIONS.md`。

## 却下した案

- **コンソールは Cookie のまま、機械にだけ Bearer を足す。** 実装は小さいが、認可経路が
  2 本になる。上記「決定 1」の理由でしない。
- **`/management/*` を別に生やす。** 仕様を分離できるが、同じ操作のハンドラ・DTO・監査が
  二重化する。`/admin/*` は既に「IdP 自身を操作する API」であり、足りなかったのは入口と粒度だけ
  だった。
- **権限コードをアクセストークンの `scope` に載せる。** ADR-0033 で却下済み（`aud` を分けても
  `scope` を共有すると、RP のログや自動処理が管理権限の文字列を見ることになる）。
- **交換したトークンを web でキャッシュする。** 往復は減るが失効の効きが遅れる。決定 2 の理由で
  しない。流量が問題になったら、TTL ではなく**失効イベントで捨てられる**キャッシュを検討する。
- **サービスアカウント（機械に紐づく利用者行）を作って `user_permissions` を流用する。**
  既存テーブルを使えるが、実体の無い利用者が利用者一覧・メンバー数・棚卸しに混ざる。主体が
  `client_id` のまま一貫する方が ADR-0033（`sub` = `client_id`）とも噛み合う。

## 積み残し

無し（初版で挙げた 2 点は上記 Revised のとおり決着した）。
