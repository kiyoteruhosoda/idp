# ADR-0033: リソースサーバの認可はアプリが `client_id` / `sub` で行う

- Status: Accepted
- Date: 2026-08-25
- 関連: `docs/adr/0006-permission-codes-as-master-data.md`（権限コード）、
  `docs/adr/0030-machine-authentication-private-key-jwt.md`（システムの認証）、
  `docs/adr/0032-client-usage-drives-the-registration-form.md`（用途と登録内容）、
  `CLAUDE.md`「権限管理」

## 背景

システム用クライアントの登録手順を書いたとき、スコープ欄に `reports.read` と書いてしまった。
実際には `validate_scopes` が OIDC の 4 値（`openid` / `profile` / `email` / `offline_access`）
しか受け付けず `openid` を必須とするため、そのまま実行すると 400 になる。

この食い違いを「`CLAUDE.md`「認可は scope（権限コード値）で行う」という方針に実装が追いついて
いない」と読んだが、**これは読み違いだった。** このコードベースには別軸の 3 つがある。

| | 実体 | 値 | 用途 |
|---|---|---|---|
| 権限コード | `PermissionCode`（`permissions` マスタ） | `idp.tenant.admin` 等。**運用で増える** | **この IdP 自身の API 認可**（`RequirePerms`） |
| OIDC scope | `domain::values::Scope` | 4 値固定（仕様で決まっている） | ID トークン・`/userinfo` のクレーム制御 |
| `clients.scopes` | DB の JSON 列 | 登録時は上の 4 値のみ | クライアントが要求できる scope の上限 |

`domain/permission.rs` は「OIDC scope とは**別軸**の『利用者が保有する権限』」と明記しており、
`CLAUDE.md` も次の行で OIDC scope の役割（クレーム制御）を分けて書いている。**方針と実装は
食い違っていない。**

残るのは、もっと小さく具体的な問いだった —— **業務上の権限（`reports.read` 等）を、IdP が
アクセストークンの `scope` として配るのか、それともアプリが自分で判断するのか。**

## 決定

**リソースサーバ（アプリ）が `client_id` ないし `sub` を見て認可する。** IdP が担うのは
**認証と ID クレームまで**であり、業務上の権限を scope として配ることはしない。

したがって:

- **`clients.scopes` は OIDC scope 専用**とする。登録時に受け付けるのは 4 値のままでよく、
  業務スコープを登録できないのは欠落ではなく設計である。
- **この IdP 自身の API の認可は権限コード**（`permissions` マスタ + `user_permissions`）で
  行う。こちらは運用で増える前提の**データ**であり、固定 enum ではない（ADR-0006）。
- `CLAUDE.md`「認可はロールではなく scope（権限コード値）で行う」の "scope" は**権限コード**を
  指す。OIDC scope のことではない。

### この決定から出る帰結

**`client_credentials` で得たアクセストークンの `scope` は空になる。**
`resolve_client_credentials_scopes` は「登録 scope から利用者前提のもの（`openid` / `profile` /
`email`）と `offline_access` を除いた集合」を既定とするが、登録できるのがその 4 値だけである以上、
残りは常に空だからである。利用者の居ないトークンに載せる意味のあるクレームが無い、という
決定どおりの姿である。

アプリはトークンの `scope` ではなく **`sub`（= `client_id`）** を見て、自分の側で
「この呼び出し元に何を許すか」を決める。

## 影響

- コンソールのスコープ欄が 4 つのチェックボックスなのは正しい（ADR-0032 決定 4）。
- 手順書のシステム用クライアントの例は `openid` のみでよい。
- 新たに必要な実装は無い。

## 積み残し（本 ADR では変えない）

**トークン側は業務スコープを扱える作りのまま残っている。** `resolve_client_credentials_scopes`
は任意の scope 文字列を `clients.scopes` の部分集合として検証でき、その単体テストと統合テストの
fixture は `reports.read` / `reports.write` を使っている（fixture は SQL 直挿しなので登録検証を
通らない）。

本決定のもとでは、これは**どの経路からも到達できない状態を記録したテスト**である。実際、
手順書に `reports.read` と書く誤りの一因になった。次のいずれかで整理する:

- テストと fixture を登録可能な scope に寄せ、`client_credentials` の `scope` が空になることを
  明示する（決定どおりの姿を記録する）
- 逆に業務スコープを配る方針へ変えるなら、変更点は**登録側**（`validate_scopes`）である

どちらもトークン発行の挙動そのものは変えない。

## 却下した案

- **業務スコープを `clients.scopes` に登録できるようにする。** 教科書的な OAuth の姿だが、
  権限の定義がアプリと IdP の 2 か所に分かれる。どちらが正なのかが運用で必ず問題になる。
  権限を持つのはアプリ側なので、IdP は主体の同一性（`sub` / `client_id`）を正しく渡すことに
  徹する。
- **権限コードをアクセストークンの scope に載せる。** 権限コードはこの IdP 自身の API を守る
  ためのものであり、他のリソースサーバの権限体系ではない。混ぜると、IdP の管理権限が外部
  アプリの認可判断に流れ込む。
