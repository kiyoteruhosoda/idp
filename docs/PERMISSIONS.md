# 権限一覧（権限コード）

assay の管理機能アクセス制御に使う**権限コード（permission code）**の一覧。利用者にもクライアントにも付与する。
認可は**ロールではなく scope（権限コード値）**で行う（`CLAUDE.md`「権限管理」）。

- 設計判断: `docs/adr/0006-admin-permission-model.md`（権限モデル）／
  `docs/adr/0009-multi-tenant-architecture.md` §4（マルチテナントでの scope・判定）／
  `docs/adr/0037-management-api-access-tokens-and-permission-set.md`（管理トークンと細粒度コード・含意）
- 付与・剥奪の手順: `docs/OPERATIONS.md`「利用者に管理権限を付与／剥奪したいとき」
- API エンドポイント仕様: 自動生成の OpenAPI（`/api/openapi.json`・Swagger UI `/api/docs`）が唯一の出所

> **注意**: ここでいう権限コードは OIDC の `scope`（`openid`/`profile`/`email`。トークン claim 制御）とは
> **別軸**である。権限コードは内部認可であり、OIDC Discovery の `scopes_supported` には載せない（ADR-0006 §7）。

> **包括的な管理権限（`idp.system.admin` / `idp.tenant.admin`）を保有できるのは利用者だけである。**
> 機械（`client_credentials` で認証するクライアント）は `client_permissions` に**細粒度コード**を持てて、
> 管理 API を叩ける（ADR-0037）。⚠ **包括コードだけは持てない** ——DB の CHECK 制約
> （`client_permissions_no_blanket_admin_chk`）・ドメイン（`permission::is_grantable_to_client`）・
> アプリ層の 3 か所で拒む。機械の資格情報は人のものより長く生き、失効の導線も弱いためである。
> 機械が取る管理トークンは `sub_type=client` である。人も機械も管理 API には管理トークン（Bearer）で入り、
> 判定はどちらも `ManagementTokenService::authorize` が保有コードの含意（`domain::permission::implies`）で
> 行う。違うのはトークンの得方だけで、管理コンソール（web）は SSO セッションを `POST /internal/admin/token` で
> 交換し（保有コードは `AdminAccessService` が集める）、機械は `client_credentials` で得る。

---

## 権限コード一覧

許可値の単一の出所は `permissions` マスタテーブル（seed は `migrations/0002_seed_master_data.up.sql`、
細粒度コードは `0045_management_api_permissions`・`0048_resource_indicators`・`0053_smtp_settings_permission`・
`0054_applications` の各マイグレーション）。コード定数と**含意関係**は `crates/core/src/domain/permission.rs`
が単一の出所である（DB に含意表は持たない。ADR-0037）。

### 包括コード（利用者だけが持てる）

| 権限コード | 通称 | scope（適用範囲） | 含意する範囲 |
|---|---|---|---|
| `idp.system.admin` | 全体管理者（システム管理者） | **root テナントのみ** | **すべての権限コード**（`idp.tenant.admin`・細粒度コード・`idp.smtp:*` を含む）。加えて、これでしか通らないシステム管理操作（下の「`idp.system.admin` が必要」） |
| `idp.tenant.admin` | テナント管理者 | 対象テナント | 下表の**テナント管理の細粒度コードすべて**（`TENANT_MANAGEMENT_CODES`）。⚠ `idp.system.admin` と `idp.smtp:*` は含意しない |

### 細粒度コード（利用者にもクライアントにも付与できる）

リソース × 読み書き（`<リソース>:read` / `<リソース>:write`）の形で、**`:write` は同じリソースの `:read` を含意する**。

| リソース | `:read` でできること | `:write` でできること（`:read` を含む） | `idp.tenant.admin` が含意するか |
|---|---|---|---|
| `idp.users` | 利用者の検索・取得、有効な refresh token の本数、ログイン識別子の一覧 | 利用者の作成・プロフィール更新・状態変更・削除、パスワード再発行、MFA 解除、ロック解除、トークンの一括失効、ログイン識別子の追加・更新・削除・主メールへの昇格 | する |
| `idp.members` | メンバー（人）の一覧・1 件の取得 | メンバーの一時停止・再開・解除（ゲストの追放）、管理者メモ、招待の作成 | する |
| `idp.clients` | クライアント（RP・サービスアカウント）の一覧・取得・状況一覧、クライアントの保有権限の参照 | クライアントの登録・更新・削除・シークレット再発行、サービスアカウントの管理者メモ、**クライアントへの権限の付与・剥奪** | する |
| `idp.applications` | アプリの一覧・取得、いま使える人の一覧、メンバー／サービスアカウントが使えるアプリ | アプリの登録・更新・削除、名乗り（binding）の追加・削除、人・サービスアカウントの割り当てと解除 | する |
| `idp.permissions` | 付与できる権限コード（マスタ）の一覧、利用者の保有権限の参照 | 利用者への権限の付与・剥奪（`idp.system.admin` は別条件。下記） | する |
| `idp.audit` | 監査ログの参照 | （`:write` は無い） | する |
| `idp.keys` | 署名鍵の一覧（公開部分と状態） | 署名鍵の生成・retire・削除 | する |
| `idp.tenant-settings` | 自テナントの表示名とテナントの設定値の参照 | 自テナントの表示名の更新、テナントの設定値の設定・解除 | する |
| `idp.authentication-policies` | 認証ポリシーの一覧 | 認証ポリシーの作成・更新・削除 | する |
| `idp.external-idps` | 外部 IdP 設定の一覧 | 外部 IdP の登録・更新・削除、SAML メタデータ・OIDC discovery の取り込み（解析のみ） | する |
| `idp.saml-service-providers` | SAML SP の一覧 | SAML SP の登録・更新・削除、SP メタデータの取り込み（解析のみ） | する |
| `idp.resources` | 保護リソース（`aud` に入る宛名）の一覧 | 宛名の登録・停止・削除 | する |
| `idp.smtp` | メールの経路（SMTP）の参照 | メールの経路の変更・解除 | ⚠ **しない**（下記「メールの経路の細粒度コード」） |

> ⚠ `idp.permissions:write` は `idp.system.admin` 以外の任意のコード（`idp.tenant.admin` を含む）を利用者へ
> 付与できる。`idp.clients:write` も同様に、包括コード以外の任意の細粒度コードをクライアントへ付与できる。
> どちらも実質 `idp.tenant.admin` に近い重さとして扱う。

### 含意の規則（`domain::permission::implies`）

保有コード `held` が要求コード `required` を満たすのは次のいずれか（判定はこの 1 関数だけが持つ）:

1. 完全一致
2. `held` が `idp.system.admin`（すべてを含意する）
3. `held` が `idp.tenant.admin` で、`required` が `TENANT_MANAGEMENT_CODES` に入っている
4. 同じリソースの `:write` が `:read` を含意する（`idp.users:write` ⊃ `idp.users:read`）

`idp.tenant.admin` は `idp.system.admin` を**含意しない**。これが崩れるとテナント管理者が root 操作へ届く。

### クライアントには包括コードを付けられない（ADR-0037）

`idp.system.admin` / `idp.tenant.admin` は**利用者だけ**が保有できる。クライアント（`client_credentials`）は
`client_permissions` に細粒度コード（`idp.smtp:*` を含む）だけを持てる。DB の CHECK 制約
（`client_permissions_no_blanket_admin_chk`）・ドメイン（`permission::is_grantable_to_client`）・アプリ層
（`ClientPermissionManagementService::grant`）の 3 か所で拒む。

---

## scope（適用範囲）と判定ルール

利用者の権限は `user_permissions` テーブルの `(user_id, permission_code, tenant_id)` で表す。`tenant_id` が
権限の適用範囲（scope）である。クライアントの権限（`client_permissions`）は scope 列を持たず、
クライアントの所属テナント（`clients.tenant_id`）が scope になる。

- **scope は当該テナントのみに及び、配下・系譜のテナントへは一切及ばない**（テナント独立。ADR-0009 §1）。
- `/{tenant_id}/admin/...` へのアクセスは「**要求テナント自身を scope に持つ**保有コードのどれかが、
  要求コードを含意するか」で判定する。祖先・配下は考慮しない。満たさなければ一律 **403**。
  判定は Application 層（管理トークンの発行時に保有コードを集め、`ManagementTokenService::authorize` が
  `implies` で照合する）。Presentation 層は `RequirePerms<P>` extractor で結果だけを受け取る。
- `idp.system.admin` は **root scope でしか存在できない**。DB の CHECK 制約
  `user_permissions_system_admin_scope_chk` とアプリ層（`permission::is_grantable_in_tenant`）の二重防御で強制する。
  したがって root 以外のテナントで `idp.system.admin` が要求を満たすことはない。
- root テナントの `idp.system.admin` 保有者は、含意により root テナント内のテナント管理もすべて行える。
- **`idp.system.admin` の付与・剥奪**: 付与・剥奪のエンドポイント自体は `idp.permissions:write` で保護されるが、
  対象コードが `idp.system.admin` の場合に限り、Application 層
  （`PermissionManagementService::ensure_system_admin_change_allowed`）が「要求テナントが root であること」と
  「**実行者が利用者で、root scope の `idp.system.admin` を保有すること**」を追加で確かめる。満たさなければ 403。
  クライアントは `idp.system.admin` を持てないので、機械からは付与も剥奪もできない。

---

## エンドポイント別の要求権限

要求コードは各ハンドラの `RequirePerms<P>` の型パラメータで決まる（マーカ型とコードの対応は
`crates/api/src/presentation/admin.rs` の `permission_markers!`。パスは `crates/api/src/presentation/router.rs`）。
以下のパスは `/{tenant_id}` を前置する。**各操作の要求・応答・403 の説明は OpenAPI（Swagger UI `/api/docs`）が
正本**で、ここではどの権限で何ができるかだけを書く。画面は管理コンソール（web の `/{tenant_id}/admin/...`）。

### 管理コンソールに入る（`idp.tenant.admin` の完全一致または含意が必要）

| 管理 API | 画面 |
|---|---|
| `GET /admin/whoami` | 管理コンソールのすべての画面（web は画面ごとに whoami で身元を確かめ、403 なら権限不足の画面を出す） |

whoami は `idp.tenant.admin`（`RequirePerms<IdpAdmin>`）を要求する唯一の管理 API である。細粒度コードは
`idp.tenant.admin` を含意しないので、**細粒度コードだけを持つ利用者は管理コンソールに入れない**。
細粒度コードの主な使い道は、システム用クライアント（機械）に管理 API の一部だけを呼ばせることである。

### 細粒度コードが必要（`idp.tenant.admin` も、root では `idp.system.admin` も含意で通る）

| 権限コード | 呼べる管理 API | 画面 |
|---|---|---|
| `idp.users:read` | `GET /admin/users`（検索）、`GET /admin/users/{user_id}`、`…/active-tokens`、`GET …/login-identifiers` | アカウント（人の詳細） |
| `idp.users:write` | `POST /admin/users`、`PATCH /admin/users/{user_id}`・`…/profile`、`DELETE /admin/users/{user_id}`、`…/password-reset`・`…/mfa-reset`・`…/token-reissue`・`…/unlock`、ログイン識別子の `POST`・`PATCH`・`DELETE`・`…/primary-email` | 利用者の作成、アカウント（人の詳細）のパスワード再発行・MFA 解除・ロック解除・トークン再発行・プロフィール・ログイン識別子 |
| `idp.members:read` | `GET /admin/members`、`GET /admin/members/{user_id}` | アカウント（人の一覧・詳細） |
| `idp.members:write` | `DELETE`・`PATCH /admin/members/{user_id}`、`PUT …/note`、`POST /admin/invitations` | アカウント（人）の一時停止・再開・解除・管理者メモ、招待 |
| `idp.clients:read` | `GET /admin/clients`・`…/status`・`…/{client_id}`、`GET …/{client_id}/permissions`、`GET /admin/service-accounts/{client_id}` | クライアント、アカウント（サービスアカウント）、状況 |
| `idp.clients:write` | `POST /admin/clients`、`PATCH`・`DELETE /admin/clients/{client_id}`、`…/secret`、`POST`・`DELETE …/{client_id}/permissions…`、`PUT /admin/service-accounts/{client_id}/note` | クライアントの登録・編集・削除・シークレット再発行・権限の付与と剥奪、サービスアカウントの作成・管理者メモ |
| `idp.applications:read` | `GET /admin/applications`・`…/{application_id}`・`…/current-users`・`…/binding-candidates`、`GET /admin/members/{user_id}/applications`、`GET /admin/service-accounts/{client_id}/applications` | アプリ、アカウントの詳細の「使えるアプリ」 |
| `idp.applications:write` | `POST /admin/applications`、`PUT`・`DELETE …/{application_id}`、`…/bindings…`、`…/assignments…` | アプリの登録・編集・削除・名乗り、人・サービスアカウントの割り当てと解除 |
| `idp.permissions:read` | `GET /admin/permissions`、`GET /admin/users/{user_id}/permissions` | 利用者の権限 |
| `idp.permissions:write` | `POST /admin/users/{user_id}/permissions`、`DELETE …/permissions/{permission_code}` | 利用者の権限の付与・剥奪 |
| `idp.audit:read` | `GET /admin/audit-logs` | 監査ログ |
| `idp.keys:read` | `GET /admin/signing-keys` | 署名鍵 |
| `idp.keys:write` | `POST /admin/signing-keys`、`…/{kid}/retire`、`DELETE …/{kid}` | 署名鍵の生成・retire・削除 |
| `idp.tenant-settings:read` | `GET /admin/settings/tenant`、`GET /admin/settings/tenant/keys` | 設定（テナント設定の区画） |
| `idp.tenant-settings:write` | `PATCH /admin/settings/tenant`、`PUT`・`DELETE /admin/settings/tenant/keys/{key}` | 設定（テナント設定の区画）の保存 |
| `idp.authentication-policies:read` | `GET /admin/authentication-policies` | 認証ポリシー |
| `idp.authentication-policies:write` | `POST /admin/authentication-policies`、`PUT`・`DELETE …/{policy_id}` | 認証ポリシーの作成・更新・削除 |
| `idp.external-idps:read` | `GET /admin/external-idps` | 外部 IdP |
| `idp.external-idps:write` | `POST /admin/external-idps`・`…/import-metadata`・`…/import-discovery`、`PATCH`・`DELETE …/{id}` | 外部 IdP の登録・編集・削除・取り込み |
| `idp.saml-service-providers:read` | `GET /admin/saml-service-providers` | SAML クライアント |
| `idp.saml-service-providers:write` | `POST /admin/saml-service-providers`・`…/import-metadata`、`PUT`・`DELETE …/{id}` | SAML クライアントの登録・更新・削除・取り込み |
| `idp.resources:read` | `GET /admin/resources` | 保護リソース |
| `idp.resources:write` | `POST /admin/resources`、`PATCH`・`DELETE …/{resource_id}` | 保護リソースの登録・停止・削除 |

### メールの経路（SMTP）の細粒度コード（ADR-0051・ADR-0058 §8）

`idp.smtp:read` / `idp.smtp:write` は**どのテナントでも付与できる**（ADR-0058 §8 で ADR-0051 §3 の
「root scope でしか持てない」を覆した）。届くのは **scope のテナントのメールの経路だけ**である。
⚠ `idp.tenant.admin` は**含意しない**（`TENANT_MANAGEMENT_CODES` に入っていない）——含意させると、
root のテナント管理者が全体の経路へ届く。付与は明示の 1 枚とする（`idp.system.admin` は含意で通る）。

| 権限コード | 呼べる管理 API | 画面 |
|---|---|---|
| `idp.smtp:read` | `GET /admin/settings/smtp`（テナントの経路。経路を持たなければ `inherited: true` で項目は空＝**全体の値は見せない**）、`GET /admin/system-settings/smtp`（全体の経路。⚠ **要求テナントが root でなければ 403**） | 設定（メールの区画） |
| `idp.smtp:write` | `PUT`・`DELETE /admin/settings/smtp`、`PUT /admin/system-settings/smtp`（root のみ） | 設定（メールの区画）の保存・解除 |

パスワードの平文は返さない。テナントの経路は**塊**で解決し、欠けた項目を全体の値で埋めない（埋めると全体の
パスワードがテナントのサーバへ送られる）。全体の経路の口は SMS・ランタイム設定・再起動には届かない。

### `idp.system.admin` が必要（全体管理者のみ。細粒度コードへは分割しない）

| 呼べる管理 API | 画面 |
|---|---|
| `/admin/tenants…`（テナントの作成・一覧・取得・更新・削除、子テナント管理者のパスワード再発行、ドメインの割り当て） | テナント |
| `GET`・`PUT /admin/system-settings`、`PUT /admin/system-settings/runtime` | 設定（システム設定の区画） |
| `POST /admin/restart` | 設定（再起動） |
| `GET /admin/logs`（エラー・警告ログ。テナント横断の運用情報） | エラー・警告ログ |

- テナント作成時に、**作成者自身**を新テナントのブートストラップ管理者として登録する（ACTIVE な
  GUEST メンバーシップ＋新テナント scope の `idp.tenant.admin`。ADR-0009 §5）。作成者は自身の SSO
  セッションのまま新テナントで正式な管理者を登録・付与し、最後に自身のゲストメンバーシップを解除して
  離脱する。離脱後は作成者（root の system admin）は当該テナント内部を操作できない。

### 権限コードを要求しない

| 管理 API・経路 | 条件 |
|---|---|
| `GET /admin/accounts`（人とサービスアカウントの一覧） | 有効な管理トークン（`ManagementPrincipal`）。並べるのは読める種別だけ（人は `idp.members:read`、サービスアカウントは `idp.clients:read`。ADR-0065） |
| `GET /admin/applications/self/users`（RP の定期照合が読む名簿） | 有効な管理トークン（`ManagementPrincipal`）。呼んできたサービスアカウントが名乗りとして結び付いたアプリの名簿だけを返し、結び付きが無ければ 403（ADR-0057 / ADR-0059） |
| `POST /invitations/accept`（招待の承諾。管理 API ではない） | 被招待者が所属元テナントのログイン済みセッションで招待トークンを提示する（`AuthenticatedUser` extractor。ADR-0009 §3） |

---

## テナント管理者ができること・できないこと（ゲスト参加先での境界）

ADR-0009 §3・§4 より、参加先テナントの管理者（`idp.tenant.admin`）が**ゲストに対して行えるのは以下のみ**:

- メンバーシップの解除（ゲストの追放）
- 参加先テナントを scope とする権限の付与・剥奪（`idp.system.admin` を除く）

**行えないこと**: ゲストの `users` レコードの操作（パスワードリセット・ステータス変更・MFA 設定・
プロフィール変更等）。これらは**所属元テナントの管理者と本人のみ**が行える。

テナント間に権限の優劣・移譲・継承は存在しない。所属元テナントの管理者であっても、ゲスト参加先テナントを
scope とする権限は付与できない（scope 完全一致・テナント独立の帰結）。

---

## ブートストラップ（最初の管理者）

- 初期管理者 `admin@example.com`（root 所属）に `idp.system.admin`（scope = root）を seed で DB 直接投入する
  （`migrations/0002_seed_master_data.up.sql`）。
- **アプリ経由で「最初の `idp.system.admin`」を作成する導線は存在しない**（ADR-0009 §4）。
- 権限の付与・剥奪の手順は `docs/OPERATIONS.md`「利用者に管理権限を付与／剥奪したいとき」を参照。
