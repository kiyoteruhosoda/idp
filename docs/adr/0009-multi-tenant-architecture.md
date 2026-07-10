# ADR-0009: マルチテナントアーキテクチャ

- **Status**: Accepted
- **Date**: 2026-07-09
- **Revised**: 2026-07-10 — `/root` エイリアスと `/admin` 横断名前空間を廃止し、URL を root 含め完全一律化。
  権限判定を「祖先サブツリー包含」の一律判定へ一本化。セッション境界・api/web 分割との整合・
  マイグレーション方針・WebAuthn 制約を明記。
- **関連**: `docs/adr/0006-admin-permission-model.md`、`docs/adr/0007-api-web-service-split.md`、
  `docs/OIDC_INPUT.md`、`CLAUDE.md`「権限管理」「DB モデリング」

---

## Context

現状の IdP は「単一組織・単一認証ドメイン」前提で設計されており、すべてのユーザー・クライアントが
フラットな同一空間に存在する。複数の組織（テナント）を 1 つの IdP インスタンスでホストするには、
以下が欠けている。

1. **テナントの概念がない** — ユーザー・クライアントを組織単位で分離する器が存在しない。
2. **管理者の粒度が粗い** — `idp.admin` は全データへのアクセスを与えており、特定テナントのみを
   管理する「テナント管理者」を表現できない。
3. **テナント間分離がアプリ層で強制されない** — リポジトリ・ユースケースにテナント境界がない。
4. **OIDC エンドポイントがテナント非対応** — `/authorize` 等がどのテナントのフローかを判別できない。
5. **管理・設定 UI が不在** — システム設定・テナント設定・ユーザー設定の画面が定義されていない。

本 IdP は MVP 段階であり、本番運用データは存在しない。ただしスキーマ変更は既存ベースライン
（`0001_baseline` 〜）を書き換えず、**追加マイグレーション（expand/contract）で行う**（§10）。

---

## Decision

### 1. テナントをファーストクラスエンティティとして新設（階層対応・UUID 識別）

テナントは UUID（`id`）で一意識別する。`name` は人間可読の表示名であり、URL・一意識別には使用しない。

```sql
CREATE TABLE tenants (
    id               CHAR(36)     NOT NULL,
    parent_tenant_id CHAR(36)     NULL
        COMMENT 'NULL は root テナントのみ。それ以外は必ず親テナントを持つ',
    name             VARCHAR(255) NOT NULL COMMENT '表示名。一意制約なし・URL には使わない',
    status           VARCHAR(16)  NOT NULL DEFAULT 'ACTIVE',
    created_at       DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at       DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    CONSTRAINT tenants_status_chk CHECK (status IN ('ACTIVE', 'DISABLED')),
    CONSTRAINT tenants_parent_fk FOREIGN KEY (parent_tenant_id)
        REFERENCES tenants(id) ON DELETE RESTRICT
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
```

**root テナント**: `parent_tenant_id = NULL`、固定 UUID（`00000000-0000-0000-0000-000000000000`）。
これのみ NULL を許容し、seed で挿入する。root は階層の最上位であり、すべてのテナントは root の
配下（サブツリー）に属する。

**root テナントの位置づけとアクセス**:
- root テナントは階層の最上位であると同時に、通常の OIDC フローも提供する実テナントである。
- root は他のテナントと同じく **UUID で識別**し、`/{root_uuid}/authorize`・`/token`・`/userinfo` 等の
  エンドポイントを通常どおり利用する。**root 専用の特別な URL・エイリアスは設けない。**
- root を含むすべてのテナントで URL 構造は一律であり、アクセス可否は権限判定のみで決まる（§3・§8）。

**階層ルール**:
- root テナントは seed のみが作成する（アプリ経由では作成不可）。
- テナント作成は「親テナント配下への子テナント作成」として一律に扱う。トップレベルのテナントは
  root テナントの子として作成する。
- テナント削除は「配下に子テナントが存在しない」かつ「**当該テナント自身に**ユーザー/クライアントが
  存在しない」場合のみ許可する（`ON DELETE RESTRICT` で DB レベルでも保護）。
- **root テナントは削除できない**（アプリ層で明示的に禁止する。seed の初期管理者が帰属するため
  実質的にも削除条件を満たさないが、明文の禁止ルールとして扱う）。
- 親付け替え（`parent_tenant_id` の更新）は禁止する。
- **DISABLED は配下サブツリーへ伝播する**。テナント解決時（§6）に祖先チェーンのいずれかが
  DISABLED であれば、当該テナントも無効として 404 を返す。祖先チェーンは権限判定（§3）でも
  辿るため、追加コストは小さい。

### 2. users・clients をテナントスコープ化

`users` / `clients` テーブルに `tenant_id CHAR(36) NOT NULL` を追加する。
`UNIQUE` 制約は `(tenant_id, email)` / `(tenant_id, client_id)` とし、テナントを跨いだ同一値を許容する。

| テーブル | カラム | UNIQUE 制約 |
|---|---|---|
| `users` | `tenant_id CHAR(36) NOT NULL` | `(tenant_id, email)` / `(tenant_id, preferred_username)` |
| `clients` | `tenant_id CHAR(36) NOT NULL` | `(tenant_id, client_id)` |

外部キー: `REFERENCES tenants(id) ON DELETE RESTRICT`

初期管理者 `admin@example.com` は seed で root テナントに帰属させる。

同一メールアドレスは複数テナントにそれぞれ独立したユーザーレコードとして存在しうる
（`sub` はユーザーレコードごとに異なる）。

### 3. 権限スコープと権限判定（一律判定）

`user_permissions.tenant_id` は常に実在するテナント ID を指す外部キーであり、権限の適用範囲（scope）を
表す。scope は「そのテナントおよびその配下サブツリー」に及ぶ。root テナントの scope はサブツリーが
全テナントに一致するため、システム全体を意味する。

既存の `granted_at` カラムおよび `users` / `permissions` への外部キー（ADR-0006、`0003` マイグレーション）
は維持し、主キーへ `tenant_id` を加える。

```sql
CREATE TABLE user_permissions (
    user_id         CHAR(36)    NOT NULL,
    permission_code VARCHAR(64) NOT NULL,
    tenant_id       CHAR(36)    NOT NULL
        COMMENT '権限の適用範囲（scope）。当該テナントおよびその配下サブツリーに及ぶ',
    granted_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (user_id, permission_code, tenant_id),
    CONSTRAINT user_permissions_user_fk
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT user_permissions_code_fk
        FOREIGN KEY (permission_code) REFERENCES permissions(code) ON DELETE RESTRICT,
    CONSTRAINT user_permissions_tenant_fk
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT user_permissions_system_admin_scope_chk CHECK (
        permission_code <> 'idp.system.admin'
        OR tenant_id = '00000000-0000-0000-0000-000000000000'
    )
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
```

`tenant_id`（scope）は DEFAULT を設けず、常に seed／アプリケーションが明示指定する。

**権限コード**:

| コード | scope | 権限内容 |
|---|---|---|
| `idp.system.admin` | root テナント UUID **のみ**（CHECK 制約＋アプリ層で強制） | システム全体権限。全テナントの管理、システム設定の閲覧・変更、`idp.system.admin` の付与・剥奪 |
| `idp.tenant.admin` | 対象テナント UUID | 当該テナントおよび配下サブツリーの管理（ユーザー・クライアント・子テナント・テナント設定） |

`idp.system.admin` を root 以外の scope で保有する状態は意味を定義しない（挿入自体を CHECK 制約と
アプリ層のバリデーションで拒否する）。

**一律の権限判定**:
- `/{tenant_id}/admin/...` へのアクセスは、ユーザーが「**当該テナント、またはその祖先テナント**を
  scope に持つ admin 権限」を保有するかで判定する。保有しなければ一律 **403** を返す。
- root だけの特別な URL・特別な判定分岐は設けない。root テナントに対する操作も、上記の一律判定に
  従う（root を scope に持つ `idp.system.admin` 保有者のみがアクセスできる）。
- **システム設定の閲覧・変更は `idp.system.admin` に含まれる権限**であり、これを保有しないユーザーには
  一律 403 となり、画面自体が見えない。
- **`idp.system.admin` の付与・剥奪は `idp.system.admin` 保有者のみ**が実行できる。それ以外の権限では
  付与操作自体が 403 となる。
- **初期の `idp.system.admin` は seed（DB 直接投入）で作成する。** アプリ経由で最初の
  `idp.system.admin` を作成する導線は存在しない。

コード上、権限 scope は単一の値オブジェクト `TenantScope(TenantId)`（サブツリー基点となるテナント ID）
で表現する。root の特別バリアントは設けず、判定は「要求テナントが権限 scope のサブツリーに含まれるか」
に一本化する（root scope はサブツリーが全体に一致するだけで、判定ロジック上の分岐はない）。
システム設定等の追加権限の有無は `permission_code`（`idp.system.admin` か否か）で判定する。

### 4. テナント作成フロー

テナント作成は親テナント配下への子テナント作成として一律に扱う（トップレベルは root の子）。
作成時に必要な情報は以下の 3 点のみ。

| 入力 | 備考 |
|---|---|
| テナント名（`name`） | 表示名。`id`（UUID）はシステムが自動採番する |
| 管理者メールアドレス | 作成と同時に、新テナントを scope とする `idp.tenant.admin` を付与した管理者ユーザーを生成する |
| パスワード | 自動生成（32 文字以上のランダム文字列）。レスポンスに一度だけ平文で返す |

- パスワードは argon2id でハッシュして `users.password_hash` へ保存する。
- 自動生成パスワードで作成された管理者ユーザーには `must_change_password = TRUE` を付与する。
  初回ログイン時は認可フローを完了させずパスワード変更（リセット）画面へ強制誘導し、変更完了までは
  他の操作を許可しない。

```sql
must_change_password TINYINT(1) NOT NULL DEFAULT 0
```

- パスワード変更（リセット）画面を新設する。当面は「ログイン済みユーザーが現行パスワードで
  認証したうえで新パスワードを設定する」フローに限定する。
- テナント作成 API のレスポンスには `generated_password` フィールドを含める（一度限り）。
  テナント作成者が確認して管理者へ別途通知する。`generated_password` はログ・監査ログに出力しない。

### 5. OIDC エンドポイントのテナント対応（テナント UUID プレフィクス方式・一律）

すべてのテナント（root を含む）で URL 構造は一律とし、テナント UUID をパスに含める。

```text
GET  /{tenant_id}/.well-known/openid-configuration
GET  /{tenant_id}/authorize
POST /{tenant_id}/token
GET  /{tenant_id}/userinfo
POST /{tenant_id}/introspect
POST /{tenant_id}/revoke
GET  /{tenant_id}/jwks.json
```

**issuer（`iss`）**:
- 発行トークンおよび discovery の `issuer` は `<基底 issuer>/<tenant_id>` を canonical 形式とする。
  基底 issuer（`https://<host>` 部分）は**設定値（`config.issuer()`）由来**であり、リクエストの
  Host ヘッダから導出しない（host header injection の余地を作らない）。
- 現行実装は起動時に固定 issuer 文字列を各サービス（Token/UserInfo/Logout/Introspection/Discovery 等）へ
  配布しているため、per-tenant 化は「基底 issuer + テナント ID をリクエスト毎に合成する」構造への
  変更を伴う（影響範囲は Consequences 参照）。
- リソースサーバは `iss` の厳密一致を検証し、A テナント発行トークンの B テナントへの流用を防ぐ。
- `/{tenant_id}/.well-known/openid-configuration` は OpenID Connect Discovery 1.0 準拠の形式
  （`{issuer}/.well-known/openid-configuration`）である。

**WebAuthn（Passkey）の制約**:
- WebAuthn の RP ID は**ドメイン（ホスト）単位**であり、パスを含められない。現行実装は issuer から
  origin/RP ID を導出しているため、per-tenant issuer 化にあたっては「RP ID・origin は基底 issuer の
  ホストから導出する（テナントパスを含めない）」よう明示的に分離する。
- したがってパスキーは WebAuthn の仕組み上はホスト単位で登録され、テナント分離は
  「クレデンシャル ⇔ ユーザー ⇔ テナント」の紐付け（アプリ層）で実現する。

**管理エンドポイント（すべて `/{tenant_id}/admin/...` に一律配置）**:

```text
/{tenant_id}/admin/tenants                 GET/POST          子テナント一覧・子テナント作成
/{tenant_id}/admin/tenants/{child_id}      GET/PATCH/DELETE  子テナント詳細・更新・削除
/{tenant_id}/admin/users                   GET/POST          当該テナント直属のユーザー管理
/{tenant_id}/admin/clients                 GET/POST          当該テナント直属のクライアント管理
/{tenant_id}/admin/settings                GET/PATCH         テナント設定（および system.admin 保有時はシステム設定）
```

- トップレベルのテナント作成は `POST /{root_uuid}/admin/tenants`（root の子作成）として行う。
- `GET /{tenant_id}/admin/tenants` は当該テナントの**直下の**子テナント一覧を返す。
- `GET /{tenant_id}/admin/users` / `admin/clients` も**当該テナント直属**のリソースのみを返す。
  子テナントのユーザー・クライアントは子テナントの URL（`/{child_id}/admin/...`）で管理する
  （祖先の admin 権限はサブツリーに及ぶため、同じ管理者がそのままアクセスできる）。
- いずれのルートも §3 の一律判定で保護され、権限 scope が要求テナントを含まなければ 403 を返す。
  `/admin/...` という特別な横断名前空間や root 専用ルートは設けない。

**テナント外パス（プレフィクスなしで残すもの）**:
`/healthz`・`/readyz`・`/api/docs`・`/api/openapi.json`、および web→api の内部 API `/internal/*`（§7）は
テナントプレフィクスを付けない。

**ルーティング衝突の回避**: axum（0.8 / matchit）の router はパスセグメントに正規表現制約を
課せないため、次の 2 段で固定パスとテナントルートを区別する。
1. matchit は同一階層で**静的セグメントをパラメータより優先マッチ**する仕様であり、`/healthz` 等の
   固定パスは `/{tenant_id}` に吸われない。
2. `:tenant_id` セグメントの UUID 形式（36 文字ハイフン区切り）検証は `TenantResolver`（§6）が行い、
   パース失敗・未知の値は 404 を返す。

### 6. テナント解決 Middleware

axum の `from_fn` middleware として `TenantResolver` を追加する。リクエストパスの `:tenant_id`
セグメントを UUID としてパースし（失敗は 404）、`tenants` を検索して `Extension<ResolvedTenant>` として
注入する。テナントが存在しない・DISABLED・**祖先チェーンに DISABLED を含む**場合は 404 を返す。
root も同一経路で UUID として解決し、特別分岐は設けない。

```text
Presentation (Router) → TenantResolver middleware → Handler
                              ↓
                    Extension<ResolvedTenant>
```

id→tenant 解決（祖先チェーン含む）はホットパスのため、TTL 付きインメモリキャッシュ + 更新時
invalidation を採用する（既存に汎用キャッシュ基盤はないため新設。`InMemoryLoginRateLimiter` と同様、
trait 越しに注入して単体インスタンス前提とし、スケールアウト時に差し替える）。

### 7. アプリ層のテナント分離強制

- すべての Repository trait のメソッドシグネチャに `tenant_id: &TenantId` を付与する。
- Application（ユースケース）は `TenantId` を保持した `TenantContext` を受け取り、リポジトリ呼び出しに
  必ず渡す。
- `RequirePerms` extractor は §3 の一律判定（要求テナントが権限 scope のサブツリーに含まれるか）を担う。
  要求テナントは `Extension<ResolvedTenant>`（§6）から取得する。
- MariaDB に RLS はないため、アプリ層が唯一の分離防御線となる。統合テストで「他テナントのデータが
  取得できないこと」を検証する negative test を必須ケースとする。

**セッションとテナントの関係（認証と認可の分離）**:
- **認証（ログイン・SSO セッション）はユーザーの帰属テナントに対して**行う。`auth_sessions` に
  `tenant_id` を追加し、`/{tenant_id}/authorize` で開始したフローのテナントを保持する。ログイン時の
  ユーザー検索は `(tenant_id, email)` で行う。`sso_sessions` はユーザーに紐づき、ユーザーが
  テナントに紐づくため、セッションの帰属テナントは一意に定まる。
- **OIDC フロー（authorize/token/userinfo）では「セッションユーザーの帰属テナント = 要求テナント」を
  検証**する。不一致の SSO セッションは当該テナントのフローでは未認証として扱う（cookie は
  ホスト単位で送られてくるため、この検証がテナント境界となる）。
- **admin ルートでは帰属テナントの一致を要求しない**。祖先テナントの管理者が子テナントの
  `/{child_id}/admin/...` へアクセスするのは正当なユースケースであり、可否は §3 の scope 判定のみで
  決まる（認証は自テナントで済ませ、認可はサブツリー包含で判定する）。
- cookie（`sso_session_id` 等）は現行どおり `Path=/`（ホスト単位）とする。パスによる cookie 分離は
  祖先管理者のクロステナント操作と両立しないため採らず、境界は上記のサーバ側検証で強制する。
- ログイン試行レートリミット（`InMemoryLoginRateLimiter`）のキーは `(tenant_id, email)` とする。
- `audit_log` に `tenant_id` カラムを追加し、監査イベントをテナント単位で追跡可能にする。

**api/web 分割（ADR-0007）との整合**:
- 画面 URL（§9）は web クレート、API は api クレートが提供する。web はデータ操作を api への
  HTTP 呼び出し（`api_client.rs`）で行うため、テナントコンテキストを web→api へ明示的に伝搬する。
- `/internal/*`（web→api 内部 API）はテナントプレフィクスを付けず、`crates/contracts` の
  リクエスト DTO（`InternalAuthenticateRequest` 等）へ `tenant_id` フィールドを追加して伝える
  （`(tenant_id, email)` 一意化により、テナント指定のない認証は成立しない）。
- `/{tenant_id}/admin/*`（管理 API）は web の `api_client.rs` がパスにテナント ID を組み込んで呼ぶ。

### 8. 権限による一律のアクセス制御

管理・設定操作は URL 上で特別扱いせず、`/{tenant_id}/admin/...` に一律配置したうえで、§3 の権限判定で
アクセス可否を決める。

- `RequirePerms` は「要求テナントを scope に含む admin 権限」の有無で判定し、無ければ 403 を返す。
- `idp.tenant.admin` 保有者は自テナントおよび配下サブツリーの管理（ユーザー・クライアント・子テナント・
  テナント設定）を行える。祖先・他系統のテナントへアクセスすると 403 となる。
- `idp.system.admin` 保有者（scope = root）は全テナントを管理でき、加えてシステム設定の変更と
  `idp.system.admin` の付与・剥奪を行える。
- **システム設定は `idp.system.admin` 固有の権限**であり、保有しないユーザーには一律 403 となって
  画面が見えない。root だけの特別 URL は存在せず、可視性は純粋に権限で決まる。

### 9. 管理・設定画面の構成

| 画面 | URL | 表示条件（権限） | 主な機能 |
|---|---|---|---|
| **テナント設定** | `/{tenant_id}/admin/settings` | 当該テナントを scope に含む admin 権限 | テナント表示名（`name`）の変更、テナント有効/無効、子テナント作成・管理 |
| **システム設定** | `/{tenant_id}/admin/settings`（同一画面のシステム区画） | `idp.system.admin` のみ | SMTP 設定（外部サーバー）、システム全体の設定値管理、`idp.system.admin` の付与・剥奪 |
| **ユーザー設定** | `/{tenant_id}/settings` | SSO ログイン済み（自分のみ） | パスワード変更、MFA 設定（TOTP・Passkey）、言語設定、SSO アカウント連携 |

- テナント設定画面のシステム区画（SMTP 等）は `idp.system.admin` 保有時のみ描画・編集可能とする。
  保有しないユーザーには当該区画は表示されず、対応 API も 403 を返す。
- メール配送を前提とするセルフサービスのパスワードリセット（忘失時再設定）は SMTP 設定完了を前提と
  するため後続タスクとする。本 ADR の範囲は「ログイン済みユーザーによるパスワード変更画面」までとする。

### 10. マイグレーション方針

既存マイグレーション（`0001` 〜）は書き換えない。sqlx はマイグレーションのチェックサムを
`_sqlx_migrations` で検証するため、適用済みファイルの改変は全環境で不整合を起こす。
マルチテナント化は**追加マイグレーション（次版以降の連番）**で行い、`.claude/skills/db-migration/` の
ルール（up/down 対、冪等 seed、expand/contract）に従う。

NOT NULL カラム追加と UNIQUE 貼り替えは expand/contract で段階投入する
（例: ① `tenants` 作成 + root seed → ② `tenant_id` を NULL 許容で追加 → ③ 既存行を root へ
backfill（MVP では seed 管理者のみ）→ ④ NOT NULL 化 + 複合 UNIQUE へ貼り替え・旧 UNIQUE 削除）。

---

## 段階的実装計画（Phase 分け）

### Phase 1: データ基盤（追加マイグレーション + seed）

1. `tenants` テーブルを作成 + root テナント seed（固定 UUID `00000000-0000-0000-0000-000000000000`）
2. `users` / `clients` へ `tenant_id NOT NULL` を追加（expand/contract。§10）+ 複合 UNIQUE へ貼り替え
3. `users` へ `must_change_password` カラムを追加
4. `user_permissions` へ `tenant_id NOT NULL`（DEFAULT なし）を追加し、主キー・CHECK 制約を再構成
5. `auth_sessions` へ `tenant_id` を、`audit_log` へ `tenant_id` を追加
6. 権限コード seed（`idp.system.admin` / `idp.tenant.admin`）
7. 初期管理者 `admin@example.com` を root テナントへ帰属 + `idp.system.admin`（scope = root UUID）を
   **DB 直接投入で付与**（アプリ経由の付与導線は設けない）

### Phase 2: ドメイン・アプリケーション層

8. `Tenant` ドメインモデル（階層含む）+ `TenantRepository` trait
9. `TenantContext` / `TenantScope` 値オブジェクト
10. Repository trait へ `tenant_id` 引数追加
11. ユースケースの `TenantContext` 対応（OIDC フローの「帰属テナント = 要求テナント」検証を含む）
12. `TenantResolver` middleware（UUID 解決・祖先 DISABLED 伝播）+ `RequirePerms` の一律 scope 判定
    （祖先サブツリー包含）
13. per-tenant issuer 合成（基底 issuer + tenant_id）と WebAuthn RP ID の基底ホスト分離

### Phase 3: プレゼンテーション層・管理 API

14. `/{tenant_id}/...` ルーティング（静的パス優先 + TenantResolver での UUID 検証）
15. `crates/contracts` DTO への `tenant_id` 追加と web `api_client.rs` のテナント対応
16. 管理 API（`/{tenant_id}/admin/tenants` ほか）+ テナント作成時の管理者自動生成・パスワード自動生成・`must_change_password` 付与
17. パスワード変更（リセット）画面の新設 + 初回ログイン時の強制変更誘導
18. テナント管理コンソール（`/{tenant_id}/admin/`）— ユーザー・クライアント・子テナント管理
19. 設定画面（`/{tenant_id}/admin/settings`）— テナント設定 + `idp.system.admin` 保有時のシステム設定区画
20. ユーザー設定画面（`/{tenant_id}/settings`）— パスワード変更・MFA・言語設定
21. 統合テスト（テナント間分離・権限境界・階層・一律権限判定・セッションのテナント境界の検証）

---

## Consequences

**Positive**

- root を含め URL 構造が完全に一律で、アクセス可否は権限判定のみで決まるため、ルーティングと認可の
  責務が明確に分離される。特別分岐がなくテスト・保守が容易。
- `idp.system.admin` の付与を system.admin 保有者に限定し、初期値を DB 直投入とすることで、
  システム全体権限の発行経路が単一かつ明示的になる。scope = root の制約は CHECK 制約でも保証される。
- `iss` はテナント UUID 基点で不変のため、issuer 安定性が構造的に保証される。
- 表示名（`name`）は URL・トークン検証に無影響で、自由に変更できる。
- 階層構造により、組織のサブ部門や子会社を同一 IdP インスタンスで表現できる。
- テナントをまたいだデータ漏洩をアーキテクチャレベルで防止できる。
- テナント作成フローが完結しており、管理者が即時アクセス可能（SMTP 不要）。初回強制変更で初期パスワードの残存リスクを低減する。

**Negative / コスト**

- URL・ログにテナント UUID が現れ、人間による判読性は低い（表示名との対応は管理 UI で補う）。
  クライアント設定（redirect_uri 等）に UUID を正確に転記する必要がある。
- 一律の権限判定は「要求テナントが権限 scope のサブツリーに含まれるか」の階層判定を要し、
  祖先探索（または materialized path 等）の実装が必要になる。
- すべての Repository インターフェース変更は広範囲に波及する。issuer を起動時固定で保持している
  各サービス（Token/UserInfo/Logout/Introspection/Discovery/WebAuthn 等）はリクエスト毎の issuer
  合成へ変更が必要。統合テストのハードコードされたパスも全面更新となる。
- パスキー（WebAuthn）はプロトコル上ホスト単位であり、テナント分離はアプリ層の紐付けに依存する。
- 階層の深さ上限はアプリ層で検証する必要がある（循環は親付け替え禁止で対処）。
- 恒久的なセルフサービス・パスワードリセットは SMTP 連携まで提供されない。

**Alternatives considered**

- root 専用 URL・専用管理名前空間（`/admin/...`、`/root/...`）を設ける: URL とアクセス制御の責務が
  混在し、特別分岐（固定パスの優先マッチ保証等）が増えるため却下。URL は一律とし権限判定に一本化する。
- cookie の `Path=/{tenant_id}` によるセッション分離: 祖先テナント管理者による子テナント管理と
  両立しないため却下。境界はサーバ側の「帰属テナント = 要求テナント」検証（OIDC フロー）と
  scope 判定（admin）で強制する。
- テナントごとに DB スキーマ（DB 分離マルチテナント）: Synology DSM/Docker 環境での運用が複雑化するため MVP 範囲外として却下。
- `users.tenant_id` を持たずクライアント単位でテナントを表現する: ユーザーが複数クライアントを持つテナントで整合性を保てないため却下。
- リクエストパラメータでテナントを指定する: エンドポイント識別が曖昧になるため却下。

---

## Follow-ups（後続タスク）

- **セルフサービス・パスワードリセット（忘失時）**: SMTP 設定完了後に実装。ユーザー設定画面に
  「メールによるリセット」フローを追加する。外部 SMTP はシステム設定区画で設定する（ADR 別途）。
- **ワンタイム招待/セットアップトークン**: SMTP 連携後、テナント作成時に平文パスワードを返さず
  トークン配送で管理者本人がパスワードを設定する方式へ移行する。
- **階層 scope 判定の実装方式**: 祖先探索の再帰 CTE か materialized path / closure table かを、
  想定テナント数と判定頻度に応じて選定する。
- **RFC 8414 path-insertion 形式の well-known 提供**: 厳格クライアント連携時に追加する。
- **ゲスト登録 / テナント切り替え**: 別テナントのユーザーをゲスト招待し複数テナントに帰属する UX。
- Phase 1 完了後、`docs/OIDC_INPUT.md` のスキーマ図（§3）にテナント関係を追記する。
- `idp.system.admin` / `idp.tenant.admin` の付与・剥奪を `audit_log` の `event_type` に追加する。
- テナントごとの signing key（`signing_keys` に `tenant_id` 追加）を検討する。
