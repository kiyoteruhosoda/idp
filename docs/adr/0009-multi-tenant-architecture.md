# ADR-0009: マルチテナントアーキテクチャ

- **Status**: Accepted
- **Date**: 2026-07-09
- **関連**: `docs/adr/0006-admin-permission-model.md`、`docs/OIDC_INPUT.md`、`CLAUDE.md`「権限管理」「DB モデリング」

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

本 IdP は MVP 段階であり、本番運用データは存在しない。スキーマはマルチテナント対応の定義で新規作成し、
初期データは seed で投入する。

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
これのみ NULL を許容し、seed で挿入する。

**root テナントの位置づけとログインフロー**:
- root テナントはシステム管理用コンテナであると同時に、通常の OIDC フローも提供する実テナントである。
- 初期管理者 `admin@example.com` は root テナントに帰属し、root ユーザーのログインフローを提供する。
  `/{root_uuid}/authorize`・`/token`・`/userinfo` 等は通常どおり機能する。
- root に限り `/root/...` を root UUID への固定エイリアスとして許可する。root 管理者はこの導線で
  ログインし、`/admin/...`（システム管理コンソール）へアクセスする。

**階層ルール**:
- root テナントは seed のみが作成する（アプリ経由では作成不可）。
- `idp.system.admin` 保有者は任意の親テナント配下に子テナントを作成できる。
- `idp.tenant.admin` 保有者は自テナント配下にのみ子テナントを作成できる。
- テナント削除は「配下に子テナントが存在しない」かつ「子テナントにユーザー/クライアントが存在しない」
  場合のみ許可する（`ON DELETE RESTRICT` で DB レベルでも保護）。
- 親付け替え（`parent_tenant_id` の更新）は禁止する。

### 2. users・clients をテナントスコープ化

`users` / `clients` テーブルは `tenant_id CHAR(36) NOT NULL` を含む定義で作成する。
`UNIQUE` 制約は `(tenant_id, email)` / `(tenant_id, client_id)` とし、テナントを跨いだ同一値を許容する。

| テーブル | カラム | UNIQUE 制約 |
|---|---|---|
| `users` | `tenant_id CHAR(36) NOT NULL` | `(tenant_id, email)` / `(tenant_id, preferred_username)` |
| `clients` | `tenant_id CHAR(36) NOT NULL` | `(tenant_id, client_id)` |

外部キー: `REFERENCES tenants(id) ON DELETE RESTRICT`

初期管理者 `admin@example.com` は seed で root テナントに帰属させる。

### 3. 権限スコープ: root テナント UUID を「システム全体」の表現に使う

`user_permissions.tenant_id` は常に実在するテナント ID を指す外部キーとし、root テナントの UUID を
「システム全体権限」の表現に使う。

```sql
CREATE TABLE user_permissions (
    user_id         CHAR(36)    NOT NULL,
    permission_code VARCHAR(64) NOT NULL,
    tenant_id       CHAR(36)    NOT NULL
        COMMENT 'root テナント UUID = システム全体権限。値は必ず seed/アプリが明示指定する',
    PRIMARY KEY (user_id, permission_code, tenant_id),
    CONSTRAINT user_permissions_tenant_fk
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);
```

`tenant_id`（スコープ）は DEFAULT を設けず、常に seed／アプリケーションが明示指定する。

権限コードおよび初期管理者の権限は seed で投入する。

| コード | `tenant_id` の値 | 意味 |
|---|---|---|
| `idp.system.admin` | root テナント UUID | テナント作成・削除・全テナント閲覧・システム設定 |
| `idp.tenant.admin` | 対象テナント UUID | 自テナント内のユーザー・クライアント管理、子テナント作成 |

コード上は `TenantScope::Root` / `TenantScope::Tenant(TenantId)` の enum で表現する。

### 4. テナント作成フロー

テナント作成時に必要な情報は以下の 3 点のみ。

| 入力 | 備考 |
|---|---|
| テナント名（`name`） | 表示名。`id`（UUID）はシステムが自動採番する |
| 管理者メールアドレス | 作成と同時に `idp.tenant.admin` 権限を付与した管理者ユーザーを生成する |
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

### 5. OIDC エンドポイントのテナント対応（テナント UUID プレフィクス方式）

テナント UUID をパスに含める。

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
- 発行トークンおよび discovery の `issuer` は `https://<host>/<tenant_id>` を canonical 形式とする。
- リソースサーバは `iss` の厳密一致を検証し、A テナント発行トークンの B テナントへの流用を防ぐ。
- `/{tenant_id}/.well-known/openid-configuration` は OpenID Connect Discovery 1.0 準拠の形式とする。

システム管理者向けエンドポイント（テナント横断）:

```text
/admin/tenants                       GET/POST          テナント一覧・作成
/admin/tenants/{tenant_id}           GET/PATCH/DELETE  テナント詳細・更新・削除
/admin/tenants/{tenant_id}/children  GET               子テナント一覧
```

**ルーティング衝突の回避**: `/admin/...` 等の固定パスは tenant ルート（`/{tenant_id}/...`）より先に
マッチさせる。`:tenant_id` セグメントには UUID 形式（36 文字ハイフン区切り）のパターン制約を課す。
root の `/root` エイリアスのみ例外とする。

### 6. テナント解決 Middleware

axum の `from_fn` middleware として `TenantResolver` を追加する。リクエストパスの `:tenant_id`
セグメント（UUID）で `tenants` を検索し、`State` に `ResolvedTenant` として注入する。テナントが
存在しない・DISABLED の場合は 404 を返す。`/root` は root UUID への固定エイリアスとして解決する。

```text
Presentation (Router) → TenantResolver middleware → Handler
                              ↓
                    Extension<ResolvedTenant>
```

id→tenant 解決はホットパスのため、TTL 付きインメモリキャッシュ + 更新時 invalidation を採用する。

### 7. アプリ層のテナント分離強制

- すべての Repository trait のメソッドシグネチャに `tenant_id: &TenantId` を付与する。
- Application（ユースケース）は `TenantId` を保持した `TenantContext` を受け取り、リポジトリ呼び出しに
  必ず渡す。
- `RequirePerms` extractor はテナントスコープ権限の検証を担う（テナント管理者が他テナントへ
  アクセスしようとすると 403）。
- MariaDB に RLS はないため、アプリ層が唯一の分離防御線となる。統合テストで「他テナントのデータが
  取得できないこと」を検証する negative test を必須ケースとする。

### 8. システム管理者専用操作の分離

`/admin/...` ルートは `RequirePerms("idp.system.admin")` で保護し、テナント CRUD・全テナント
ユーザー閲覧・システム設定変更のみをここで提供する。テナント管理者は `/{tenant_id}/admin/...` 配下
（自テナント限定）を使う。

### 9. 管理・設定画面の構成

| 画面 | URL | アクセス権限 | 主な機能 |
|---|---|---|---|
| **システム設定** | `/admin/settings` | `idp.system.admin` | SMTP 設定（外部サーバー）、システム全体の設定値管理、デフォルト値の上書き |
| **テナント設定** | `/{tenant_id}/admin/settings` | `idp.tenant.admin`（自テナント） | テナント表示名（`name`）の変更、テナント有効/無効、子テナント作成・管理 |
| **ユーザー設定** | `/{tenant_id}/settings` | SSO ログイン済み（自分のみ） | パスワード変更、MFA 設定（TOTP・Passkey）、言語設定、SSO アカウント連携 |

SMTP 設定はシステム設定画面で管理し、テナント共通の外部 SMTP サーバー接続情報を保持する。
メール配送を前提とするセルフサービスのパスワードリセット（忘失時再設定）は SMTP 設定完了を前提とするため
後続タスクとする。本 ADR の範囲は「ログイン済みユーザーによるパスワード変更画面」までとする。

---

## 段階的実装計画（Phase 分け）

### Phase 1: データ基盤（スキーマ定義 + seed）

1. `tenants` テーブルを作成 + root テナント seed（固定 UUID `00000000-0000-0000-0000-000000000000`）
2. `users` / `clients` を `tenant_id NOT NULL` を含む定義で作成
3. `users` に `must_change_password` カラムを含めて定義
4. `user_permissions` を `tenant_id NOT NULL`（DEFAULT なし）を含む定義で作成
5. 権限コード seed（`idp.system.admin` / `idp.tenant.admin`）
6. 初期管理者 `admin@example.com` を root テナントへ seed + `idp.system.admin`（tenant_id = root UUID）付与

### Phase 2: ドメイン・アプリケーション層

7. `Tenant` ドメインモデル（階層含む）+ `TenantRepository` trait
8. `TenantContext` / `TenantScope` 値オブジェクト
9. Repository trait へ `tenant_id` 引数追加
10. ユースケースの `TenantContext` 対応
11. `TenantResolver` middleware（UUID 解決 + `/root` エイリアス）+ `RequirePerms` のテナントスコープ拡張

### Phase 3: プレゼンテーション層・管理 API

12. `/{tenant_id}/...` ルーティング（UUID パターン制約）+ 固定パス優先度保証
13. テナント CRUD API（`/admin/tenants`）+ テナント作成時の管理者自動生成・パスワード自動生成・`must_change_password` 付与
14. パスワード変更（リセット）画面の新設 + 初回ログイン時の強制変更誘導
15. テナント管理者向け管理コンソール（`/{tenant_id}/admin/`）— ユーザー・クライアント・子テナント管理
16. システム設定画面（`/admin/settings`）— SMTP 等のシステム設定
17. テナント設定画面（`/{tenant_id}/admin/settings`）
18. ユーザー設定画面（`/{tenant_id}/settings`）— MFA・言語設定
19. 統合テスト（テナント間分離・権限境界・階層・root ログインフローの検証）

---

## Consequences

**Positive**

- root テナントが実在するため DB 整合性が自明になる。
- `iss` はテナント UUID 基点で不変のため、issuer 安定性が構造的に保証される。
- 表示名（`name`）は URL・トークン検証に無影響で、自由に変更できる。
- 階層構造により、組織のサブ部門や子会社を同一 IdP インスタンスで表現できる。
- テナントをまたいだデータ漏洩をアーキテクチャレベルで防止できる。
- テナント作成フローが完結しており、管理者が即時アクセス可能（SMTP 不要）。初回強制変更で初期パスワードの残存リスクを低減する。
- ADR-0006 の permission モデルを大幅変更せずにスコープを拡張できる。

**Negative / コスト**

- URL・ログにテナント UUID が現れ、人間による判読性は低い（表示名との対応は管理 UI で補う）。
  クライアント設定（redirect_uri 等）に UUID を正確に転記する必要がある。
- すべての Repository インターフェース変更は広範囲に波及する。
- 階層の深さ上限はアプリ層で検証する必要がある（循環は親付け替え禁止で対処）。
- 恒久的なセルフサービス・パスワードリセットは SMTP 連携まで提供されない。

**Alternatives considered**

- テナントごとに DB スキーマ（DB 分離マルチテナント）: Synology DSM/Docker 環境での運用が複雑化するため MVP 範囲外として却下。
- `users.tenant_id` を持たずクライアント単位でテナントを表現する: ユーザーが複数クライアントを持つテナントで整合性を保てないため却下。
- リクエストパラメータでテナントを指定する: エンドポイント識別が曖昧になるため却下。

---

## Follow-ups（後続タスク）

- **セルフサービス・パスワードリセット（忘失時）**: SMTP 設定完了後に実装。ユーザー設定画面に
  「メールによるリセット」フローを追加する。外部 SMTP はシステム設定画面で設定する（ADR 別途）。
- **ワンタイム招待/セットアップトークン**: SMTP 連携後、テナント作成時に平文パスワードを返さず
  トークン配送で管理者本人がパスワードを設定する方式へ移行する。
- **RFC 8414 path-insertion 形式の well-known 提供**: 厳格クライアント連携時に追加する。
- **ゲスト登録 / テナント切り替え**: 別テナントのユーザーをゲスト招待し複数テナントに帰属する UX。
- Phase 1 完了後、`docs/OIDC_INPUT.md` のスキーマ図（§3）にテナント関係を追記する。
- テナント管理者の権限付与/剥奪を `audit_log` の `event_type` に追加する。
- テナントごとの signing key（`signing_keys` に `tenant_id` 追加）を検討する。
