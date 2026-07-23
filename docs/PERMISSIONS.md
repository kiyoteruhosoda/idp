# 権限一覧（利用者権限コード）

本 IdP の管理機能アクセス制御に使う**利用者権限コード（permission code）**の一覧。
認可は**ロールではなく scope（権限コード値）**で行う（`CLAUDE.md`「権限管理」）。

- 設計判断: `docs/adr/0006-admin-permission-model.md`（権限モデル）／
  `docs/adr/0009-multi-tenant-architecture.md` §4（マルチテナントでの scope・判定）
- 付与・剥奪の手順: `docs/OPERATIONS.md`「利用者に管理権限を付与／剥奪したいとき」
- API エンドポイント仕様: 自動生成の OpenAPI（`/api/openapi.json`・Swagger UI `/api/docs`）が唯一の出所

> **注意**: ここでいう権限コードは OIDC の `scope`（`openid`/`profile`/`email`。トークン claim 制御）とは
> **別軸**である。権限コードは内部認可であり、OIDC Discovery の `scopes_supported` には載せない（ADR-0006 §7）。

---

## 権限コード一覧

許可値の単一の出所は `permissions` マスタテーブル（seed マイグレーション `migrations/0002_seed_master_data.up.sql`）。
コード定数は `crates/core/src/domain/permission.rs`（`SYSTEM_ADMIN` / `TENANT_ADMIN`）に集中管理する。

| 権限コード | 通称 | scope（適用範囲） | 概要 |
|---|---|---|---|
| `idp.system.admin` | 全体管理者（システム管理者） | **root テナントのみ** | システム設定の閲覧・変更、`idp.system.admin` の付与・剥奪、テナントの作成・削除、root テナント自身のテナント管理 |
| `idp.tenant.admin` | **テナント管理者** | **対象テナント** | 当該テナント内の管理：ユーザー・クライアント・テナント設定・メンバー/招待・当該テナント scope の権限付与（`idp.system.admin` を除く） |

**質問への回答**: 全体管理者の権限は `idp.system.admin`、**各テナントの管理者権限は `idp.tenant.admin`** である。

---

## scope（適用範囲）と判定ルール

権限は `user_permissions` テーブルの `(user_id, permission_code, tenant_id)` で表す。`tenant_id` が
権限の適用範囲（scope）である。

- **scope は当該テナントのみに及び、配下・系譜のテナントへは一切及ばない**（テナント独立。ADR-0009 §1）。
- `/{tenant_id}/admin/...` へのアクセスは「**要求テナント自身を scope に持つ**権限を保有するか」の
  **完全一致**で判定する。祖先・配下は考慮しない。保有しなければ一律 **403**。
  （判定は Application 層 `crates/core/src/application/admin_access.rs` の `AdminAccessService::authorize`。
  Presentation 層は `RequirePerms<P>` extractor で結果のみ受け取る）
- `idp.system.admin` は **root scope でしか存在できない**。DB の CHECK 制約
  `user_permissions_system_admin_scope_chk` とアプリ層の二重防御で強制する。
- `idp.system.admin` は root テナント自身のテナント管理を含むため、`idp.tenant.admin` を要求する
  エンドポイントでは**常に代替として許可**される（root の管理者は root テナント内の管理も行える）。
  逆に `idp.system.admin` を要求するエンドポイントでは代替フォールバックしない（system admin 固有）。
- **`idp.system.admin` の付与・剥奪**: 権限付与・剥奪エンドポイント自体は `idp.tenant.admin` で保護されるが、
  付与・剥奪する権限コードが `idp.system.admin` の場合に限り、Application 層
  （`PermissionManagementService::ensure_system_admin_change_allowed`）が**実行者自身も `idp.system.admin` を
  保有すること**を追加検証する。したがって root テナントでは既存の `idp.system.admin` 保有者が
  `idp.system.admin` を付与・剥奪**できる**。単なる `idp.tenant.admin`（system.admin 非保有）では
  `idp.system.admin` を付与・剥奪できず 403 となる。

```
要求権限が idp.tenant.admin のとき許可される保有権限:
  [対象テナント scope の idp.tenant.admin]  または  [root scope の idp.system.admin]（＝要求テナントが root の場合のみ一致）

要求権限が idp.system.admin のとき許可される保有権限:
  [対象テナント scope の idp.system.admin]  ← root 以外の scope では CHECK 制約により存在し得ない
```

---

## エンドポイント別の要求権限

`RequirePerms<P>` の型パラメータで指定する（`crates/api/src/presentation/admin.rs`）。
`IdpAdmin` → `idp.tenant.admin`、`IdpSystemAdmin` → `idp.system.admin`。パスは
`crates/api/src/presentation/router.rs` が出所。多くのエンドポイントは Swagger UI（`/api/docs`）で
詳細を確認できるが、`whoami`・`GET /admin/permissions`（付与可能コード一覧）・SAML SP 管理は
現状 `#[utoipa::path]` 未付与のため OpenAPI/Swagger には現れない（パスは本表・router.rs を参照）。

### `idp.system.admin` が必要（全体管理者のみ）

| 機能 | 概要 |
|---|---|
| テナント管理（`/{tenant_id}/admin/tenants...`） | テナントの作成・一覧・取得・更新・削除。実質 root だけがテナントを作成できる |
| システム設定（`/{tenant_id}/admin/system-settings...`） | システム設定の閲覧・変更 |

- テナント作成時に、**作成者自身**を新テナントのブートストラップ管理者として登録する（ACTIVE な
  GUEST メンバーシップ＋新テナント scope の `idp.tenant.admin`。ADR-0009 §5）。作成者は自身の SSO
  セッションのまま新テナントで正式な管理者を登録・付与し、最後に自身のゲストメンバーシップを解除して
  離脱する。離脱後は作成者（root の system admin）は当該テナント内部を操作できない。

### `idp.tenant.admin` が必要（当該テナントの管理者。`idp.system.admin` でも可＝root テナントに限る）

| 機能 | 概要 |
|---|---|
| クライアント管理（`/{tenant_id}/admin/clients...`） | RP（OIDC クライアント）の登録・一覧・取得・更新・シークレット再発行 |
| SAML SP 管理（`/{tenant_id}/admin/saml-service-providers...`） | SAML Service Provider の登録・一覧・更新・削除・メタデータ取り込み |
| ユーザー管理（`/{tenant_id}/admin/users...`） | 当該テナントを所属元とするユーザーの管理（作成・取得・状態変更・削除・パスワードリセット等） |
| 付与可能な権限コード一覧（`GET /{tenant_id}/admin/permissions`） | `permissions` マスタの一覧（付与フォームの選択肢提示用） |
| 権限の付与・剥奪・参照（`GET`/`POST /{tenant_id}/admin/users/{user_id}/permissions`、`DELETE …/{permission_code}`） | 当該テナント scope の権限を付与・剥奪・参照する（`idp.system.admin` の付与条件は上記「scope と判定ルール」を参照） |
| メンバー管理（`/{tenant_id}/admin/members...`） | ゲストメンバーシップの解除等 |
| 招待管理（`/{tenant_id}/admin/invitations...`） | 招待の作成 |
| テナント設定（`/{tenant_id}/admin/settings/tenant`） | 自テナント（要求テナント自身）の表示名の取得・更新 |
| 署名鍵管理（`/{tenant_id}/admin/signing-keys...`） | 署名鍵の一覧・ローテーション等（秘密鍵は返さない） |
| 監査ログ参照（`/{tenant_id}/admin/audit-logs`） | `audit_log` の絞り込み参照 |
| 管理者身元確認（`/{tenant_id}/admin/whoami`） | ログイン中の管理者身元の確認 |

### 権限を要求しない（ログイン済みであることのみ）

| 機能 | 概要 |
|---|---|
| 招待の承諾（`/{tenant_id}/invitations/accept`） | 被招待者が所属元テナントのログイン済みセッションで招待トークンを提示する（`AuthenticatedUser` extractor。ADR-0009 §3） |

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
