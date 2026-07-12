# ADR-0009: マルチテナントアーキテクチャ

- **Status**: Accepted
- **Date**: 2026-07-09
- **Revised**: 2026-07-10 —
  1. `/root` エイリアスと `/admin` 横断名前空間を廃止し、URL を root 含め完全一律化。
  2. テナント独立モデル（Entra ID 型）へ変更: 権限 scope のサブツリー伝播を廃止（**完全一致判定**）、
     ユーザーの所属テナントは 1 つに限定し、他テナントへは**招待（ゲスト）**で参加する。
     マイグレーションは行わず、初期 DDL・マスタデータを刷新して既存データは破棄する。
  3. UUID は **UUIDv7** を採用（エンティティ主キー）。root テナントは固定 UUID を廃し**投入時に
     動的採番**、`idp.system.admin` の scope = root 制約は投入時に解決値をリテラル化して付与する。
- **Revised**: 2026-07-12 — §4 の権限付与対象を明確化（GAP1 解消）: 付与対象は「当該テナントで
  **ACTIVE なメンバーシップ**（HOME / GUEST）を持つユーザー」であり、**アカウントの出自では区別しない**。
  `INVITED` は対象外。設計変更ではなく従来意図の明文化であり、実装（所属元限定になっていた
  付与対象判定）側を本定義に合わせて修正する。
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

**基本モデル（Entra ID 型のテナント独立）**: マルチテナントというデータ構成ではあるが、
**各テナントは独立**した管理境界である。root（システム運営側）は新しいテナントを作成できるが、
作成したテナントの内部を操作できるわけではない。テナント内部の管理は、そのテナント自身の管理者
だけが行う。他テナントのユーザーは**招待**によってゲストとして参加できるが、ユーザーの状態
（パスワード・ステータス・MFA 等）は所属元テナントだけが管理する。

本 IdP は MVP 段階であり、本番運用データは存在しない。スキーマ・マスタデータはマルチテナント対応の
定義で**全面刷新**し、既存データはすべて破棄する（§11）。

---

## Decision

### 1. テナントをファーストクラスエンティティとして新設（UUID 識別・テナント独立）

テナントは UUID（`id`）で一意識別する。`name` は人間可読の表示名であり、URL・一意識別には使用しない。

すべての UUID は **UUIDv7**（時刻順序性を持つ）を採用する（§12）。

```sql
CREATE TABLE tenants (
    id               CHAR(36)     NOT NULL COMMENT 'UUIDv7。root も含めシード/アプリが動的採番する',
    parent_tenant_id CHAR(36)     NULL
        COMMENT '作成元テナント。NULL は root テナントのみ',
    name             VARCHAR(255) NOT NULL COMMENT '表示名。一意制約なし・URL には使わない',
    status           VARCHAR(16)  NOT NULL DEFAULT 'ACTIVE',
    -- root（parent_tenant_id IS NULL）を DB レベルで 1 行に限定するための番兵列。
    -- root のとき 1、それ以外は NULL。UNIQUE は複数 NULL を許容するため root だけが一意化される。
    -- 式が (x IS NULL) OR NULL なのは、MariaDB 10.11 が索引付き生成列で IF()/CASE を許可しない
    -- （ERROR 1901）ため。TRUE OR NULL = 1 / FALSE OR NULL = NULL で意図した値になる。
    is_root          TINYINT(1)   GENERATED ALWAYS AS ((parent_tenant_id IS NULL) OR NULL) VIRTUAL,
    created_at       DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at       DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY tenants_single_root_uk (is_root),
    CONSTRAINT tenants_status_chk CHECK (status IN ('ACTIVE', 'DISABLED')),
    CONSTRAINT tenants_parent_fk FOREIGN KEY (parent_tenant_id)
        REFERENCES tenants(id) ON DELETE RESTRICT
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
```

**root テナント**: `parent_tenant_id = NULL`。root も含め **UUID は固定値を使わず、seed（DDL 投入時）に
動的採番する**（UUIDv7）。root は「`parent_tenant_id IS NULL` の唯一の行」として**構造的に識別**し、
特定の UUID リテラルには依存しない。`is_root` 番兵列 + `tenants_single_root_uk` により、root が
**DB レベルで高々 1 行**であることを担保する。

- root の UUID はホスト側で予測できないため、初期 system 管理者のログイン URL（`/{root_uuid}/authorize`）は
  ブートストラップ時に確定する。seed 実行時に root UUID を標準出力へ記録し、取得手順
  （`SELECT id FROM tenants WHERE parent_tenant_id IS NULL`）を `docs/OPERATIONS.md` に記載する。

**root テナントの位置づけとアクセス**:
- root テナントはシステム運営側のテナントであると同時に、通常の OIDC フローも提供する実テナントである。
- root は他のテナントと同じく **UUID で識別**し、`/{root_uuid}/authorize`・`/token`・`/userinfo` 等の
  エンドポイントを通常どおり利用する。**root 専用の特別な URL・エイリアスは設けない。**
- root を含むすべてのテナントで URL 構造・機能は一律であり、アクセス可否は権限判定のみで決まる
  （§4・§9）。root と他テナントの差は「操作する管理者がどの権限を持つか」だけである。

**テナントの独立性**:
- `parent_tenant_id` は「どのテナントから作成されたか」の系譜であり、**管理権限・データアクセスの
  境界としては何の意味も持たない**。親テナントの管理者が子テナントを操作できるわけではない。
- 権限 scope は当該テナントのみに及ぶ（サブツリー伝播はしない。§4）。
- テナントの `status` も各テナント独立であり、親の DISABLED は子へ伝播しない。

**テナントのライフサイクル**:
- root テナントは seed のみが作成する（アプリ経由では作成不可）。
- テナント作成は「あるテナント配下への子テナント作成」として機能上は一律に提供する（§4 の権限
  制約により、実質的に root 配下にのみ作成される）。
- テナント削除は「配下に子テナントが存在しない」かつ「**当該テナント自身に**ユーザー/クライアントが
  存在しない」場合のみ許可する（`ON DELETE RESTRICT` で DB レベルでも保護）。削除時、当該テナントの
  ゲストメンバーシップ（§3）は消滅するが、ゲストのユーザー本体は所属元テナントに残る。
- **root テナントは削除できない**（アプリ層で明示的に禁止する）。
- 親付け替え（`parent_tenant_id` の更新）は禁止する。

### 2. users・clients をテナントスコープ化（所属元は 1 つに限定）

`users` / `clients` テーブルは `tenant_id CHAR(36) NOT NULL` を含む定義で作成する。
**`users.tenant_id` はユーザーの所属元（ホーム）テナントであり、常に 1 つに限定する。**
複数テナントへの参加は所属の複製ではなく、招待によるメンバーシップ（§3）で表現する。

`UNIQUE` 制約は `(tenant_id, email)` / `(tenant_id, client_id)` とし、テナントを跨いだ同一値を許容する。

| テーブル | カラム | UNIQUE 制約 |
|---|---|---|
| `users` | `tenant_id CHAR(36) NOT NULL`（所属元。変更不可） | `(tenant_id, email)` / `(tenant_id, preferred_username)` |
| `clients` | `tenant_id CHAR(36) NOT NULL` | `(tenant_id, client_id)` |

外部キー: `REFERENCES tenants(id) ON DELETE RESTRICT`

- **ユーザーの状態（パスワード・`status`・MFA・プロフィール等 `users` 上の属性）を操作できるのは、
  所属元テナントの管理者と本人のみ**である。参加先（ゲスト先）テナントの管理者は操作できない（§3）。
- 初期管理者 `admin@example.com` は seed で root テナントに帰属させる。

### 3. 招待とメンバーシップ（ゲスト参加）

ユーザーが所属元以外のテナントに参加する唯一の経路は**招待**である（Entra ID の B2B ゲストに相当）。
参加は `tenant_memberships` で表現する。

```sql
CREATE TABLE tenant_memberships (
    tenant_id             CHAR(36)    NOT NULL COMMENT '参加先テナント',
    user_id               CHAR(36)    NOT NULL,
    membership_type       VARCHAR(16) NOT NULL COMMENT 'HOME = 所属元 / GUEST = 招待による参加',
    status                VARCHAR(16) NOT NULL COMMENT 'INVITED = 招待中（未承諾） / ACTIVE',
    invited_by            CHAR(36)    NULL COMMENT '招待を作成した管理者ユーザー',
    invitation_token_hash VARCHAR(64) NULL COMMENT '招待トークンのハッシュ（INVITED の間のみ）',
    invitation_expires_at DATETIME(6) NULL,
    created_at            DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at            DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (tenant_id, user_id),
    CONSTRAINT tenant_memberships_tenant_fk
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT tenant_memberships_user_fk
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT tenant_memberships_type_chk CHECK (membership_type IN ('HOME', 'GUEST')),
    CONSTRAINT tenant_memberships_status_chk CHECK (status IN ('INVITED', 'ACTIVE'))
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
```

- **HOME メンバーシップ**はユーザー作成時に自動生成する（`users.tenant_id` が所属元の単一の出所で
  あり、HOME 行はフロー判定を一元化するための投影）。HOME は解除・削除できない。
- **招待フロー（MVP・SMTP 不要）**: 参加先テナントの管理者が招待を作成すると、一度限りの
  **招待トークン**をレスポンスで返す（`generated_password` と同じ「一度だけ返し、管理者が別途本人へ
  通知する」パターン。トークンはハッシュのみ保存し、ログ・監査ログに出力しない）。
  被招待者は**所属元テナントでログイン済みのセッション**で承諾エンドポイントにトークンを提示し、
  メンバーシップが `ACTIVE` になる。本人性はトークンの所持とログイン済みセッションで確認する。
  メール配送による招待リンク送付は SMTP 連携後の後続タスクとする。
- **参加先テナントの管理者がゲストに対して行えるのは以下のみ**:
  - メンバーシップの解除（ゲストの追放）
  - 参加先テナントを scope とする権限の付与・剥奪（§4。`idp.system.admin` を除く）
- **参加先テナントの管理者が行えないこと**: ゲストの `users` レコードの操作
  （パスワードリセット・ステータス変更・MFA 設定・プロフィール変更等）。これらは所属元テナントの
  管理者と本人のみが行える。
- メンバーシップ解除時、当該テナントを scope とするそのユーザーの権限行も削除する（アプリ層で実施）。

### 4. 権限スコープと権限判定（完全一致・一律判定）

`user_permissions.tenant_id` は常に実在するテナント ID を指す外部キーであり、権限の適用範囲（scope）を
表す。**scope は当該テナントのみに及び、配下・系譜のテナントへは一切及ばない**（テナント独立。§1）。

既存の `granted_at` カラムおよび `users` / `permissions` への外部キー（ADR-0006）は維持し、
主キーへ `tenant_id` を加える。

```sql
CREATE TABLE user_permissions (
    user_id         CHAR(36)    NOT NULL,
    permission_code VARCHAR(64) NOT NULL,
    tenant_id       CHAR(36)    NOT NULL
        COMMENT '権限の適用範囲（scope）。当該テナントのみに及ぶ（配下へは及ばない）',
    granted_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (user_id, permission_code, tenant_id),
    CONSTRAINT user_permissions_user_fk
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT user_permissions_code_fk
        FOREIGN KEY (permission_code) REFERENCES permissions(code) ON DELETE RESTRICT,
    CONSTRAINT user_permissions_tenant_fk
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
    -- CHECK（idp.system.admin の scope = root）は投入時に動的付与する（下記）
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
```

`tenant_id`（scope）は DEFAULT を設けず、常に seed／アプリケーションが明示指定する。

**`idp.system.admin` の scope = root 保証について**: root UUID を動的採番する（§1）ため、
「`idp.system.admin` は root scope でしか存在できない」を **CHECK 制約の固定リテラル**では書けない
（MariaDB の CHECK はサブクエリ・他テーブル参照が不可）。しかし root UUID は**データ投入時には
確定している**ため、seed/投入スクリプトが**解決済みの root UUID をリテラルとして CHECK 制約を付与**する。

```sql
-- 投入スクリプト内（root INSERT 後）。解決した root UUID をリテラルとして制約を付与する。
SET @root := (SELECT id FROM tenants WHERE parent_tenant_id IS NULL);
SET @ddl  := CONCAT(
  'ALTER TABLE user_permissions ADD CONSTRAINT user_permissions_system_admin_scope_chk ',
  'CHECK (permission_code <> ''idp.system.admin'' OR tenant_id = ''', @root, ''')');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;
```

- sqlx マイグレーション**ファイル自体は静的**（実行時に `@root` を解決する `PREPARE`/`EXECUTE`）で
  あり、チェックサムは全環境で一致する。制約に埋め込まれるリテラルは環境ごとの root UUID になるが、
  CHECK は各 DB ローカルの定義なので環境間で一致する必要はない（`SHOW CREATE TABLE` で確認可能）。
- `is_root` 番兵列（§1）が root を 1 行に限定するため、`@root` の解決は常に一意に定まる。
- これにより **DB レベルの機械的保証**が維持される。アプリ層は付与経路で同じ検証（scope が root か）を
  重ねて行い、二重の防御線とする。

**権限コード**:

| コード | scope | 権限内容 |
|---|---|---|
| `idp.system.admin` | root テナント UUID **のみ**（投入時付与の CHECK 制約＋アプリ層で二重に強制） | システム設定の閲覧・変更、`idp.system.admin` の付与・剥奪、**テナントの作成・削除**（scope テナント配下）、root テナント自身のテナント管理 |
| `idp.tenant.admin` | 対象テナント UUID | 当該テナント内の管理: ユーザー（所属元がこのテナントのユーザーのみ）・クライアント・テナント設定・メンバー/招待管理・当該テナント scope の権限付与（`idp.system.admin` を除く） |

**一律の権限判定（完全一致）**:
- `/{tenant_id}/admin/...` へのアクセスは、ユーザーが「**当該テナント自身を scope に持つ** admin 権限」を
  保有するかで判定する。**祖先・配下は考慮しない**。保有しなければ一律 **403** を返す。
- 子テナントの作成・削除（`/{tenant_id}/admin/tenants...`）は「当該テナントを scope に持つ
  `idp.system.admin`」を要求する。投入時付与の CHECK 制約＋アプリ層検証により `idp.system.admin` は
  root scope でしか存在できないため、**実質的にテナントを作成できるのは root だけ**になる。
  機能・エンドポイント・判定は
  root もそれ以外もすべて同一であり、差は「必要な権限を付与できるユーザーが存在するか」だけである。
- `idp.tenant.admin` に子テナント作成は**含めない**。root（system.admin）は新しいテナントを作成
  できるが、作成後のテナント内部（ユーザー・クライアント・設定）は操作できない。内部を操作できるのは
  当該テナントを scope とする `idp.tenant.admin` 保有者のみである。
- **システム設定の閲覧・変更は `idp.system.admin` に含まれる権限**であり、これを保有しないユーザーには
  一律 403 となり、画面自体が見えない。
- **`idp.system.admin` の付与・剥奪は `idp.system.admin` 保有者のみ**が実行できる。それ以外の権限では
  付与操作自体が 403 となる。
- **初期の `idp.system.admin` は seed（DB 直接投入）で作成する。** アプリ経由で最初の
  `idp.system.admin` を作成する導線は存在しない。
- 権限の付与・剥奪の対象は「当該テナントで **ACTIVE なメンバーシップ**（HOME / GUEST）を持つ
  ユーザー」に限る。**アカウントの出自（HOME か GUEST か）では区別しない**。`INVITED`（未承諾）の
  ゲストは対象外であり、対象外のユーザーへの操作はテナント越しの存在推測を防ぐため不存在（404）に倒す。
- 付与・剥奪を実行できるのは当該テナントを scope とする admin 権限の保有者のみである。**所属元
  （ホーム）テナントの管理者であっても、ゲスト参加先テナントを scope とする権限は付与できない**
  （scope 完全一致・テナント独立の帰結。テナント間に権限の優劣・移譲・継承は存在しない）。
- 削除の意味論は権限とメンバーシップの関係に従う: GUEST は**メンバーシップの解除**（当該テナント
  scope の権限行も削除。§3）、HOME ユーザーは**アカウントの削除**（全テナントのメンバーシップ・
  権限行も FK の `ON DELETE CASCADE` で消滅）で表現する。

コード上、権限 scope は単一の値オブジェクト `TenantScope(TenantId)` で表現する。root の特別
バリアントは設けず、判定は「要求テナント ID と権限 scope の完全一致」に一本化する。システム設定等の
追加権限の有無は `permission_code`（`idp.system.admin` か否か）で判定する。

### 5. テナント作成フロー

テナント作成は親テナント配下への子テナント作成として機能上一律に扱う（§4 の権限制約により実質
root 配下のみ）。作成時に必要な情報は以下の 3 点のみ。

| 入力 | 備考 |
|---|---|
| テナント名（`name`） | 表示名。`id`（UUID）はシステムが自動採番する |
| 管理者メールアドレス | 作成と同時に、新テナントを所属元とし、新テナントを scope とする `idp.tenant.admin` を付与した管理者ユーザーを生成する |
| パスワード | 自動生成（32 文字以上のランダム文字列）。レスポンスに一度だけ平文で返す |

- 生成された管理者ユーザーの所属元は新テナントである。以後この管理者（および同テナントの
  `idp.tenant.admin`）だけがテナント内部を管理する。作成者（root の system.admin）は内部を
  操作できない。
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

### 6. OIDC エンドポイントのテナント対応（テナント UUID プレフィクス方式・一律）

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
  「クレデンシャル ⇔ ユーザー ⇔ 所属元テナント」の紐付け（アプリ層）で実現する。

**管理エンドポイント（すべて `/{tenant_id}/admin/...` に一律配置）**:

```text
/{tenant_id}/admin/tenants                 GET/POST          子テナント一覧・子テナント作成（idp.system.admin）
/{tenant_id}/admin/tenants/{child_id}      GET/PATCH/DELETE  子テナント詳細・更新・削除（idp.system.admin）
/{tenant_id}/admin/users                   GET/POST          所属元がこのテナントのユーザー管理
/{tenant_id}/admin/clients                 GET/POST          当該テナントのクライアント管理
/{tenant_id}/admin/members                 GET               メンバー一覧（HOME / GUEST）
/{tenant_id}/admin/members/{user_id}       DELETE            ゲストメンバーシップの解除（HOME は不可）
/{tenant_id}/admin/invitations             POST              ゲスト招待の作成（招待トークンを一度だけ返す）
/{tenant_id}/admin/settings                GET/PATCH         テナント設定（root では加えてシステム設定）
/{tenant_id}/invitations/accept            POST              招待の承諾（ログイン済みユーザーがトークンを提示）
```

- トップレベルのテナント作成は `POST /{root_uuid}/admin/tenants`（root の子作成）として行う。
- `GET /{tenant_id}/admin/tenants` は当該テナントの**直下の**子テナント一覧を返す。
- `GET /{tenant_id}/admin/users` は**所属元が当該テナントのユーザー**のみを返す。ゲストは
  `admin/members` に現れ、`admin/users` の操作対象にはならない（§3）。
- いずれのルートも §4 の完全一致判定で保護され、権限 scope が要求テナントと一致しなければ 403 を返す。
  `/admin/...` という特別な横断名前空間や root 専用ルートは設けない。

**テナント外パス（プレフィクスなしで残すもの）**:
`/healthz`・`/readyz`・`/api/docs`・`/api/openapi.json`、web→api の内部 API `/internal/*`（§8）、
および**静的アセット（画像・CSS・JavaScript・favicon 等。将来 `/static/...` 等の固定パスで配信する
場合を含む）**はテナントプレフィクスを付けない。静的アセットはテナントに依存しない共有リソースであり、
テナント UUID を経路に含めない。

**ルーティング衝突の回避**: axum（0.8 / matchit）の router はパスセグメントに正規表現制約を
課せないため、次の 2 段で固定パスとテナントルートを区別する。
1. matchit は同一階層で**静的セグメントをパラメータより優先マッチ**する仕様であり、`/healthz` や
   静的アセット（`/static/...` 等）の固定パスは `/{tenant_id}` に吸われない。テナント外パスの
   ルート先頭セグメント（`healthz`・`readyz`・`api`・`internal`・`static` 等）は予約語として扱い、
   テナント UUID がこれらと衝突しないことは UUID 形式（次項）が保証する。
2. `:tenant_id` セグメントの UUID 形式（36 文字ハイフン区切り）検証は `TenantResolver`（§7）が行い、
   パース失敗・未知の値は 404 を返す。

### 7. テナント解決 Middleware

axum の `from_fn` middleware として `TenantResolver` を追加する。リクエストパスの `:tenant_id`
セグメントを UUID としてパースし（失敗は 404）、`tenants` を検索して `Extension<ResolvedTenant>` として
注入する。テナントが存在しない・DISABLED の場合は 404 を返す（status は各テナント独立。§1）。
root も同一経路で UUID として解決し、特別分岐は設けない。

```text
Presentation (Router) → TenantResolver middleware → Handler
                              ↓
                    Extension<ResolvedTenant>
```

id→tenant 解決はホットパスのため、TTL 付きインメモリキャッシュ + 更新時 invalidation を採用する
（既存に汎用キャッシュ基盤はないため新設。`InMemoryLoginRateLimiter` と同様、trait 越しに注入して
単体インスタンス前提とし、スケールアウト時に差し替える）。

**このキャッシュ基盤は scope→権限のマッピング（解決）にも共用する。** §4 の権限判定は
`(user_id, permission_code, tenant_id)` の存在確認であり、同じくリクエスト毎に評価されるホットパスである。
テナント解決と同一の TTL キャッシュ抽象（`Cache` trait）を用いて、権限行の参照結果も
キャッシュ + 更新時 invalidation の対象とする。権限の付与・剥奪時に該当エントリを invalidate する。
キャッシュは「テナント解決」「scope→権限解決」の 2 用途で共有する汎用機構として設計し、用途ごとに
別インスタンス（別キー空間）を注入する。

### 8. アプリ層のテナント分離強制

- すべての Repository trait のメソッドシグネチャに `tenant_id: &TenantId` を付与する。
- Application（ユースケース）は `TenantId` を保持した `TenantContext` を受け取り、リポジトリ呼び出しに
  必ず渡す。
- `RequirePerms` extractor は §4 の完全一致判定を担う。要求テナントは `Extension<ResolvedTenant>`
  （§7）から取得する。
- MariaDB に RLS はないため、アプリ層が唯一の分離防御線となる。統合テストで「他テナントのデータが
  取得できないこと」を検証する negative test を必須ケースとする。

**セッションとテナントの関係（認証と認可の分離）**:
- **認証（パスワード・MFA によるログイン）はユーザーの所属元テナントでのみ**行う。`auth_sessions` に
  `tenant_id` を追加し、`/{tenant_id}/authorize` で開始したフローのテナントを保持する。ログイン画面の
  ユーザー検索は `(tenant_id, email)`（= そのテナントを所属元とするユーザー）で行う。
  ゲストの資格情報が参加先テナントの画面に入力されることはない。
- **OIDC フロー（authorize/token/userinfo）では「セッションユーザーが要求テナントの `ACTIVE`
  メンバーシップ（HOME または GUEST）を持つこと」を検証**する。ゲストは所属元テナント
  （`/{home_id}/authorize` 等）でログインしてホスト共有の SSO セッションを確立し、参加先テナントの
  フローではそのセッション + メンバーシップ判定で許可される（Entra ID のホームテナント認証の簡易形）。
  メンバーシップのない SSO セッションは当該テナントのフローでは未認証として扱う。
- **admin ルートはメンバーシップではなく §4 の権限判定のみ**で決まる（権限は当該テナントの
  メンバーにしか付与できないため、権限保有はメンバーシップを含意する）。
- cookie（`sso_session_id` 等）は現行どおり `Path=/`（ホスト単位）とする。パスによる cookie 分離は
  ゲストのクロステナント参加と両立しないため採らず、境界は上記のサーバ側検証で強制する。
- ログイン試行レートリミット（`InMemoryLoginRateLimiter`）のキーは `(tenant_id, email)` とする。
- `audit_log` に `tenant_id` カラムを追加し、監査イベントをテナント単位で追跡可能にする。

**api/web 分割（ADR-0007）との整合**:
- 画面 URL（§10）は web クレート、API は api クレートが提供する。web はデータ操作を api への
  HTTP 呼び出し（`api_client.rs`）で行うため、テナントコンテキストを web→api へ明示的に伝搬する。
- `/internal/*`（web→api 内部 API）はテナントプレフィクスを付けず、`crates/contracts` の
  リクエスト DTO（`InternalAuthenticateRequest` 等）へ `tenant_id` フィールドを追加して伝える
  （`(tenant_id, email)` 一意化により、テナント指定のない認証は成立しない）。
- `/{tenant_id}/admin/*`（管理 API）は web の `api_client.rs` がパスにテナント ID を組み込んで呼ぶ。

### 9. 権限による一律のアクセス制御

管理・設定操作は URL 上で特別扱いせず、`/{tenant_id}/admin/...` に一律配置したうえで、§4 の権限判定で
アクセス可否を決める。

- `RequirePerms` は「要求テナントを scope に持つ admin 権限」の完全一致で判定し、無ければ 403 を返す。
- `idp.tenant.admin` 保有者は scope テナント内の管理（ユーザー・クライアント・メンバー/招待・
  テナント設定）を行える。他テナント（自テナントが作成した子テナントを含む）へアクセスすると
  403 となる。
- `idp.system.admin` 保有者（scope = root）は、システム設定の変更、`idp.system.admin` の付与・剥奪、
  テナントの作成・削除、root テナント自身の内部管理を行える。**他テナントの内部は管理できない。**
- **システム設定は `idp.system.admin` 固有の権限**であり、保有しないユーザーには一律 403 となって
  画面が見えない。root だけの特別 URL は存在せず、可視性は純粋に権限で決まる。

### 10. 管理・設定画面の構成

| 画面 | URL | 表示条件（権限） | 主な機能 |
|---|---|---|---|
| **テナント設定** | `/{tenant_id}/admin/settings` | 当該テナントを scope に持つ admin 権限 | テナント表示名（`name`）の変更、テナント有効/無効、メンバー・招待管理 |
| **システム設定** | `/{root_uuid}/admin/settings`（同一画面のシステム区画） | `idp.system.admin` のみ | SMTP 設定（外部サーバー）、システム全体の設定値管理、`idp.system.admin` の付与・剥奪、テナント作成・削除 |
| **ユーザー設定** | `/{tenant_id}/settings` | 当該テナントのメンバー（自分のみ） | パスワード変更・MFA 設定（TOTP・Passkey）・プロフィール（所属元テナントでのみ表示）、言語設定 |

- システム区画は権限 scope の完全一致により **root テナントの設定画面にのみ**現れる（`idp.system.admin`
  の scope は root に限定されるため、他テナントの settings 画面に描画されることは構造上ない）。
- ユーザー設定のうち `users` レコードに属するもの（パスワード・MFA・プロフィール）は
  **所属元テナントの画面でのみ**操作できる。参加先テナントの画面では表示しない（§3）。
- メール配送を前提とするセルフサービスのパスワードリセット（忘失時再設定）は SMTP 設定完了を前提と
  するため後続タスクとする。本 ADR の範囲は「ログイン済みユーザーによるパスワード変更画面」までとする。

### 11. スキーマ・マスタデータの刷新（マイグレーションは行わない）

既存スキーマからのデータ移行（マイグレーション）は**行わない**。MVP 段階で本番運用データが存在しない
ため、**初期設定 DDL とマスタデータ（seed）をマルチテナント対応の定義で全面的に刷新し、既存データは
すべて破棄する**。

- 既存のマイグレーションファイル群を、マルチテナント対応の完全な初期 DDL（`tenants`・
  `tenant_memberships`・`tenant_id` 入りの `users`/`clients`/`user_permissions`/`auth_sessions`/
  `audit_log` 等）＋ seed（root テナント・権限コード・初期管理者）で**作り直す**。
  段階的な expand/contract は行わない。
- root テナントおよびエンティティの UUID は seed/投入スクリプトが **UUIDv7 で動的採番**し、
  `idp.system.admin` の scope = root を縛る CHECK 制約は、解決した root UUID をリテラル化して
  投入時に付与する（§4）。マイグレーションファイル自体は静的でチェックサムは安定する。
- 全環境は DB を再作成する（`_sqlx_migrations` のチェックサム不整合は DB 再作成で解消する。
  リセット手順は `docs/OPERATIONS.md` に記載する）。
- これは MVP 期の一度限りの措置である。刷新後は従来どおり `.claude/skills/db-migration/` のルール
  （追記型マイグレーション・up/down 対・冪等 seed）に戻る。

### 12. UUID は UUIDv7 を採用

新規に生成する UUID は **UUIDv7**（先頭にミリ秒精度の Unix 時刻を持つ時刻順序型）を採用する。
CHAR(36) の正準文字列で保持する点は従来どおりで、CLAUDE.md「DB モデリング」の UUID 規約と互換。

- **適用範囲**: テナント・ユーザー・クライアント・signing key 等の**エンティティ主キー**は v7 とする。
  時刻順序性により InnoDB のクラスタインデックス（CHAR(36) PK）への挿入が概ね昇順となり、ランダム
  UUID（v4）で生じるページ分割・断片化を抑える。
- **v4 のまま残すもの**: `jti`・`correlation_id`（requestId）・`csrf_id` など、時刻順序性が無意味で
  かつ生成時刻を露出させたくない揮発トークン類は v4 を維持する。
- **情報露出の留意点**: v7 は UUID から生成時刻（ミリ秒）が復元できる。エンティティ UUID は URL・
  `iss` に露出するため「テナント/ユーザーの作成時刻が第三者に読める」ことを許容する（IdP では通常
  問題にならないが、秘匿が要る識別子には v7 を使わない）。
- **実装**: `uuid` crate の feature に `"v7"` を追加し、生成箇所を `Uuid::now_v7()` に切り替える
  （現状は `features = ["v4"]`・`Uuid::new_v4()`）。ID 生成はドメイン層のファクトリ／`IdGenerator`
  相当に集約し、テストでは固定値へ差し替える（時刻・乱数と同様に注入する）。

---

## 段階的実装計画（Phase 分け）

### Phase 1: データ基盤（初期 DDL・seed の刷新）

1. 初期 DDL を刷新: `tenants`（`is_root` 番兵列 + 単一 root UNIQUE 含む）・`tenant_memberships` を
   新設し、`users`（`tenant_id`・`must_change_password` 含む）・`clients`・`user_permissions`
   （`tenant_id` 含む）・`auth_sessions`・`audit_log`（`tenant_id` 含む）等を再定義。UUID 列は v7 前提
   （§11・§12。既存データは破棄）
2. root テナント seed（UUIDv7 を動的採番。固定リテラルは使わない）
3. `user_permissions` の `idp.system.admin` scope = root を縛る CHECK 制約を、解決した root UUID を
   リテラル化して投入時に付与（`PREPARE`/`EXECUTE`。§4）
4. 権限コード seed（`idp.system.admin` / `idp.tenant.admin`）
5. 初期管理者 `admin@example.com` を root テナントへ seed（HOME メンバーシップ含む）+
   `idp.system.admin`（scope = root UUID）を **DB 直接投入で付与**（アプリ経由の付与導線は設けない）
6. root UUID を seed 実行時に標準出力へ記録し、取得手順・DB 再作成手順を `docs/OPERATIONS.md` へ記載

### Phase 2: ドメイン・アプリケーション層

6. `Tenant` / `TenantMembership` ドメインモデル + `TenantRepository` / `TenantMembershipRepository` trait
7. `TenantContext` / `TenantScope` 値オブジェクト
8. Repository trait へ `tenant_id` 引数追加
9. ユースケースの `TenantContext` 対応（OIDC フローのメンバーシップ判定、認証は所属元テナント限定）
10. 招待ユースケース（招待作成・トークン一度限り返却・承諾・メンバーシップ解除）
11. 汎用 TTL キャッシュ抽象（`Cache` trait）の新設 —「テナント解決」「scope→権限解決」で共用
12. `TenantResolver` middleware（UUID 解決・キャッシュ利用）+ `RequirePerms` の完全一致 scope 判定
    （権限解決もキャッシュ利用、付与・剥奪時に invalidate）
13. per-tenant issuer 合成（基底 issuer + tenant_id）と WebAuthn RP ID の基底ホスト分離

### Phase 3: プレゼンテーション層・管理 API

14. `/{tenant_id}/...` ルーティング（静的パス優先 + TenantResolver での UUID 検証）
15. `crates/contracts` DTO への `tenant_id` 追加と web `api_client.rs` のテナント対応
16. 管理 API（`/{tenant_id}/admin/tenants` / `users` / `clients` / `members` / `invitations`）+
    テナント作成時の管理者自動生成・パスワード自動生成・`must_change_password` 付与
17. パスワード変更（リセット）画面の新設 + 初回ログイン時の強制変更誘導
18. テナント管理コンソール（`/{tenant_id}/admin/`）— ユーザー・クライアント・メンバー・招待管理
19. 設定画面（`/{tenant_id}/admin/settings`）— テナント設定 + root のみシステム設定区画
20. ユーザー設定画面（`/{tenant_id}/settings`）— パスワード変更・MFA・言語設定
21. 統合テスト（テナント間分離・権限境界の完全一致・ゲスト参加とユーザー状態の保護・
    「root は作成できるが内部を操作できない」ことの検証）

---

## Consequences

**Positive**

- root を含め URL 構造・機能が完全に一律で、アクセス可否は権限判定のみで決まるため、ルーティングと
  認可の責務が明確に分離される。特別分岐がなくテスト・保守が容易。
- **権限判定が「要求テナント = scope」の完全一致**であり、祖先探索・サブツリー判定が不要。
  実装・テストが単純で、判定の計算量も O(1)。
- テナントが互いに独立した管理境界となり（Entra ID 型）、「ホスティング側（root）は器を作るだけで
  中身に触れない」というプライバシー・責務分界を構造的に保証できる。
- ユーザーの所属元が 1 つに限定され、ユーザー状態の管理責任が常に所属元テナントに一意に定まる。
  ゲスト参加はメンバーシップとして明示され、参加先が操作できる範囲が構造的に制限される。
- `idp.system.admin` の scope を root に限定する（投入時付与の CHECK 制約 + アプリ層検証 + 単一 root
  番兵列）ことで、「テナント作成権限を他テナントへ付与できるユーザーが存在しない」ことを DB・アプリ
  両面で保証する。root UUID を動的採番しても、投入時に解決値をリテラル化するため CHECK が維持される。
- UUIDv7 の採用でエンティティ主キー（CHAR(36)）の挿入局所性が向上し、ランダム UUID による
  InnoDB のページ分割断片化を抑えられる。
- `iss` はテナント UUID 基点で不変のため、issuer 安定性が構造的に保証される。
- 表示名（`name`）は URL・トークン検証に無影響で、自由に変更できる。
- テナントをまたいだデータ漏洩をアーキテクチャレベルで防止できる。
- テナント作成フローが完結しており、管理者が即時アクセス可能（SMTP 不要）。初回強制変更で初期パスワードの残存リスクを低減する。

**Negative / コスト**

- URL・ログにテナント UUID が現れ、人間による判読性は低い（表示名との対応は管理 UI で補う）。
  クライアント設定（redirect_uri 等）に UUID を正確に転記する必要がある。
- 組織階層（部門・子会社への管理権限の委譲）は表現できない。サブツリー管理が必要になった場合は
  scope 伝播の再導入ではなく、必要テナントへの個別の権限付与（ゲスト + `idp.tenant.admin`）で
  対応する。
- 招待・メンバーシップの管理（テーブル・API・承諾フロー）が増える。SMTP 連携までは招待トークンの
  手動伝達が必要。
- すべての Repository インターフェース変更は広範囲に波及する。issuer を起動時固定で保持している
  各サービス（Token/UserInfo/Logout/Introspection/Discovery/WebAuthn 等）はリクエスト毎の issuer
  合成へ変更が必要。統合テストのハードコードされたパスも全面更新となる。
- パスキー（WebAuthn）はプロトコル上ホスト単位であり、テナント分離はアプリ層の紐付けに依存する。
- スキーマ刷新により全環境で DB 再作成が必要（MVP 期の一度限り。§11）。
- root UUID が固定値でなくなるため、ブートストラップ時の system 管理者ログイン URL が環境ごとに
  異なる。seed 実行ログ／DB 参照で root UUID を確認する手順が必要（§1）。CHECK 制約も投入時に
  動的付与するため、通常の CREATE TABLE より一手間（`PREPARE`/`EXECUTE`）が増える。
- UUIDv7 はエンティティ UUID から生成時刻が復元できる（作成時刻の露出。§12）。
- 恒久的なセルフサービス・パスワードリセットは SMTP 連携まで提供されない。

**Alternatives considered**

- **権限 scope のサブツリー伝播（祖先テナント管理者が配下を管理できる階層モデル）**: 本 ADR の
  旧改訂で採用していたが、「各テナントは独立した管理境界であり、ホスティング側も他テナントの内部を
  操作できない」という要件（Entra ID 型）と両立しないため廃止。クロステナント管理が必要な場合は
  招待 + 権限付与で明示的に行う。
- root 専用 URL・専用管理名前空間（`/admin/...`、`/root/...`）を設ける: URL とアクセス制御の責務が
  混在し、特別分岐が増えるため却下。URL は一律とし権限判定に一本化する。
- ユーザーの複数テナント所属（テナントごとに `users` 行を複製）: ユーザー状態の管理責任が分散し、
  「所属元だけが状態を管理する」原則と矛盾するため却下。参加はメンバーシップで表現する。
- cookie の `Path=/{tenant_id}` によるセッション分離: ゲストのクロステナント参加と両立しないため
  却下。境界はサーバ側のメンバーシップ検証と scope 完全一致判定で強制する。
- 既存スキーマからの段階的マイグレーション（expand/contract）: 本番運用データが存在しない MVP 段階
  では移行コストに見合わないため却下し、初期 DDL・マスタデータの全面刷新とする。
- テナントごとに DB スキーマ（DB 分離マルチテナント）: Synology DSM/Docker 環境での運用が複雑化するため MVP 範囲外として却下。
- `users.tenant_id` を持たずクライアント単位でテナントを表現する: ユーザーが複数クライアントを持つテナントで整合性を保てないため却下。
- リクエストパラメータでテナントを指定する: エンドポイント識別が曖昧になるため却下。

---

## Follow-ups（後続タスク）

- **招待のメール配送**: SMTP 設定完了後、招待トークンを管理者の手動伝達ではなくメールリンクで
  被招待者へ直接送付するフローへ移行する。
- **セルフサービス・パスワードリセット（忘失時）**: SMTP 設定完了後に実装。ユーザー設定画面に
  「メールによるリセット」フローを追加する。外部 SMTP はシステム設定区画で設定する（ADR 別途）。
- **ワンタイム招待/セットアップトークン**: SMTP 連携後、テナント作成時に平文パスワードを返さず
  トークン配送で管理者本人がパスワードを設定する方式へ移行する。
- **RFC 8414 path-insertion 形式の well-known 提供**: 厳格クライアント連携時に追加する。
- Phase 1 完了後、`docs/OIDC_INPUT.md` のスキーマ図（§3）にテナント・メンバーシップ関係を追記する。
- `idp.system.admin` / `idp.tenant.admin` の付与・剥奪、招待の作成・承諾・解除を `audit_log` の
  `event_type` に追加する。
- テナントごとの signing key（`signing_keys` に `tenant_id` 追加）を検討する。
