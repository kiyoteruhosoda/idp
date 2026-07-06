# ADR-0006: 管理機能のための利用者権限モデル（user ↔ permission）

- Status: Accepted
- Date: 2026-07-06
- 関連: `CLAUDE.md`「権限管理」、`docs/OIDC_INPUT.md`（設計仕様）、`docs/Progress.md`（A1〜A3・K1）、
  `docs/adr/0005-rust-mariadb-stack.md`

## Context

MVP 以降で管理機能（A1: RP 登録 API・画面、A2: 管理コンソール、A3: 状況確認画面、K1: 鍵管理）を
追加するにあたり、「特定の利用者だけがこれらを実行できる」認可が必要になる。

`CLAUDE.md`「権限管理」は次を定めている。

- 認可は **ロールではなく scope（権限コード値）** で行う。ロール名での分岐は禁止。
- 保護エンドポイントには scope 検証を行う axum extractor（例: `RequirePerms("scope_name")`）を付与する。
- 権限の検証は Application 層で行い、Presentation 層には結果のみ渡す。

しかし現状の実装には利用者に権限を紐付ける仕組みが無い。

- `domain::values::Scope` は OIDC の `openid` / `profile` / `email` の 3 種のみ（トークン claim 制御用）。
- scope は **Clients にのみ**紐づく（`Client.scopes` と `allows_scopes()`＝要求 scope の部分集合判定）。
- `users` テーブルには権限・エンタイトルメントを表す列も関連テーブルも無い。

つまり「クライアントが要求する OIDC scope（claim 制御）」と「利用者が保有する権限（IdP 機能への
アクセス制御）」は**別の関心事**であり、後者のデータモデルが未定義であることが管理機能の前提を塞いでいる。

## Decision

### 1. 2 つの軸を明確に分離する

| 軸 | 主体 | 目的 | 現状 |
|---|---|---|---|
| **OIDC scope** | クライアントが要求 | 発行トークン・`/userinfo` の claim 制御 | 実装済み（変更しない） |
| **権限コード（permission code）** | 利用者が保有 | 保護された IdP 機能へのアクセス制御 | 本 ADR で新設 |

OIDC scope（`openid`/`profile`/`email`）はそのまま維持する。権限コードは新しい軸として追加する。

### 2. 権限コードはマスタテーブルで管理する（拡張前提）

権限コードは運用に応じて増える。DB ネイティブ ENUM も `CHECK` 列挙も使わない（追加のたびに `ALTER` が
必要になり DDL 運用と噛み合わない）。許可値の単一出所を **seed マイグレーション**とするマスタテーブルで表す
（`CLAUDE.md`「DDL 管理」「マスタデータ」）。

```sql
-- 権限コードのマスタ（許可値の単一出所 = seed マイグレーション）
CREATE TABLE permissions (
    code        VARCHAR(64)  NOT NULL,
    description VARCHAR(255) NOT NULL,
    created_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- 利用者 ↔ 権限（多対多）
CREATE TABLE user_permissions (
    user_id         CHAR(36)     NOT NULL,
    permission_code VARCHAR(64)  NOT NULL,
    granted_at      DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (user_id, permission_code),
    KEY user_permissions_code_idx (permission_code),
    CONSTRAINT user_permissions_user_fk FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT user_permissions_code_fk FOREIGN KEY (permission_code)
        REFERENCES permissions (code) ON DELETE RESTRICT
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
```

### 3. 命名は名前空間付き権限コード

MVP-admin は粗粒度の `idp.admin` から開始する。将来はスキーマ変更なし（マスタ行の追加のみ）で
細分化できる。

- `idp.admin` — 管理機能全体（MVP）
- 将来例: `idp.clients:read` / `idp.clients:write` / `idp.audit:read` / `idp.keys:write`

### 4. ブートストラップ（最初の管理者）

seed 管理ユーザー（`admin@example.com`、ADR 外の `migrations/0002_seed_initial_admin`）へ `idp.admin` を
**冪等 upsert** で付与する seed マイグレーションを追加する（人手を介さず初期管理者を成立させる）。

### 5. 認可の実装（既存 DDD/DIP パターンを踏襲）

- **Domain**: 権限コードの値表現と `UserPermissionRepository` trait（DIP 境界）を追加。
  権限コードは**マスタ駆動＝データ**のため Rust の固定 enum にはしない（値オブジェクトは `String` ラッパ）。
- **Application**: 保護ユースケースで「SSO 認証済み利用者が必要権限を保有するか」を検証し、
  Presentation には結果（可否）のみ渡す。
- **Presentation**: `RequirePerms("idp.admin")` axum extractor（`CLAUDE.md` 記載どおり）。
  SSO セッションから利用者を解決し、保有権限と突合する。

### 6. トランスポート非依存

MVP-admin の管理コンソール（A2）は既存 SSO セッション背後の**サーバレンダリング画面**とし、
`RequirePerms` で保護する。権限モデルはトランスポートに依存しないため、将来ファーストパーティの
管理 SPA を OIDC で構築する場合も、**利用者が保有する権限コードに限定してトークンへ scope を発行する**
形で同じモデルを再利用できる。

### 7. サードパーティへは公開しない

権限コードは内部認可であり、OIDC Discovery の `scopes_supported` には載せない。
`Clients.scopes`（OIDC scope）とも混在させない。

## Consequences

**Positive**

- ロール分岐なしに scope/権限コードで一貫（`CLAUDE.md` 準拠）。細分化がスキーマ変更なしで可能。
- OIDC scope と利用者権限を分離し、概念の混同を回避。
- 既存の DDD 4層・DIP・`RequirePerms` 規約にそのまま乗る。
- 権限付与/剥奪を監査対象にできる（例 `user_permission.granted` / `.revoked` を `audit_log` に追加）。

**Negative / コスト**

- テーブル 2 つ + seed + リポジトリ + extractor の実装（A2 の前提作業）。
- 権限の付与/剥奪 UI（誰が誰に権限を与えるか）が別途必要（A2 スコープ内で管理者による最小限の付与/剥奪）。

**Alternatives considered**

- `users.is_admin` boolean: 実質ロール分岐で `CLAUDE.md` 違反。粒度が固定で拡張不可 → 却下。
- 権限コードを Rust enum + `CHECK` で集中管理: 権限追加のたびに `ALTER`/再デプロイが必要でデータ駆動運用に
  不向き → 却下（マスタテーブル採用）。固定・少数の許可値（`UserStatus` 等）とは要件が異なる。
- OIDC scope を流用し `idp.admin` を `Clients.scopes` に混ぜる: claim 制御と権限制御が混線し、
  サードパーティ client が管理 scope を要求し得る → 却下。
- グループ/ロール階層（RBAC）: MVP には過剰。将来 permissions の上位概念として追加可能。

## Follow-ups

- 本 ADR 確定後、`docs/Progress.md` の **A2** に「`permissions` / `user_permissions` マイグレーション + seed
  （admin へ `idp.admin` 付与）+ `UserPermissionRepository` + `RequirePerms` extractor」を実装項目として紐付ける。
- 権限付与/剥奪イベントの監査ログ種別を `docs/OIDC_INPUT.md` §7 の一覧へ追記する。
