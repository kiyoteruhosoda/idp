# CHANGELOG

完了した重要な変更の要約（詳しい経緯は `history/`、設計判断は `adr/`）。

## 2026-07-10（MT9・MT10: `/{tenant_id}/...` ルーティング + TenantResolver mount + web テナント伝搬）

- **MT9 — api テナントルーティング**（ADR-0009 §6・§7）: テナントスコープの api エンドポイント
  （`authorize`/`token`/`userinfo`/`introspect`/`revoke`/`logout`/`.well-known/*`/`auth/register`/`admin/*`）を
  `/{tenant_id}/...` 配下へ再構成し、`resolve_tenant` middleware を `route_layer` で mount した。テナント外パス
  （`healthz`/`readyz`/`internal/*`/`api/docs`）はプレフィクス無しで据え置き。各ハンドラと `RequirePerms`
  extractor は `state.default_tenant` から**パス由来の `Extension<ResolvedTenant>`** へ移行し、要求テナントは
  URL から解決する。ネスト経路では `tenant_id` が先頭パスパラメータになるため、ドメインパラメータを取る
  ハンドラの `Path` 抽出子を `(tenant_id, ...)` タプルへ更新した。UUID 不正・未知・DISABLED は一律 404。
- **MT10 — contracts DTO + web api_client テナント対応**（ADR-0009 §8）: 内部認証 API の DTO
  （`InternalAuthenticate*`/`InternalConsent*`/`InternalVerifyTotp`/`InternalPasskeyLoginComplete`/
  `InternalLogout`）へ `tenant_id: Option<String>` を追加。api 内部ハンドラは DTO 由来テナントを使い、未指定は
  既定テナント（root）へフォールバックする（過渡期。`(tenant_id, email)` 一意化）。web `api_client.rs` は
  `/internal/root-tenant`（新設・サービストークン保護）で root テナント UUID を遅延解決・キャッシュし、
  `/{tenant_id}/admin/*` パスに前置する。
- **過渡期（web の画面テナント経路化＝MT13 まで）**: web の画面 URL・テンプレートは従来どおりフラット
  （`/login`・`/admin/console/*`）のままで、管理コンソールは root テナントを対象とする。api の
  `/{tenant_id}/authorize` は引き続き `/login`（web・フラット）へ 302 する。統合テスト・`scripts/e2e.sh` の
  ダイレクト api 呼び出しは `/{root_uuid}/...` へ追随した。

## 2026-07-10（MT8: 招待ユースケース + OIDC フローのメンバーシップ判定）

- **招待ユースケース**（ADR-0009 §3。`application::invitation::InvitationService`）:
  - **招待作成**: 参加先テナントの管理者が既存ユーザーをゲスト招待する。GUEST/INVITED メンバーシップを
    作成し、一度限りの平文トークンを返す（保存はハッシュのみ。ログ・監査には出さない）。既メンバー
    （HOME/GUEST/INVITED）は `AlreadyMember`、不存在ユーザーは `NotFound`。
  - **承諾**: 被招待ユーザー本人がログイン済みセッション + トークン提示で `ACTIVE` 化する。トークンが
    当該テナントの招待でない・期限切れ・不存在は一律 `InvalidOrExpired`、本人でなければ `Forbidden`。
  - **メンバーシップ解除**: ゲストを追放する。HOME は解除不可（`Forbidden`）。解除時に当該テナントを
    scope とする権限行も剥奪する（列挙 → 個別 revoke。権限キャッシュも invalidate）。
  - 監査イベント `tenant_invitation.created` / `.accepted` / `tenant_membership.revoked` を追加。
    HTTP エンドポイント（`/{tenant_id}/admin/invitations` 等）は MT11 で追加する。`AppState.invitations`
    に配線済み。招待 TTL は `INVITATION_TTL_SECS`（既定 7 日）。
- **OIDC フローのメンバーシップ判定**（ADR-0009 §8）: `AuthorizeService` の SSO 復元経路に、要求
  テナントの **ACTIVE メンバーシップ（HOME または GUEST）検証**を追加。メンバーシップのない SSO
  セッションは当該テナントのフローでは未認証として扱う（= ログインへ）。ゲストは所属元テナントで
  ログインしてホスト共有 SSO を確立し、参加先テナントのフローではこの判定で許可される。認証（ログイン）
  自体の所属元テナント限定は MT5 で導入済み。

## 2026-07-10（MT7: per-tenant issuer 合成 + WebAuthn RP ID の基底ホスト分離）

- **per-tenant issuer**（ADR-0009 §6。`domain::issuer::tenant_issuer`）: 発行トークン（ID/Access）・
  discovery・introspection・front-channel logout の `iss` を `<基底 issuer>/<tenant_id>` の canonical
  形式へ移行。基底 issuer は設定値（`config.issuer()`）由来で Host ヘッダから導出しない
  （host header injection 対策）。`TokenService`/`UserInfoService`/`IntrospectionService`/`LogoutService`
  は起動時固定 issuer を保持する構造から、リクエストの `TenantContext` を用いた**毎リクエスト合成**へ
  変更。リソースサーバ（userinfo/introspection）は要求テナントの合成 issuer と `iss`/`aud` を厳密照合し、
  他テナント発行トークンの流用を弾く。
- **WebAuthn RP ID の基底ホスト分離**: WebAuthn はプロトコル上ホスト単位でパスを含められないため、
  RP ID・origin は**基底 issuer のホスト**から導出する（per-tenant issuer は渡さない）。テナント分離は
  「クレデンシャル ⇔ ユーザー ⇔ 所属元テナント」のアプリ層の紐付けで実現する（`state.rs` に明示）。
- **過渡期（MT9 まで）**: ルーティングは未導入のため、各エンドポイントは既定テナント（root）で issuer を
  合成する（`iss` = `<基底>/<root_uuid>`）。MT9 でパス由来 `ResolvedTenant` へ置き換える。

## 2026-07-10（MT6: 汎用 TTL キャッシュ抽象 + TenantResolver + 権限解決のキャッシュ化）

- **汎用 TTL キャッシュ抽象**（ADR-0009 §7）: `domain::cache::Cache<K, V>` trait（`get`/`insert`/
  `invalidate`）と `infrastructure::cache::InMemoryTtlCache`（TTL 判定・`get` 時の期限切れ遅延削除、
  `Clock` 注入でテスト可能）を新設。`InMemoryLoginRateLimiter` と同様に trait 越しに注入し単体
  インスタンス前提、スケールアウト時は共有ストア実装へ差し替える。用途ごとに別インスタンス（別キー
  空間）を注入する。TTL は `TENANT_CACHE_TTL_SECS`／`PERMISSION_CACHE_TTL_SECS`（既定 60 秒）。
- **scope→権限解決のキャッシュ化**: `CachedUserPermissionRepository` デコレータが `has_permission`
  の判定結果を TTL キャッシュし、`grant`/`revoke` 時に該当キー（`(tenant_id, user_id, code)`）を
  即時 invalidate する。`AppState::build` で `SqlxUserPermissionRepository` をラップし、判定
  （`AdminAccessService`）と変更（`PermissionManagementService`）が同一インスタンスを共有するため
  付与直後の反映漏れ（stale allow/deny）が起きない。
- **TenantResolver middleware**（ADR-0009 §7）: `application::tenant_resolution::TenantResolutionService`
  が id → tenant を TTL キャッシュ（テナント実体を格納し、有効性は取り出し後に判定）付きで解決し、
  `presentation::tenant` に `ResolvedTenant` 型と axum middleware `resolve_tenant` を追加。パスの
  `:tenant_id` を UUID として解決し、UUID 不正・未知・`DISABLED` は一律 404、`ACTIVE` は
  `Extension<ResolvedTenant>` を注入する。root も同一経路で解決し特別分岐なし。
- **過渡期（MT9 まで）**: `/{tenant_id}/...` ルーティングは未導入のため本 middleware はまだルーターへ
  mount せず、api は引き続き `AppState::default_tenant`（root）を全リクエストへ適用する。`Cache` 基盤と
  解決サービスは `AppState`（`tenant_resolution`）へ配線済みで、MT9 が middleware をテナントルート群へ
  付与し、`RequirePerms` の要求テナントを `default_tenant` からパス由来 `ResolvedTenant` へ置き換える。

## 2026-07-10（MT5: 全 Repository trait／ユースケースへ tenant_id 追加 — テナント分離の強制）

- **Repository trait のテナントスコープ化**（ADR-0009 §8。MariaDB に RLS がないため、アプリ層が
  唯一の分離防御線）: テナントスコープのテーブルを参照・検索するメソッドへ `tenant_id: TenantId`
  を追加し、sqlx 実装は必ず WHERE 句へ含める（`users` の `(tenant_id, email)` 検索、
  `clients` の `(tenant_id, client_id)` 解決・一覧・更新、auth session／authorization code／
  refresh token／consent／user_permissions／監査ログ参照）。グローバル一意キーによる本人解決
  （`users.id`/`sub`）・SSO セッション（ホスト単位共有）・ユーザー単位の全失効・テナント列を
  持たないテーブルは意図的に除外（根拠は `domain/repositories.rs` のモジュールコメント）。
- **ユースケースの `TenantContext` 対応**: 全サービスの公開メソッドが `TenantContext` を受け取り、
  リポジトリ呼び出しへ必ず伝搬。認証（ログイン・管理ログイン）のユーザー検索は所属元テナント限定、
  認可コード・refresh token の消費／検索は発行テナント一致必須。ドメインモデル
  （`User`（+`must_change_password`）・`Client`・`AuthSession`・`AuthorizationCode`・`RefreshToken`・
  `ClientConsent`・監査イベント）へ `tenant_id` を追加し、監査ログはテナント単位で追跡可能にした。
- **登録時の HOME メンバーシップ自動生成**（ADR-0009 §3）: `RegisterService` がユーザー作成と同時に
  `tenant_memberships` へ HOME/ACTIVE 行を投影する。
- **管理権限を ADR-0009 §4 の完全一致判定へ移行**: `idp.admin` を廃し、`RequirePerms<IdpAdmin>` は
  「要求テナントを scope に持つ `idp.tenant.admin`」の完全一致で判定（`idp.system.admin` は root
  scope のみ存在し root 自身の管理を含むため代替として許可）。`idp.system.admin` の付与・剥奪は
  保有者のみ実行可能（アプリ層で強制。DB の CHECK 制約と二重防御）。
- **過渡期（MT9 まで）の既定テナント**: api は起動時に root テナントを解決（fail-fast）し、
  `AppState::default_tenant` として全リクエストへ適用する。MT9 で `TenantResolver`／パス由来の
  解決へ置き換える。
- DB 統合テスト（`register`／`oidc_flow`／`internal_auth`／`admin_*`）と `scripts/e2e.sh` を
  新スキーマへ追随（root UUID・初期管理者 UUID は動的採番のため DB から解決）。初回ログインは
  F3 の設計どおり同意画面を経由する検証に修正した。e2e.sh はローカル mariadb/mysql クライアントへの
  フォールバックと、WebAuthn RP ID 制約（IP 不可）に伴う `ISSUER=http://localhost:8080` 化を含む。

## 2026-07-10（MT3・MT4: UUIDv7 生成の集約 + Tenant/TenantMembership ドメイン基盤）

- **MT3 — UUIDv7 導入**: `uuid` crate に `v7` feature を追加。エンティティ主キーの生成を
  `domain::id_generator::IdGenerator` トレイト（`infrastructure::id_generator::UuidV7Generator` が
  `Uuid::now_v7()` で実装）へ集約し、`RegisterService`（`User.id`/`sub`）・`ClientManagementService`
  （`Client.id`）・`PasskeyRegistrationService`（`WebAuthnCredential.id`）へ Clock と同様に注入した。
  `jti`／`correlation_id`／`csrf_id`／`PasskeyChallenge.id` 等の揮発トークンは時刻順序性が不要かつ
  生成時刻を露出させたくないため v4 のまま維持する（ADR-0009 §12）。
- **MT4 — テナントのドメイン基盤**: `domain::tenant::{Tenant, TenantId}`・
  `domain::tenant_membership::TenantMembership` エンティティと、`domain::tenant_context::{TenantContext,
  TenantScope}` 値オブジェクト（`TenantScope::matches` で「要求テナント ID と scope の完全一致」判定。
  祖先・配下は考慮しない。ADR-0009 §4）を追加。`domain::repositories::{TenantRepository,
  TenantMembershipRepository}` トレイトと sqlx 実装（`SqlxTenantRepository`／
  `SqlxTenantMembershipRepository`）を追加した。既存の Repository trait／ユースケースへの
  `tenant_id` 波及（MT5）はまだ行っていない。

## 2026-07-10（MT1・MT2: マルチテナントのデータ基盤 — 初期 DDL・seed の刷新）

- **初期マイグレーションを ADR-0009 の定義で全面刷新**（既存 0001〜0012 を廃棄し
  `0001_baseline` + `0002_seed_master_data` へ。全環境 DB 再作成が必要 —
  手順は `docs/OPERATIONS.md`「DB を作り直したいとき」）。
  - `tenants`（`is_root` 番兵列 + UNIQUE で **root を DB レベルで高々 1 行に担保**）・
    `tenant_memberships`（HOME/GUEST・招待トークンハッシュ）を新設。
  - `users`（`tenant_id`＝所属元・`must_change_password`・テナント内一意の email/username）・
    `clients`（テナント内一意の `client_id`）・`user_permissions`（主キーへ scope=`tenant_id`）・
    `auth_sessions`/`authorization_codes`/`refresh_tokens`/`client_consents`
    （`(tenant_id, client_id)` 複合外部キー）・`audit_log`（`tenant_id`）を再定義。
    `sso_sessions` はホスト共有のため tenant なし（境界はメンバーシップ検証。ADR-0009 §8）。
  - MariaDB 10.11 は索引付き生成列で `IF()`/`CASE` を許可しない（ERROR 1901）ため、
    番兵列の式は `(parent_tenant_id IS NULL) OR NULL` とした（ADR-0009 の DDL 例も修正）。
- **seed（冪等）**: root テナントを **UUIDv7 で投入時に動的採番**（固定リテラル廃止）。
  `idp.system.admin` の scope=root を縛る CHECK 制約は解決済み root UUID をリテラル化して
  `PREPARE`/`EXECUTE` で付与（ファイルは静的・チェックサム全環境一致）。権限コード
  （`idp.system.admin`/`idp.tenant.admin`）と初期管理者（root 所属・HOME メンバーシップ・
  `must_change_password=1`・`idp.system.admin` を DB 直接付与）を投入。
  `scripts/init.sh` が root UUID を標準出力へ記録する。
- **統合テスト `schema.rs` を刷新**: 全テーブル存在・seed 検証に加え、negative test
  （2 つ目の root 挿入拒否・`idp.system.admin` の非 root scope 付与拒否・同一テナント内
  email 重複拒否とテナント跨ぎ許容）を MariaDB 10.11 実機で検証。

## 2026-07-10（ADR-0009 再改訂: テナント独立モデル・Entra ID 型）

- **権限 scope のサブツリー伝播を廃止し、完全一致判定へ変更**。各テナントは独立した管理境界であり、
  root（system.admin）はテナントを作成できるが内部は操作できない。機能・URL は root 含め全テナント
  一律で、差は「必要な権限を付与できるユーザーが存在するか」のみ。
- **UUIDv7 を採用**（エンティティ主キー。揮発トークンは v4 のまま）。root テナントの固定 UUID
  （`00…0`）を廃し**投入時に動的採番**。`idp.system.admin` の scope = root を縛る CHECK 制約は、
  投入時に解決した root UUID をリテラル化して付与（`PREPARE`/`EXECUTE`）＋アプリ層で二重に強制し、
  `tenants` の単一 root は生成列 `is_root` + UNIQUE で担保する。
- **招待とメンバーシップ（`tenant_memberships`）を新設**。ユーザーの所属元は 1 テナントに限定し、
  他テナントへは招待（ゲスト）で参加する。ゲストのユーザー状態（パスワード・status・MFA 等）は
  参加先の管理者でも操作できず、所属元テナントと本人のみが管理する。認証は所属元テナントでのみ行い、
  参加先はホスト共有 SSO セッション + メンバーシップ判定で許可する。
- **マイグレーション方針を変更**: 段階的 expand/contract を廃し、初期 DDL・マスタデータを
  マルチテナント対応の定義で全面刷新して既存データは破棄する（全環境 DB 再作成。MVP 期の一度限り）。

## 2026-07-10（ADR-0009 改訂: マルチテナントアーキテクチャ）

- **ADR-0009 をレビューに基づき改訂**。`/root` エイリアスと `/admin` 横断名前空間を廃止し、
  root 含め URL を `/{tenant_id}/...` に完全一律化。権限判定を「要求テナントが権限 scope の
  サブツリー（祖先包含）に含まれるか」の一律判定へ一本化。
- レビュー指摘の反映: SSO セッションのテナント境界（認証は帰属テナント・認可は scope 判定、
  OIDC フローでは帰属テナント一致を検証）、api/web 分割（ADR-0007）との整合（contracts DTO へ
  `tenant_id` 追加）、WebAuthn RP ID はホスト単位でパスを含められない制約、`idp.system.admin` の
  scope = root 強制（CHECK 制約）、DISABLED の階層伝播、追加マイグレーション方式
  （ベースライン書き換え禁止・expand/contract）、テナント削除条件の文言修正 ほか。

## 2026-07-08（F4: Logout / F5: Token 管理）

- **F4 — RP-initiated Logout（設計仕様 §9.3 / OIDC RP-initiated Logout 1.0）**:
  - `clients` テーブルに `post_logout_redirect_uris`（JSON）、`frontchannel_logout_uri`、
    `backchannel_logout_uri`（VARCHAR）を追加（migration 0008）。
  - `LogoutService`: SSO セッション・関連 auth session・有効な authorization code を失効させ、
    back-channel 通知対象（`backchannel_logout_uri` を持つ client）と front-channel URI 一覧を返す。
  - `GET /logout`: SSO Cookie を失効させ、back-channel logout token（`logout+jwt`）を非同期 POST、
    front-channel logout 用 iframe HTML を返す（または `post_logout_redirect_uri` へ 302）。
  - Discovery に `end_session_endpoint`、`frontchannel_logout_supported`、`backchannel_logout_supported` を追加。

- **F5 — Token Revocation / Introspection（RFC 7009 / RFC 7662）**:
  - `revoked_access_tokens` テーブルを追加（migration 0009）。`jti` を PK として JTI ブロックリストを実現。
  - `RevocationService`: Refresh Token（DB の `revoked_at`）と Access Token（JTI ブロックリスト）の両方を
    失効させる。RFC 7009 §2.2 準拠: 失効済み・不存在でも 200 を返す。
  - `IntrospectionService`: confidential client 専用。Access Token（署名検証 + JTI ブロックリスト）と
    Refresh Token（DB 有効性確認）をイントロスペクトし `{ "active": true/false }` を返す。
  - `POST /revoke`（RFC 7009）、`POST /introspect`（RFC 7662）エンドポイントを追加。
  - `UserInfoService` も JTI ブロックリストを確認するよう更新。
  - Discovery に `revocation_endpoint`、`introspection_endpoint` を追加。

## 2026-07-08（F2: Refresh Token）

- **F2 — Refresh Token（設計仕様 §9.1）**:
  - `refresh_tokens` テーブルを追加（migration 0006）。`token_hash = SHA-256(plain_token)` で保存。
    `parent_hash` で rotation チェーンを追跡し reuse detection に使う。
  - `Scope::OfflineAccess`（`offline_access`）を追加。authorization_code フローで `offline_access`
    を要求した場合のみ Refresh Token を発行する。
  - Refresh Token rotation を実装: `POST /token?grant_type=refresh_token` で旧トークンを失効させ
    新トークンを発行する。TTL は旧トークンから引き継ぐ（スライドさせない）。
  - Reuse detection: 同一 token_hash から二重発行を検知した場合は `invalid_grant` を返し
    旧トークンも失効させる（`refresh_token.reuse_detected` 監査ログを記録）。
  - Discovery に `offline_access` scope と `refresh_token` grant type を追加。
  - 設定: `REFRESH_TOKEN_TTL_SECS`（既定 2592000 = 30 日）。

## 2026-07-08（K2: 署名鍵自動ローテーション / S1: SSL アクセラレーター対応）

- **K2 — 署名鍵自動ローテーション**: `KeyService::rotate_if_needed(lead_days)` を追加。
  ACTIVE 鍵の `not_after` まで `KEY_ROTATION_LEAD_DAYS`（既定 30 日）を切った際に新鍵（同アルゴリズム）を
  自動生成し旧鍵を RETIRED に変更する。`lib.rs` で tokio バックグラウンドタスクを起動時に spawn し、
  1 時間ごとに実行する。RETIRED 鍵は `not_after` 経過後に自動的に JWKS 非公開となる（既存挙動）。
  設定: `KEY_ROTATION_LEAD_DAYS`（日数、既定 30）。
- **S1 — SSL アクセラレーター/リバースプロキシ対応**:
  - `TRUST_FORWARDED_HEADERS`（bool、既定 `false`）を追加。有効時のみ `X-Forwarded-For` を信頼して
    実 IP を監査ログ・IP レート制限に使う。未設定時はヘッダを無視（ヘッダ偽装対策）。
  - `HSTS_MAX_AGE`（秒、既定 `0` = 無効）を追加。正値のとき `Strict-Transport-Security: max-age=N`
    をすべてのレスポンスに付与する。
  - セキュリティヘッダミドルウェア（`security_headers.rs`）を新設。全レスポンスに
    `X-Content-Type-Options: nosniff`・`Referrer-Policy: strict-origin-when-cross-origin`・
    `X-Frame-Options: DENY` を付与する。

## 2026-07-08（K1: 署名鍵管理 — ES256 対応・管理 API・管理コンソール）

- **EC(ES256) 対応**: `signing_keys.algorithm` の CHECK 制約に `ES256` を追加（migration 0005）。
  `p256` クレートを追加し、`infrastructure/jwt.rs` を RS256/ES256 両対応に書き換え（`Jwk` の `n`/`e` を
  `Option` 化、EC 用の `crv`/`x`/`y` フィールドを追加、`generate_ec_keypair()`・`ec_public_jwk()` 新設）。
- **複数鍵署名 / JWKS `not_after` フィルタ**: `list_published` を `not_after > UTC_TIMESTAMP(6)` 条件に修正。
  `Domain` 層の `SigningAlgorithm` enum を新設（`Rs256`/`Es256`）。`ActiveSigningKey` に `algorithm` フィールドを追加。
- **管理 API（`/admin/signing-keys`）**: `list_keys`・`generate_key`・`retire_key`・`delete_key` ハンドラを追加。
  `SigningKeyRepository` トレイトを `list_all`・`update_status`・`delete` で拡張し、sqlx 実装を追加。
  `KeyManagementError` を定義し `key_service.rs` に admin ユースケースを追加。
- **管理コンソール画面**: `crates/web` に `/admin/console/signing-keys` 画面を追加（一覧/生成/退役/削除）。
  Askama テンプレート `signing_keys.html`、`admin_dto.rs` の `SigningKeyView`、`api_client.rs` の
  4 メソッド、ハンドラ `admin_signing_keys_console.rs`（`list`・`generate`・`retire`・`delete`）を実装。
  ホーム画面ナビに署名鍵管理リンクを追加。i18n（`en`/`ja` `.ftl`）を追加。



- **web の HTML をコード生成から Askama テンプレートへ移行**。web crate の全画面（利用者ログイン・
  管理コンソール: ホーム/ログイン/クライアント一覧・登録/編集・詳細・secret 表示/利用者検索・権限/
  監査ログ/クライアント状況/共通レイアウト・告知）で `format!` による HTML 組み立てを廃し、
  `crates/web/templates/` 配下の `.html`（`console/layout.html` を継承）へ集約した。テンプレートは
  `.html` 拡張子により `{{ }}` 出力が自動 HTML エスケープされるため、手動エスケープの `html.rs`
  （`escape`）を削除。Askama のコンパイル時型検証で描画の型安全を担保（sqlx のコンパイル時クエリ検証と
  同じ思想）。外形（フォーム項目・CSRF 埋め込み・エスケープ）は不変で、web の全テスト・E2E 経路は維持。
  （エスケープは名前付き実体参照 `&lt;` から数値文字参照 `&#60;` へ変わるが XSS 安全性は同等。）
- **ビルド／デプロイのホスト分離**。ソースがある「ビルド側」と稼働する「デプロイ先」を別ホストとして扱う
  構成に整理した。`scripts/build.sh`（ビルド側）はネイティブ binary／Docker イメージのビルドと
  検証（`--check` = fmt/clippy/test）を行い、**コンテナは起動しない**。イメージ受け渡しはレジストリ
  （`--push`）と tar（`--save`）の両対応。デプロイ先用に `docker-compose.deploy.yml`（`build:` を持たず
  `image:` 参照のみ）を追加し、`init.sh`（初回・DB コンテナ新規作成）／`deploy.sh`（更新）は
  **ソースを持たずビルドせず**、`pull`／`docker load` 済みイメージで起動する。イメージ名は
  `${IMAGE_PREFIX:-idp}/{api,web,migrate}:${IMAGE_TAG:-latest}`（`.env` で設定）。`scripts/README.md`・
  `docs/OPERATIONS.md` を分離構成へ更新。

## 2026-07-06（C1 完了: API/Web サービス分割 — P5 テスト再編・E2E）

- **C1（コンテナ分離）完了**。ADR-0007 の理想形（真のサービス分割）を P0〜P5 まで実装。api（OIDC
  protocol・JSON 管理 API・内部 API・DB 唯一の所有者）と web（全 HTML 画面・API クライアント・DB 非依存）
  を cargo workspace（`core`/`contracts`/`api`/`web`）＋別コンテナ＋単一オリジンのリバースプロキシで分離。
- **P5 テスト再編**。api 単体統合テスト（`oidc_flow` は `/internal/authenticate` 駆動）＋web→api の自動
  E2E ハーネス `scripts/e2e.sh` を新設。e2e はapi・webを別プロセスで起動し、`/authorize`→web `/login`→
  `/token` の OIDC フローと管理コンソール（ログイン・クライアント作成・権限付与・状況/監査）を
  ブラウザ相当の HTTP で通す（実 MariaDB で全項目パスを確認）。
- 外部から見た OIDC 契約（`docs/OIDC_INPUT.md`）は分割の前後で不変。

## 2026-07-06（C1 P3-4・P4 完了: api の HTML 撤去とサービス分離 Compose）

- **api から HTML を撤去**（P3-4）。ログイン画面・管理コンソール 4 画面・i18n・html・`AdminHtmlSession`
  を削除し、api は OIDC protocol・JSON 管理 API・内部 API のみに。JSON 401/403 を返す
  `RequirePerms<IdpAdmin>` は残す。`/login`・`/admin/console/*` ルートを削除。core の未使用
  `admin_csrf_token` を削除。api 統合テストを再編（`oidc_flow` は `/internal/authenticate` 駆動へ、
  HTML 画面テストは web へ移動）。全テスト緑（fresh MariaDB）。
- **api / web / proxy の Compose 分離**（P4、ADR-0007 §2）。Dockerfile を 1 ワークスペース→2 バイナリ
  （`idp`＝api、`idp-web`＝web）＋2 実行ステージ（`runtime-api`・`runtime-web`）に。`docker-compose.yml`
  を `api`（DB 直結・非公開）／`web`（DB 非依存・非公開）／`proxy`（nginx。単一オリジンでパスルーティング）
  へ再構成。`docker/nginx.conf`: `/login`・`/admin/console/*`→web、`/internal/*` 遮断、他→api。
  `INTERNAL_SERVICE_TOKEN` を api・web で共有（`init.sh` が乱数生成、Compose が必須化）。`init.sh`・
  `deploy.sh`・`OPERATIONS.md`・`.env.example` を分離構成へ更新。
  （注: Docker イメージのビルドはサンドボックスの egress 制限〔apt ミラー 405〕で本環境では検証不可。
  ワークスペースはホスト cargo で両バイナリともビルド・実機起動を確認済み、compose config は妥当。）

## 2026-07-06（C1 P3-2 完了: ログイン画面を web crate へ移設）

- **ログイン画面（`/login` GET/POST）と i18n を `web` crate へ移設**（ADR-0007 P3-2）。web はフォーム描画と
  リダイレクトのみを担い、資格情報検証・SSO/code 発行は api の `POST /internal/authenticate` に委ねる。
  web は接続元情報（`X-Forwarded-For` 由来 IP・User-Agent）を転送し、成功時に api が返す `sso_session_id` を
  Cookie 化して `redirect_to` へ 302、`auth_session_id` Cookie を失効させる。エラーはローカライズして再描画。
- **ログイン CSRF 導出を `contracts` に一元化**（`idp_contracts::csrf::login_csrf_token`）。web（フォーム描画）と
  api（`LoginService` 検証）で同一導出を共有し、固定ベクタのユニットテストで齟齬を防ぐ。core は本関数へ委譲。
- web に i18n・cookies・correlation・login ハンドラを実装（api の presentation から移植）。api 側の `/login` は
  当面併存（全部入り E2E 維持のため。撤去は P3-4）。
- 検証: `cargo build`／`clippy` 警告なし／lib テスト（api 31・core 45・contracts 2・web 7）。**api＋web＋MariaDB を
  同時起動した実機 E2E**で、api `/authorize` →（別プロセスの）web `/login` GET/POST → api `/internal/authenticate`
  → SSO Cookie 発行＋`code` 付き RP リダイレクト → api `/token` で `id_token` 発行、まで疎通を確認。web が転送した
  IP が `sso_sessions.ip_address` に記録されることも確認。

## 2026-07-06（C1 P3-1 完了: contracts crate ＋ web crate 土台）

- **`contracts` crate（`idp-contracts`）を新設**（ADR-0007 §6）。内部認証 API（`/internal/authenticate*`）の
  DTO を api の presentation から移設し、**api サーバと web クライアントで同一の serde 型を共有**する
  （コンパイル時に契約整合を保証）。DB/axum/sqlx へは依存しない。
- **`web` crate（`idp-web` / bin=`idp-web`）を新設**。web 固有設定（`API_BASE_URL`・共有サービストークン・
  `WEB_BIND_ADDR` 等）、JSON ログ初期化、**reqwest ベースの API クライアント**（api への唯一の出入口。
  内部認証呼び出しにサービストークンと correlation_id を付与）、ヘルスチェック（`/healthz` liveness、
  `/readyz` は api への到達性で判断）を実装。
- **web は sqlx / idp-core に依存しない**ことを `cargo tree` で確認（crate 境界で分離を強制。ADR の肝）。
  api は無変更で全テスト緑。web バイナリの起動と `/healthz`=200・`/readyz`=503（api 停止時）を実機確認。
- P3 は規模が大きいためステージ分割で進める（本コミットは土台）。ログイン画面・管理コンソール・i18n の
  web 移設と、api からの HTML 撤去は後続ステージ。テスト再編は P5。

## 2026-07-06（C1 P2 完了: 内部認証 API）

- **内部認証エンドポイントを api に新設**（ADR-0007 §3・§5、C1 の P2）。OIDC 標準外の
  `POST /internal/authenticate`（OIDC ログイン）と `POST /internal/authenticate/admin`（管理コンソール）。
  将来の `web` crate が資格情報・`auth_session_id` 参照・接続元情報（IP/User-Agent）を JSON で転送し、api が
  既存の `LoginService`／`AdminLoginService`（資格情報検証・ロックアウト §4.3・IP レート制限・SSO/code 発行・
  監査）を実行して `result` タグ付き JSON を返す。Cookie 組み立て（Secure/HttpOnly/SameSite/TTL）とエラー
  文言のローカライズは呼び出し側（web）の責務。
- **サービス認証トークンで `/internal/*` を保護**（§5）。`X-Internal-Auth-Token` ヘッダを設定
  `INTERNAL_SERVICE_TOKEN`（未設定時は開発用の既定値＋起動時警告）と定数時間比較し、不一致は 401。
  `route_layer` で内部サブルータのみに適用（外部公開しない前提。リバースプロキシ遮断は P4）。
- 内部 DTO は presentation（`dto.rs`）に定義し `result` で判別（`contracts` crate 化は P3）。既存 HTML
  `/login`・`/admin/console/login` は同一プロセスのため引き続きユースケースを直接呼ぶ（API クライアント化は
  P3）。外部から見た OIDC 契約（§4.2）は不変。`docs/OIDC_INPUT.md` §4.3 に実装メモを追記。
- 検証: `cargo build`／`cargo clippy`（警告なし）／ユニットテスト（内部認証 3 件を追加）／MariaDB 実 DB での
  統合テスト `tests/internal_auth.rs`（トークン 401・CSRF 不一致・認証成功で SSO/code 発行・管理認証失敗）と
  既存 E2E（`oidc_flow` 等）を確認。

## 2026-07-06（ADR-0007 Accepted・C1 P1 完了: cargo workspace 化）

- **ADR-0007（API/Web サービス分割）を Accepted** とし、C1 の **P1（workspace 化）** を実施。単一クレート
  `idp` を **cargo workspace** に分割した。`crates/core`（lib=`idp_core`）に domain/application/
  infrastructure と config/telemetry（sqlx・DB 依存）を集約し、`crates/api`（lib=`idp_api` / bin=`idp`）に
  presentation と `run()` を置く。api は core を再エクスポートするため presentation 内の `crate::domain` 等の
  参照は不変。共通依存は `[workspace.dependencies]` で一元管理。
- **all-in-one を保ったままの crate 境界作成**（P1 の方針どおり。web/contracts crate と Web→API HTTP 化は
  後続 P2〜P5）。統合テストは `crates/api/tests/` へ移設（参照は `idp_api::*`）。`migrations/`・`i18n/` は
  リポジトリルート据え置きで、`sqlx::migrate!("../../migrations")`／`include_str!(CARGO_MANIFEST_DIR/../../i18n)`
  により crate から相対参照する。Dockerfile の builder を workspace ビルドへ更新（bin=`idp` は不変）。
- 検証: `cargo build --workspace`／`cargo clippy --workspace --all-targets`（警告なし）／lib ユニットテスト
  45 件パス。外部契約（OIDC・API 経路・バイナリ名）に変更なし。

## 2026-07-06（A3 完了: 状況確認画面）

- **状況確認画面をサーバレンダリングで実装**（A3 完了、設計仕様 §7）。監査／ログインログ一覧
  （`/admin/console/audit-logs`）とクライアント状況一覧（`/admin/console/status`）を追加。画面用
  extractor `AdminHtmlSession` で保護し、共通レイアウト `render_layout`（A2）の上に描画。JSON 管理 API
  （`GET /admin/audit-logs`、OpenAPI の正典）とは経路を分離。ホームから両画面へリンク。
- **監査ログ一覧画面**: `event_type`／`result`（`failure` 等のエラー絞り込みが主眼）／`client_id`／
  `correlation_id`／期間（`from`/`to`、RFC3339）で AND 絞り込みし、新しい順に表示。`offset` による前後
  ページ移動（フィルタ条件は URL エンコードで引き継ぐ）。日時形式が不正なら検索せずエラー表示。データ取得は
  API と同じ `AuditQueryService` を通す（読み取り専用のため CSRF は無い）。
- **クライアント状況一覧画面**: 各クライアントの状態（ACTIVE/DISABLED）・scope・**最終利用時刻**を表示。
  最終利用時刻は `audit_log`（成功した `token.issued`／`authorization_code.issued` の最新 `occurred_at`）
  から導出する（マイグレーション不要・書き込み経路への影響なし）。Application に読み取り専用の
  `ClientStatusService`（`ClientRepository` × `AuditLogQuery`、変更を担う `ClientManagementService` とは
  SRP で分離）を新設し、`AuditLogQuery::last_used_per_client`（client_id 別の最新利用時刻を 1 回の集計で取得）
  を追加。
- 単体テスト（監査行のエスケープ・失敗行の強調・空/日時エラー表示・ページャ・クエリ文字列のエンコード・
  状況一覧の最終利用時刻／未利用の `-`、サービスの突き合わせ）と統合テスト `tests/admin_status_console.rs`
  （未認証→ログイン画面へ 302、非管理者→403、状況一覧で最終利用時刻表示、監査一覧の絞り込み・不正日時→
  エラー）を追加。

## 2026-07-06（A2 完了: 利用者権限の付与・剥奪画面）

- **利用者権限の付与・剥奪のサーバレンダリング画面を実装**（A2 完了、ADR-0006）。`/admin/console/users*` に
  利用者検索（メール／ユーザー名）・保有権限の一覧・付与フォーム（付与可能コードの datalist 付き）・
  剥奪ボタンを提供。画面用 extractor `AdminHtmlSession` で保護し、共通レイアウト `render_layout`（A2）の
  上に描画する。データ操作は JSON API と同じ `PermissionManagementService` を通し、検証・監査記録を二重化しない。
- **経路分離**: ブラウザ向けコンソールは `/admin/console/users*`、JSON 管理 API（OpenAPI の正典）は
  `/admin/users/{user_id}/permissions` のまま。付与・剥奪の POST は Post/Redirect/Get で権限画面へ 302 し、
  失敗（CSRF 不一致・未知コード等）は `error` クエリで伝える（二重送信の回避）。CSRF は SSO セッション id
  由来の同期トークン `console_csrf_token`。利用者入力は `presentation::html::escape` を通し格納型 XSS を防止。
- Application の `PermissionManagementService` に画面用の読み取り（識別子→利用者解決 `find_user_by_identifier`・
  表示用 `get_user`・付与可能コード一覧 `available_codes`）を追加。付与可能コードは `permissions` マスタを
  単一の出所とし、`UserPermissionRepository::list_available_codes` で取得する（許可値の直書き重複なし）。
- 単体テスト（検索結果／権限画面のレンダリングと HTML エスケープ・エラークエリ→i18n キー写像・
  リダイレクト先の検証、サービスの識別子解決／付与可能コード）と統合テスト `tests/admin_users_console.rs`
  （未認証→ログイン画面へ 302、非管理者→403、メール／ユーザー名検索、CSRF 不一致・未知コード→302 error、
  付与／剥奪の 302 と `audit_log` 記録、不存在・非 UUID→404）を追加。

## 2026-07-06（A1: クライアント（RP）管理画面、A2 コンソール基盤の上に実装）

- **クライアント（RP）管理のサーバレンダリング画面を実装**（A1 完了、設計仕様 §9.3）。一覧・新規登録・
  詳細・編集・secret 再発行・無効化（状態 DISABLED）を `/admin/console/clients*` で提供。画面用 extractor
  `AdminHtmlSession` で保護し、共通レイアウト `render_layout`（A2）の上に描画する。データ操作は JSON API と
  同じ `ClientManagementService` を通し、検証・監査記録・secret 発行のロジックを二重化しない。
- **経路分離**: ブラウザ向けコンソールは `/admin/console/*`、JSON 管理 API（OpenAPI の正典）は
  `/admin/*` に整理。これに伴い前コミットの A2 コンソール（ログイン/ホーム/ログアウト）も `/admin/console/*`
  へ移設（`/admin/console/login`・`/admin/console`・`/admin/console/logout`）。
- **セキュリティ**: 利用者入力を HTML へ差し込む箇所は新設の `presentation::html::escape` を通し格納型 XSS を防止。
  ログイン後の状態変更フォームは SSO セッション id 由来の同期トークン `console_csrf_token` で CSRF 対策。
  `client_secret` は confidential の作成・再発行時に**その画面でのみ**平文表示（DB はハッシュのみ）。
- 単体テスト（入力パース・HTML エスケープ・一覧のエスケープ・CSRF 導出）と統合テスト
  `tests/admin_clients_console.rs`（未認証→ログイン画面へ 302、CSRF 不一致・不正 scope→400、
  confidential 作成で secret 一度表示、詳細・編集で DISABLED 反映、secret 再発行、不存在→404、非管理者→403）を追加。

## 2026-07-06（A2: 管理コンソール基盤 UI・管理ログイン、ADR-0006 §6）

- **管理コンソールのサーバレンダリング基盤 UI を実装**（A2、ADR-0006 §6）。管理ログイン
  （`GET/POST /admin/console/login`）・ホーム（`GET /admin/console`）・ログアウト（`POST /admin/console/logout`）を追加。
  文言は既存ログイン画面と同じ `fluent`（en/ja）。
- 管理ログインは OIDC クライアント不要で **SSO セッションを直接発行**する（`/authorize` 由来の
  `auth_session_id`・code 発行・redirect を伴わない）。初回デプロイ時にクライアントが存在しなくても
  コンソールへ入れる（鶏卵問題の回避）。資格情報検証・ロックアウト（§4.3）・IP レート制限は通常ログインと
  同方針で、レート制限器は共有。`idp.admin` 非保有の正当利用者は Forbidden（SSO 非発行）。CSRF は同期
  トークン方式（GET で `admin_csrf_id` Cookie を発行し一方向ハッシュをフォームへ埋め込む）。
- Application に `AdminLoginService`（ログイン／ログアウト。ログアウトは `sso_session.terminated` を監査）、
  Presentation に画面用の認可 extractor `AdminHtmlSession`（未認証→ログイン画面へ 302／権限不足→403 HTML。
  API 用 `RequirePerms<IdpAdmin>` の JSON 401/403 と使い分け）と共通レイアウト `render_layout`
  （A1/A3 の画面はこの上に差し込む）を追加。監査は既存種別のみ使用（§7 の追加なし）。
- 単体テスト（CSRF 導出の決定性・名前空間分離、フォーム／レイアウトのレンダリングと i18n）と統合テスト
  `tests/admin_console.rs`（ログイン画面→CSRF 発行、未認証ホーム→302、CSRF 不一致→400、正当ログイン→
  SSO 発行→ホーム 200→ログアウトで失効、非管理者→403）を追加。

## 2026-07-06（A2: 利用者権限の付与・剥奪 API）

- **利用者権限の付与・剥奪 API を実装**（管理コンソール基盤 A2、ADR-0006、設計仕様 §7）。
  `/admin/users/{user_id}/permissions` の付与（`POST`）・剥奪（`DELETE {permission_code}`）・参照（`GET`）
  （`RequirePerms<IdpAdmin>`）。付与は冪等、未知の権限コードは 400、対象利用者不存在は 404、
  `user_id` が UUID でなければ 400。応答は操作後の保有権限コード一覧。
- 参照（保護判定）の `AdminAccessService` と責務を分離（SRP）し、管理（変更）用の
  `PermissionManagementService`（Application）を新設。付与・剥奪を `AuditEventType::UserPermission*`
  （`user_permission.granted` / `.revoked`、actor を `user_id`・対象と権限コードを `reason` に記録）
  として `audit_log` へ出力する結線を追加。DTO（`GrantPermissionRequest` / `UserPermissionsResponse`）と
  `admin_permissions` ハンドラを追加し OpenAPI（tag `admin`）へ掲載。単体テスト（付与/剥奪の監査記録・
  空/未知コード・対象不存在）と統合テスト `tests/admin_permissions.rs`（401/403/400/404・付与/剥奪・
  冪等・監査記録）を追加。

## 2026-07-06（A3: 監査/ログイン ログ参照 API）

- **監査ログ参照 API を実装**（状況確認画面 A3、設計仕様 §7）。`GET /admin/audit-logs`
  （`RequirePerms<IdpAdmin>`）で `audit_log` を `event_type` / `result`（`failure` 等のエラー絞り込み）/
  期間（`from`/`to`、RFC3339）/ `client_id` / `correlation_id` で AND 絞り込みし、新しい順
  （`occurred_at` 降順・同時刻は `id` 降順）に返す。`limit`（既定 50・上限 200）・`offset` でページング。
- 読み取り境界 `AuditLogQuery`（書き込みの `AuditLogSink` と分離）と読み取りモデル `AuditLogEntry` /
  `AuditLogFilter` をドメインに追加。sqlx 実装は `QueryBuilder` で条件を安全にバインド。Application に
  `AuditQueryService`（limit クランプ・空文字正規化）、Presentation に `admin_audit` ハンドラと DTO を追加。
  OpenAPI に tag `admin` で掲載。単体テスト（limit クランプ・正規化）と統合テスト `tests/admin_audit.rs`
  （絞り込み・新しい順・401/403/400）を追加。

## 2026-07-06（A1: クライアント（RP）登録・管理 API）

- **クライアント管理 API を実装**（設計仕様 §9.3、Progress A1）。`/admin/clients` の CRUD＋シークレット
  再発行（`RequirePerms<IdpAdmin>` で保護）。`client_id` 自動採番、`client_secret` は confidential の
  登録・再発行時に**その応答でのみ**平文表示し DB は argon2 ハッシュのみ。`client_type` に応じ
  `token_endpoint_auth_method`（public=`none`／confidential=`client_secret_basic`）と PKCE を設定。
  redirect_uri は完全一致・複数登録・フラグメント／ワイルドカード禁止をアプリ層で検証。scope は
  `openid` を含む OIDC scope に限定。
- ドメインに `ClientRepository::{create,list,update}` を追加し sqlx 実装、Application に
  `ClientManagementService`（検証・secret 発行・監査記録）、Presentation に `admin_clients` ハンドラ群と
  DTO を追加。`ApiError::NotFound`（404）を追加。監査種別 `client.registered`/`.updated`/
  `.secret_rotated` を追加（§7）。OpenAPI に tag `admin` で自動掲載。
- 単体テスト（redirect_uri／scope／app_name 検証）と統合テスト `tests/admin_clients.rs`
  （401/403/400/CRUD/secret 再発行、権限の無い利用者の 403）を追加。

## 2026-07-06（管理機能の権限モデル基盤・A2 の前提、ADR-0006）

- **利用者権限モデルを実装**（ADR-0006）。OIDC scope（claim 制御）とは別軸の「利用者権限
  （permission code）」を新設。マイグレーション `0003_permissions_and_user_permissions`
  （`permissions` マスタ＋`user_permissions` 多対多）と seed `0004_seed_admin_permission`
  （`idp.admin` の登録と初期管理者への冪等付与）を追加。
- ドメインに値オブジェクト `PermissionCode` と `UserPermissionRepository`（DIP 境界。参照/付与/剥奪）、
  Infrastructure に sqlx 実装、Application に `AdminAccessService`（SSO セッション→利用者解決→権限突合。
  検証は Application 層で完結し Presentation には可否のみ返す）、Presentation に `RequirePerms<IdpAdmin>`
  extractor を追加。保護の疎通確認用に内部エンドポイント `GET /admin/whoami`（`idp.admin` 必須）を追加。
- 監査イベント種別 `user_permission.granted` / `.revoked` を追加（設計仕様 §7）。

## 2026-07-05（インフラ整備 T9〜T13・D2）

- **T9: IdP アプリのコンテナ化と Compose 統合**。マルチステージ `Dockerfile`（`rust:slim` ビルド →
  `debian:bookworm-slim` 実行、非 root、i18n は include_str! で埋め込み、TLS は rustls）を追加。
  `docker-compose.yml` に `web` サービス（`/healthz` の HEALTHCHECK、`mariadb` の service_healthy を
  `depends_on`、`DATABASE_URL` はサービス名 `mariadb` で解決）と、DDL/マスタデータ適用専用の
  ワンショット `migrate` サービス（sqlx-cli。`profiles: [tools]`）を追加。`.dockerignore` も追加。
- **T10: 秘密情報・設定の .env 一元管理**。`.env.example` を全設定（MariaDB パスワード・
  `KEY_ENCRYPTION_KEY`・`TEST_DATABASE_URL` を含む）の単一テンプレートへ拡充。Compose の秘密値を
  `.env` から注入するようパラメータ化。`config.rs` は空文字の環境変数を「未設定」として扱うよう
  堅牢化（Compose の `${VAR:-}` 由来の空値でパースが失敗しないように。単体テスト追加）。
- **T11: 初期設定スクリプト**。`scripts/init.sh`（冪等）でパスワード・鍵を乱数生成して `.env` を作成
  （既存は上書きしない）→ MariaDB 起動 → マイグレーション適用 → web ビルド・起動 → healthz 待機。
  共通処理は `scripts/lib.sh` に集約。
- **T12: 初期管理ユーザーのマスタデータ**。seed マイグレーション
  `migrations/0002_seed_initial_admin`（冪等 upsert。固定 id/sub、既定パスワードは変更前提）を追加。
  password_hash は argon2id（アプリと同一形式）。
- **T13: デプロイスクリプト**。`scripts/deploy.sh`（イメージビルド → DDL/マスタデータ適用の専用ジョブ →
  `up -d web` → `/readyz` 確認、ロールバック方針をコメント記載）。
- **D2: 運用手順を OPERATIONS.md に統合**。初期化・デプロイ・ロールバック・初期管理ユーザーの
  パスワード変更・`KEY_ENCRYPTION_KEY` ローテーション・バックアップ/リストアの手順を追記。

## 2026-07-05

- **T8: テスト & MVP 完了条件の E2E 検証**。`tests/oidc_flow.rs` で設計仕様 §10 の条件 1〜13 を
  通しで検証（登録 → /authorize → /login → code → /token → /userinfo → SSO 復元、code 再利用拒否、
  ロックアウト、client 認証失敗、監査ログの記録）。PKCE は RFC 7636 Appendix B のテストベクタを使用。
  純粋ロジック（PKCE / CSRF / Cookie / redirect URL 構築 / i18n / レート制限 / 認可検証）の
  単体テストを各モジュールへ追加。
- **D1: 付随ドキュメント整備**。`docs/ARCHITECTURE.md`（レイヤー構成・実装パターン）と
  `docs/OPERATIONS.md`（起動・マイグレーション・テスト・環境変数などの手順）を新設。
  utoipa による OpenAPI 自動生成（`/api/openapi.json`）と Swagger UI（`/api/docs`）を追加し、
  API 仕様の唯一の出所とした。
- **T7: 監査ログを横断結線**。`AuditService` が全イベント（login.succeeded/failed/locked、
  authorization_code.issued/used/reuse_detected、token.issued、client.authentication_failed、
  sso_session.created/resumed/expired）を tracing（JSON）と `audit_log` テーブルへ二重出力。
  correlation_id ミドルウェア（`x-request-id`）でリクエストと監査イベントを一気通貫で追跡可能に。
- **T6: Discovery / JWKS / UserInfo を実装**。`GET /.well-known/openid-configuration`（issuer は
  末尾スラッシュ無しで `iss` と完全一致）、`GET /.well-known/jwks.json`（ACTIVE+RETIRED 公開）、
  `GET /userinfo`（Bearer の `typ=at+jwt` JWT を署名・iss・aud・exp（±60s スキュー）で検証し、
  scope（openid/email/profile）に応じたクレームのみ返却）。
- **T5: トークン発行 `POST /token` を実装**。client 認証（confidential=`client_secret_basic`
  （argon2 検証・Basic ヘッダの percent-decode 対応）/ public=なし、header と body の client_id
  不一致は `invalid_request`）、code の原子的 one-time 消費（`UPDATE ... WHERE used_at IS NULL AND
  expires_at > ?` の affected rows 判定。0 行 = `invalid_grant` + `authorization_code.reuse_detected`）、
  PKCE S256 検証（verifier 43〜128 文字・文字種検証）、ID Token（`typ=JWT`、scope に応じた
  email/profile クレーム付与）と Access Token（`typ=at+jwt`、`aud=<issuer>/userinfo`）の RS256 発行、
  `Cache-Control: no-store` / `Pragma: no-cache`。
- **T4: 認可フロー中核を実装**。`GET /authorize`（検証: client 存在/ACTIVE・redirect_uri 完全一致・
  `response_type=code`・scope が openid を含み client 登録 scope の部分集合・state/nonce 必須・
  `code_challenge_method=S256`。client_id/redirect_uri 不正はリダイレクトせず 400、他は redirect_uri
  へエラー返却）、`GET/POST /login`（fluent による en/ja の i18n 画面、CSRF は auth_session_id 由来の
  同期トークン、username 単位 連続 10 回失敗 → 15 分ロック、IP 単位レート制限、成功時リセット）、
  SSO セッション（Cookie は平文 session_id・DB は SHA-256。復元時 idle +8h 延長・absolute 不変・
  `auth_time` は初回値維持）、code 発行共通モジュール（`code_issuance.rs`、256bit 乱数・ハッシュ保存・
  TTL 60s）。Cookie は `HttpOnly`/`Secure`(設定可)/`SameSite=Lax`/`Path=/`。302 Found でリダイレクト。
- **T3: ユーザー登録を実装**。`POST /auth/register`（設計仕様 §4.1）。argon2id でパスワードハッシュ、
  `id`/`sub`(UUID v4) 採番、`status=ACTIVE` / `email_verified=false`。email・preferred_username の
  一意性（DB UNIQUE ＋ 事前チェック、競合は 409）、簡易バリデーション（メール形式・パスワード最小長 8）。
  `PasswordHasher` トレイト（domain）＋ argon2 実装、`UserRepository` の sqlx 実装、`RegisterService`、
  presentation の DTO / `ApiError` / `AppState`（`FromRef`）を追加。統合テスト `tests/register.rs`
  （201 / 409 / 400 と DB 永続化）。
- **T2: 署名鍵と JWT 基盤を実装**。RSA-2048 鍵生成、秘密鍵の AES-256-GCM 暗号化保存、`kid` 採番、
  RS256 署名（ID Token=`typ=JWT` / Access Token=`typ=at+jwt`）、JWKS 構築（公開鍵 PEM→`n`/`e`）、
  検証用 `DecodingKey` を実装（`infrastructure/jwt.rs`・`crypto.rs`）。`SigningKeyRepository` の sqlx 実装、
  `KeyService`（ACTIVE 鍵ブートストラップ＝冪等 / 署名材料取得 / JWKS）、`Clock` トレイトと `SystemClock`、
  `KEY_ENCRYPTION_KEY` 設定を追加。クレートを lib+bin 構成へ変更（`src/lib.rs::run()`）。起動時に署名鍵を
  ブートストラップする。sqlx 互換のためベースラインの照合を `utf8mb4_unicode_ci` に統一（`_bin` は
  VARBINARY 扱いで String デコード不可のため。完全一致比較はアプリ層で担保）。統合テスト `tests/keys.rs`
  で「鍵ブートストラップ→署名→JWKS 検証」を確認。
- **T1: データモデルとマイグレーションを実装**。ベースラインマイグレーション
  `migrations/0001_baseline`（up/down）で 6 テーブル（users / clients / auth_sessions /
  sso_sessions / authorization_codes / signing_keys）＋ `audit_log` を作成（MariaDB 向け型読み替え:
  UUID→`CHAR(36)`、enum→`VARCHAR`+`CHECK`、時刻→UTC `DATETIME(6)`、配列→`JSON`、CITEXT 相当のみ
  大小無視照合、既定は `utf8mb4_bin`）。ドメイン層にエンティティ・列挙・監査イベント型・リポジトリ
  トレイト（DIP 境界、`#[async_trait]`）を追加。DB 接続のセッションタイムゾーンを UTC に固定。
  マイグレーション整合の統合テスト（`tests/schema.rs`）を追加。

- **ドキュメントを実装スタック（Rust + MariaDB）に整合**。CLAUDE.md・db-migration スキルを
  Rust/axum/sqlx 前提へ改訂し、ADR-0005（スタック採用）を追加、ADR-0004 と OIDC_INPUT.md に
  MariaDB 読み替え注記を追加（ADR-0005）。
- **T0: プロジェクト基盤を構築**。単一バイナリクレート（`idp`）を作成し、DDD 4層のモジュール骨格
  （domain / application / infrastructure / presentation）を配置。axum によるサーバ起動、`config`
  モジュール（環境変数 > 既定値、issuer 正規化・各種 TTL）、`tracing` の JSON 構造化ログ、sqlx の
  MariaDB 接続プール、起動時のスキーマ version 照合（`_sqlx_migrations` を SSOT とした fail-fast）、
  `/healthz`・`/readyz` ヘルスチェック、開発用 `docker-compose.yml`（MariaDB 10.11 / 任意 Redis）を実装。

- **F3: Consent（同意画面・同意済み scope 記録、`prompt`/`max_age` 正式対応）**。
  マイグレーション `0007_client_consents`（user_id×client_id の unique 制約付き JSON スコープ保持）を追加。
  ドメイン層に `ClientConsent` エンティティ・`ClientConsentRepository` trait・監査イベント
  `ConsentGranted`/`ConsentDenied` を追加。`AuthorizeRequest` に `prompt`/`max_age` フィールドを追加し、
  `prompt=none`（インタラクション禁止）・`prompt=login`（強制再認証）・`max_age` 超過時の強制再認証を実装。
  `ConsentRequired` を `AuthorizeOutcome`/`LoginOutcome` に追加し、SSO 再利用パスでも同意確認を行う。
  `/internal/consent-info`・`/internal/consent-approve`・`/internal/consent-deny` の 3 エンドポイントを
  api に追加。web 側に `/consent` 画面（Askama テンプレート、CSRF 保護付き POST）を追加。
  i18n（en/ja）の同意画面文言を追加。

## TOTP MFA（任意の二段階認証）実装

ユーザーが自分で TOTP（Google Authenticator 等）を登録・削除できる任意 MFA を実装。
強制ではなくオプション機能として提供する。

- **DB**: `user_totp_secrets`（`secret_encrypted`, `confirmed_at`）テーブルを追加（migration 0010）。
  `auth_sessions` に `password_verified_at` カラムを追加（migration 0011）。
- **Domain**: `TotpSecret` エンティティ、`TotpSecretRepository` トレイト、
  `AuthSession.password_verified_at` フィールド追加。
- **Application**: `TotpRegistrationService`（setup/confirm/delete）、`MfaLoginService`（TOTPステップ）。
  シークレットは AES-256-GCM 暗号化（署名鍵と同方式）。コード検証は `totp-rs 5.x` を使用。
- **API**: `/internal/mfa/totp/setup|confirm|delete|verify` 4 エンドポイントを追加。
  `InternalAuthenticateResponse::MfaRequired` バリアント追加。
- **Web**: `/account/mfa/totp/setup`（セルフ登録）・`/mfa/totp`（ログインフロー TOTP 入力）を追加。
  セットアップ画面は QR コード SVG（サーバサイド生成、`qrcode 0.14`）と生 base32 シークレットの両方を表示
  （QR が使えないユーザーも手動入力できる）。
- **i18n**: MFA 関連文言を en/ja に追加。

## T4: Passkey（WebAuthn）登録・認証（2026-07-08）

- **Migration 0012**: `user_webauthn_credentials`（クレデンシャル保存）・`passkey_challenges`（チャレンジ
  一時保存。TTL 5 分）テーブルを追加。クレデンシャル ID は base64url VARCHAR(512)で保存。
- **Domain**: `WebAuthnCredential`・`PasskeyChallenge` エンティティ、
  `WebAuthnCredentialRepository`・`PasskeyChallengeRepository` トレイト追加。
- **Infrastructure**: `WebAuthnService`（`webauthn-rs 0.5`ラッパー。RP ID/Origin は `config.issuer()` から自動導出）、
  `SqlxWebAuthnCredentialRepository`・`SqlxPasskeyChallengeRepository` 追加。
- **Application**: `PasskeyRegistrationService`（begin/complete/delete/list）、
  `PasskeyAuthenticationService`（begin/complete、Discoverable Credentials flow）追加。
  認証成功後は通常の OIDC フロー（consent → code 発行）と同一パスを通る。
- **API**: `/internal/passkey/register/begin|complete`・`/internal/passkey/delete|list`・
  `/internal/passkey/login/begin|complete` 6 エンドポイント追加。
- **Web**: `/account/passkey`（一覧）・`/account/passkey/register`（登録）・
  `/passkey/register/begin|complete`・`/passkey/login/begin|complete` を追加。
  ログイン画面に「パスキーでサインイン」ボタンを追加（WebAuthn JS API 経由）。
- **i18n**: Passkey 関連文言を en/ja に追加。
