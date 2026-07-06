# CHANGELOG

完了した重要な変更の要約（詳しい経緯は `history/`、設計判断は `adr/`）。

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
