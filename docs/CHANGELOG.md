# CHANGELOG

完了した重要な変更の要約（詳しい経緯は `history/`、設計判断は `adr/`）。

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
