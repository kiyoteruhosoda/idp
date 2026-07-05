# ARCHITECTURE

本プロジェクトの設計・レイヤー構成・命名規則をまとめる（DDD の実装パターン解説）。
操作手順は `OPERATIONS.md`、API 仕様は自動生成の OpenAPI（`/api/openapi.json`・Swagger UI `/api/docs`）を参照。

## レイヤー構成（DDD 4層）

依存方向は **Presentation → Application → Domain**。Infrastructure は Domain のトレイトを実装する
（依存性逆転、DIP）。単一バイナリクレート（lib + bin 構成、`src/lib.rs::run()` がブートストラップ）。

```
src/
  main.rs             # エントリポイント（lib.rs::run() を呼ぶだけ）
  lib.rs              # 起動シーケンス: 設定 → ログ → DB 接続 → スキーマ照合 → 鍵ブートストラップ → HTTP
  config.rs           # 設定（環境変数 > DB system_settings > 既定値）。生の env 参照は禁止
  telemetry.rs        # tracing の JSON 構造化ログ初期化

  domain/             # ビジネスロジック（フレームワーク・DB 非依存）
    user.rs client.rs auth_session.rs sso_session.rs authorization_code.rs signing_key.rs
    values.rs         # 文字列 enum（DB の VARCHAR+CHECK に対応する許可値の集中管理）
    pkce.rs           # PKCE S256 検証（純粋関数）
    repositories.rs   # リポジトリトレイト（DIP 境界）
    clock.rs password.rs rate_limit.rs   # 時刻・ハッシュ・レート制限の抽象
    audit.rs          # 監査イベント型（設計仕様 §7）
    error.rs          # DomainError と OAuth/OIDC エラーコード

  application/        # ユースケース（トレイト越しに Infrastructure へ依存）
    register.rs       # ユーザー登録（§4.1）
    authorize.rs      # 認可リクエスト検証・SSO 復元・AuthSession 作成（§4.2）
    login.rs          # 認証・ロックポリシー・SSO 発行（§4.3）
    code_issuance.rs  # authorization code 発行の共通モジュール（§4.2/§4.3 で共用）
    token.rs          # client 認証・code 消費・PKCE 検証・トークン発行（§4.4, §5）
    userinfo.rs       # Access Token 検証と scope 別クレーム返却（§4.7）
    key_service.rs    # 署名鍵ブートストラップ・JWKS 構築
    audit.rs          # AuditService（tracing + audit_log テーブルへ二重出力）

  infrastructure/     # Domain トレイトの実装
    repositories/     # sqlx（MariaDB）実装。UUID=CHAR(36)、JSON カラムはバイト列で受けて parse
    jwt.rs            # RS256 署名・JWK 変換・検証キー生成
    crypto.rs         # 乱数トークン・SHA-256・AES-256-GCM（秘密鍵の暗号化保存）
    password.rs       # argon2 実装
    clock.rs          # SystemClock
    rate_limit.rs     # インメモリのログインレート制限（単一インスタンス前提）
    db.rs             # 接続プール（セッション TZ を UTC 固定）・スキーマ version 照合

  presentation/       # axum ハンドラ・ルータ・DTO
    router.rs         # ルータ集約（merge/nest）・ミドルウェア適用
    handlers/         # エンドポイント別ハンドラ（authorize/login/token/userinfo/discovery/…）
    state.rs          # AppState（依存注入の組み立ては AppState::build に集約）
    dto.rs            # 〇〇Request / 〇〇Response（serde + utoipa::ToSchema）
    cookies.rs        # Cookie 読み書き（HttpOnly/Secure/SameSite=Lax/Path=/）
    correlation.rs    # correlation_id（x-request-id）ミドルウェア
    i18n.rs           # fluent によるログイン画面の翻訳（en/ja）
    openapi.rs        # utoipa の ApiDoc（OpenAPI 生成の唯一の出所）
    error.rs          # ApiError → HTTP ステータス/JSON 変換
```

## 実装パターン

- **DIP 境界はトレイト**: `domain/repositories.rs` の各トレイト（`UserRepository` 等）と
  `Clock` / `PasswordHasher` / `LoginRateLimiter`。Application 層はこれらのみに依存し、
  `Arc<dyn Trait>` でコンストラクタ注入する。組み立ては `AppState::build` に集約。
- **axum への注入**: ハンドラは `State<AppState>`（または `FromRef` による部分注入）で
  サービスを受け取る。リクエスト由来の値は extractor（`Query` / `Form` / `Json`）で受ける。
- **DTO と Domain の分離**: serde DTO から直接 Domain モデルを作らず、Application 層の
  Command（`RegisterCommand` 等）へ詰め替える。
- **列挙の集中管理**: DB は `VARCHAR` + `CHECK`、Rust 側は `domain/values.rs` の
  `string_enum!` で許可値を一元管理（DB ネイティブ ENUM は使わない）。
- **時刻**: 常に UTC。取得は `Clock` トレイト越し（テストで固定実装に差し替える）。
  JWT の `exp` 検証も `Clock` 経由で自前判定する（±60 秒のスキュー許容）。
- **秘匿値の保存**: authorization code / SSO session_id は平文を DB に置かず
  `SHA-256` ハッシュのみ保存。署名秘密鍵は AES-256-GCM で暗号化（鍵は DB 外 = 環境変数）。
- **識別子**: DB キーに使うランダム識別子（`auth_sessions.id`・session_id）は
  ci 照合下でも厳密一致になるよう小文字 16 進で生成する（`crypto::random_hex`）。

## 命名規則

- スキーマ: `〇〇Request`（Deserialize） / `〇〇Response`（Serialize）。
- ユースケースは `〇〇Service`＋`〇〇Command`／`〇〇Outcome`。
- ドメイン語彙（ユビキタス言語）を使う。`util` / `helper` は作らない。

## 横断関心

- **監査ログ（§7）**: `AuditService` が全イベントを tracing（JSON）と `audit_log` テーブルへ
  二重出力する。`correlation_id` は `presentation/correlation.rs` のミドルウェアが
  リクエスト単位で採番（`x-request-id`）し、HTTP → ユースケース → 監査イベントを一気通貫で追跡する。
- **CSRF**: ログインフォームのトークンは `SHA-256("csrf:" + auth_session_id)` を埋め込み、
  POST 時に Cookie から再計算して照合する（同期トークン方式。サーバ側の追加保存は不要）。
- **ロック/レート制限**: username 単位は `users.failed_login_count`／`locked_until`
  （連続 10 回失敗 → 15 分）。IP 単位は `LoginRateLimiter`（MVP はインメモリ実装）。
- **スキーマ整合**: 起動時に sqlx マイグレーション version と `_sqlx_migrations` を突合し、
  DB が期待未満なら fail-fast（ADR-0004。適用そのものは行わない）。
