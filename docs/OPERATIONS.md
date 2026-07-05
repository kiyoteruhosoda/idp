# OPERATIONS

「〇〇したいとき、〇〇する」の手順のみをまとめる。設計の背景は `ARCHITECTURE.md`、
API 仕様は自動生成の OpenAPI（起動後 `/api/openapi.json`・Swagger UI `/api/docs`）を参照。

## 開発環境を起動したいとき

```sh
docker compose up -d mariadb          # MariaDB 10.11 を起動
sqlx migrate run                       # マイグレーション適用（要 DATABASE_URL）
cargo run                              # IdP サーバ起動（既定: 0.0.0.0:8080）
```

## マイグレーションを適用したいとき

```sh
DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' sqlx migrate run
```

新規作成の規約は `migrations/README.md` と `.claude/skills/db-migration/` を参照。
アプリは起動時に version を照合するだけで適用は行わない。

## テストを実行したいとき

```sh
cargo test                             # 単体テストのみ（DB 不要）
TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test   # 統合テスト込み
```

統合テスト（`tests/schema.rs` / `keys.rs` / `register.rs` / `oidc_flow.rs`）は
`TEST_DATABASE_URL` 未設定時はスキップされる。

## クライアントを登録したいとき

MVP には管理 API がないため、SQL で `clients` へ登録する。

```sql
INSERT INTO clients (id, client_id, client_secret_hash, client_type, client_status,
  app_name, redirect_uris, grant_types, response_types, scopes,
  token_endpoint_auth_method, require_pkce)
VALUES (UUID(), 'my-app', NULL, 'public', 'ACTIVE',
  'My App', '["https://app.example.com/callback"]', '["authorization_code"]', '["code"]',
  '["openid","profile","email"]', 'none', 1);
```

confidential client の場合は `client_type='confidential'`、
`token_endpoint_auth_method='client_secret_basic'` とし、`client_secret_hash` に
argon2 ハッシュ（アプリと同じ `Argon2PasswordHasher` で生成した PHC 文字列）を設定する。

## 環境変数を設定したいとき

| 変数 | 既定値 | 用途 |
|---|---|---|
| `ISSUER` | `http://localhost:8080` | OIDC issuer（末尾スラッシュ無しに正規化） |
| `BIND_ADDR` | `0.0.0.0:8080` | 待ち受けアドレス |
| `DATABASE_URL` | `mysql://idp:idp@127.0.0.1:3306/idp` | MariaDB DSN |
| `DB_MAX_CONNECTIONS` | `10` | 接続プール上限 |
| `LOG_FORMAT` | `json` | `json` / `pretty` |
| `KEY_ENCRYPTION_KEY` | 開発用固定値 | 署名秘密鍵の暗号化キー（base64、32 バイト）。**本番では必須** |
| `COOKIE_SECURE` | issuer が https なら `true` | Cookie の `Secure` 属性 |
| `AUTH_SESSION_TTL_SECS` | `600` | AuthSession の有効期間 |
| `AUTHORIZATION_CODE_TTL_SECS` | `60` | authorization code の有効期間 |
| `SSO_IDLE_TTL_SECS` | `28800` | SSO idle タイムアウト（8h） |
| `SSO_ABSOLUTE_TTL_SECS` | `86400` | SSO absolute タイムアウト（24h） |
| `ACCESS_TOKEN_TTL_SECS` | `900` | Access Token 有効期間 |
| `ID_TOKEN_TTL_SECS` | `3600` | ID Token 有効期間 |
| `CLOCK_SKEW_SECS` | `60` | JWT 検証時のクロックスキュー許容 |
| `RUST_LOG` | `info,idp=debug` | ログフィルタ |

## 本番用の鍵暗号化キーを作りたいとき

```sh
openssl rand -base64 32   # これを KEY_ENCRYPTION_KEY に設定する
```

## API 仕様を確認したいとき

サーバ起動後に次へアクセスする（手書きの API 仕様書は無い）。

- OpenAPI JSON: `GET /api/openapi.json`
- Swagger UI: `GET /api/docs`

## 死活・準備状態を確認したいとき

- Liveness: `GET /healthz`
- Readiness: `GET /readyz`（DB 到達と組み合わせてスキーマ version も起動時に照合済み）
