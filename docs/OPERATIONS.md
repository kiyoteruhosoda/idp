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

管理 API（`idp.admin` 権限が必要）で登録する。エンドポイント仕様は `/api/docs`（Swagger UI）を参照。
`client_id` は自動採番され、confidential クライアントの `client_secret` は**この応答でのみ**平文で返る
（DB には argon2 ハッシュのみ保存。以後は再表示できないため保管する。紛失時は再発行する）。
呼び出しには `idp.admin` を保有する利用者の有効な SSO セッション（`sso_session_id` Cookie）が要る。

```bash
# 有効な SSO セッションの Cookie を付けて呼ぶ（ブラウザのセッションでも可）。
curl -sS -X POST "$ISSUER/admin/clients" \
  -H 'Content-Type: application/json' \
  -H "Cookie: sso_session_id=<セッションID>" \
  -d '{
    "app_name": "My App",
    "client_type": "confidential",
    "redirect_uris": ["https://app.example.com/callback"],
    "scopes": ["openid", "profile", "email"]
  }'
```

- 一覧: `GET /admin/clients`、取得: `GET /admin/clients/{client_id}`
- 更新（app_name / redirect_uris / scopes / status）: `PATCH /admin/clients/{client_id}`
- シークレット再発行（confidential のみ）: `POST /admin/clients/{client_id}/secret`

redirect_uri は完全一致・複数登録に対応し、フラグメント／ワイルドカードは拒否する。要求 scope は
`openid` を含む OIDC scope（openid/profile/email）のみ。

> 管理画面（サーバレンダリング UI）は A2 の進行に合わせて追加予定。それまでは上記 API を用いる。
> 管理者向けの初回ログイン後の SSO セッション確立は通常の `/authorize`→`/login` フローで行う。

## 監査ログ／ログインログを確認したいとき

管理 API（`idp.admin` 必須）で `audit_log` を絞り込み参照する。`GET /admin/audit-logs`。
エラーの絞り込みは `result=failure`、失敗ログインは `event_type=login.failed` 等で行う。
`correlation_id` を付ければ 1 リクエストの一連イベントを追跡できる。

```bash
# 直近の失敗イベント（新しい順、既定 50 件）。有効な SSO セッション Cookie が必要。
curl -sS "$ISSUER/admin/audit-logs?result=failure" \
  -H "Cookie: sso_session_id=<セッションID>"

# 期間・種別・クライアントで絞る（from/to は RFC3339）。
curl -sS "$ISSUER/admin/audit-logs?event_type=token.issued&client_id=<cid>&from=2026-07-01T00:00:00Z&to=2026-07-07T00:00:00Z&limit=100" \
  -H "Cookie: sso_session_id=<セッションID>"
```

## 利用者に管理権限（idp.admin）を付与／剥奪したいとき

管理コンソールの権限付与 UI は未実装のため、SQL で `user_permissions` を操作する（権限モデルは
ADR-0006）。付与できる権限コードは `permissions` マスタに存在するものに限る（初期値は `idp.admin`）。
初期管理者（`admin@example.com`）には seed で `idp.admin` が付与済み。

```sql
-- 付与（対象ユーザーの id は users テーブルから引く。email で照合する例）
INSERT INTO user_permissions (user_id, permission_code)
SELECT id, 'idp.admin' FROM users WHERE email = 'someone@example.com'
ON DUPLICATE KEY UPDATE user_id = user_id;

-- 剥奪
DELETE up FROM user_permissions up
  JOIN users u ON u.id = up.user_id
  WHERE u.email = 'someone@example.com' AND up.permission_code = 'idp.admin';
```

権限を保有する利用者は、有効な SSO セッション（一度ログイン済み）で `GET /admin/whoami` に
アクセスでき、自身の `user_id` が返る（保護の疎通確認用）。

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

## 初めて環境を初期化したいとき（db + web）

`scripts/init.sh` を実行する。冪等（既存 `.env` は上書きしない）。

```sh
./scripts/init.sh
```

内容: 秘密情報（DB パスワード・`KEY_ENCRYPTION_KEY`）を乱数生成して `.env` を作成 → MariaDB 起動 →
マイグレーション（DDL + マスタデータ）適用 → web をビルド・起動 → `/healthz` 待機。

前提: `docker`（Compose v2）と `openssl`。マイグレーションはコンテナ側の sqlx-cli で適用するため
ホストへの sqlx-cli 導入は不要。

## デプロイしたいとき（同一ホスト Compose）

`scripts/deploy.sh` を実行する（事前に `init.sh` 実行済み ＝ `.env` がある前提）。

```sh
./scripts/deploy.sh
```

内容: イメージビルド（web / migrate）→ DDL + マスタデータ適用（専用ジョブで単独実行）→
`docker compose up -d web` → `/readyz` で起動確認。

## マイグレーションだけを適用したいとき（Compose）

DDL・マスタデータの適用は常駐させない専用ジョブ（`migrate` サービス）で単独実行する。

```sh
docker compose run --rm migrate            # sqlx migrate run（DATABASE_URL は .env から解決）
```

ホストに sqlx-cli がある場合は従来どおり `DATABASE_URL=... sqlx migrate run` でもよい。

## ロールバックしたいとき

- アプリ: 直前のイメージへ戻す（タグ運用なら該当タグで `docker compose up -d web`、
  未タグ運用なら 1 つ前のコミットを checkout して `./scripts/deploy.sh`）。
- スキーマ: migration は expand/contract 前提のため、直前バージョンのアプリは新スキーマ上でも動く。
  DDL 自体を戻す必要がある場合のみ次を実行する（`.down.sql` を適用）。

```sh
docker compose run --rm --entrypoint sqlx migrate migrate revert --source /migrate/migrations
```

## 初期管理ユーザーのパスワードを変更したいとき

初期管理ユーザー `admin@example.com` は「変更前提のデフォルト値」として seed される
（既定パスワード `ChangeMe!123`）。本番では初回ログイン後すぐに変更する。

MVP には管理 API・パスワード変更フローが無いため、`/auth/register` で新しい管理ユーザーを作成し
（パスワードはアプリが argon2 でハッシュ化）、seed 管理ユーザーを無効化する運用とする。

```sh
# 1. 新しい管理ユーザーを登録（アプリがパスワードをハッシュ化）
curl -fsS -X POST http://localhost:8080/auth/register \
  -H 'content-type: application/json' \
  -d '{"email":"admin@your-domain.example","preferred_username":"admin2","password":"<強いパスワード>"}'
```

```sql
-- 2. seed 管理ユーザーを無効化する（削除ではなく DISABLED にして監査を残す）
UPDATE users SET status = 'DISABLED' WHERE email = 'admin@example.com';
```

## 秘密鍵の暗号化キー（KEY_ENCRYPTION_KEY）をローテーションしたいとき

`KEY_ENCRYPTION_KEY` は `signing_keys.private_key_encrypted` の暗号化に使う。値を変えると既存の
暗号化秘密鍵を復号できなくなるため、単純な差し替えは不可。MVP では次の手順で入れ替える。

```sql
-- 1. 現行 ACTIVE 鍵を RETIRED にする（JWKS には残り、既存トークンの検証は継続可能）
UPDATE signing_keys SET status = 'RETIRED' WHERE status = 'ACTIVE';
```

```sh
# 2. .env の KEY_ENCRYPTION_KEY を新しい値へ更新して web を再起動する。
#    ACTIVE 鍵が無いため起動時ブートストラップが新鍵を新キーで暗号化して生成する。
openssl rand -base64 32     # 新しい KEY_ENCRYPTION_KEY
docker compose up -d web
```

RETIRED 鍵は新キーでは復号できないが、公開鍵（`public_key`）は平文のため JWKS 掲載・検証は継続できる。
`not_after` を過ぎたら DB から削除してよい。

## バックアップ／リストアしたいとき

MariaDB のデータボリューム（`mariadb_data`）を論理ダンプで退避する。

```sh
# バックアップ（.env の root パスワードを使用）
docker compose exec mariadb sh -c \
  'exec mariadb-dump -uroot -p"$MARIADB_ROOT_PASSWORD" --single-transaction idp' > backup.sql

# リストア
docker compose exec -T mariadb sh -c \
  'exec mariadb -uroot -p"$MARIADB_ROOT_PASSWORD" idp' < backup.sql
```

`.env`（秘密情報一式）と `backup.sql` は別々に安全な場所へ保管する。`.env` を失うと
`KEY_ENCRYPTION_KEY` が失われ、暗号化済み署名秘密鍵を復号できなくなる点に注意する。
