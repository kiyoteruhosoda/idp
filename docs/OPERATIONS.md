# OPERATIONS

「〇〇したいとき、〇〇する」の手順のみをまとめる。設計の背景は `ARCHITECTURE.md`、
API 仕様は自動生成の OpenAPI（起動後 `/api/openapi.json`・Swagger UI `/api/docs`）を参照。

## 開発環境を起動したいとき

api（DB 直結。既定 :8080）と web（HTML 画面。既定 :8081）を別プロセスで起動する（ADR-0007）。

```sh
docker compose up -d mariadb          # MariaDB 10.11 を起動
sqlx migrate run                       # マイグレーション適用（要 DATABASE_URL）
# 別々のシェルで（web は api を API_BASE_URL で呼ぶ）
cargo run -p idp-api                   # api 起動（既定 0.0.0.0:8080）
API_BASE_URL=http://localhost:8080 cargo run -p idp-web   # web 起動（既定 0.0.0.0:8081）
```

ブラウザは通常はリバースプロキシ（単一オリジン）経由で使う。ローカルで直に触る場合、ログイン画面・
管理コンソールは web（:8081）、OIDC protocol・JSON 管理 API は api（:8080）。両者は同一の
`INTERNAL_SERVICE_TOKEN` を共有する（web→api の `/internal/*` 呼び出しに必要）。

## マイグレーションを適用したいとき

```sh
DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' sqlx migrate run
```

新規作成の規約は `migrations/README.md` と `.claude/skills/db-migration/` を参照。
アプリは起動時に version を照合するだけで適用は行わない。

## root テナントの UUID を確認したいとき

root テナントの UUID は seed が**動的採番**するため環境ごとに異なる（固定値はない。ADR-0009 §1）。
システム管理者のログイン URL（`/{root_uuid}/...` 系）の確定に必要になる。
`deploy.sh` はデプロイ完了時にログイン URL として標準出力へ記録するが、後から確認するには DB を参照する。

```sql
SELECT id FROM tenants WHERE parent_tenant_id IS NULL;
```

```sh
# Compose 環境の場合
docker compose exec -T mariadb sh -c \
  'exec mariadb -uidp -p"$MARIADB_PASSWORD" idp -N -B -e \
   "SELECT id FROM tenants WHERE parent_tenant_id IS NULL"'
```

## DB を作り直したいとき（スキーマ刷新後の再作成）

マルチテナント対応（ADR-0009 §11）で初期マイグレーションを全面刷新したため、**刷新前に作成した DB は
そのまま使えない**（`_sqlx_migrations` のチェックサム不整合になる）。既存データを破棄して再作成する。

```sh
# Compose 環境: MariaDB のデータボリュームごと作り直して再適用する
docker compose down mariadb
docker volume rm <project>_mariadb_data      # ボリューム名は `docker volume ls` で確認
docker compose up -d mariadb                 # healthy を待つ
docker compose run --rm migrate              # DDL + マスタデータを適用

# ホスト直結（開発）: DB を落として作り直す
mariadb -e 'DROP DATABASE idp; CREATE DATABASE idp CHARACTER SET utf8mb4;'
DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' sqlx migrate run
```

再作成後、root テナント UUID は再採番される（上記の手順で確認し、クライアント設定等を更新する）。

## テストを実行したいとき

```sh
cargo test                             # 単体テストのみ（DB 不要）
TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test   # 統合テスト込み
```

統合テスト（`tests/schema.rs` / `keys.rs` / `register.rs` / `oidc_flow.rs` ほか）は
`TEST_DATABASE_URL` 未設定時はスキップされる。`oidc_flow` は api 単体（ログイン検証は
`POST /internal/authenticate` 経由）で駆動する。

**web→api の疎通 E2E**（2 サービスを実際に起動して検証、ADR-0007）:

```sh
# 前提: MariaDB 起動＋マイグレーション適用済み（seed 管理ユーザーが必要）。
TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' ./scripts/e2e.sh
```

api・web を別プロセスで起動し、`/authorize`→web `/login`→`/token` の OIDC フローと、管理コンソール
（ログイン・クライアント作成・権限付与・状況/監査）をブラウザ相当の HTTP で通す。終了時に自動で停止する。

## クライアントを登録したいとき

管理 API（`idp.tenant.admin` 権限が必要。`idp.system.admin` でも可）で登録する。エンドポイント仕様は `/api/docs`（Swagger UI）を参照。
`client_id` は自動採番され、confidential クライアントの `client_secret` は**この応答でのみ**平文で返る
（DB には argon2 ハッシュのみ保存。以後は再表示できないため保管する。紛失時は再発行する）。
呼び出しには対象テナントを scope とする `idp.tenant.admin`（または `idp.system.admin`）を保有する利用者の有効な SSO セッション（`sso_session_id` Cookie）が要る。

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

管理 API（`idp.tenant.admin` 必須。`idp.system.admin` でも可）で `audit_log` を絞り込み参照する。`GET /admin/audit-logs`。
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

## 利用者に管理権限を付与／剥奪したいとき

管理コンソールの権限付与 UI は未実装のため、SQL で `user_permissions` を操作する（権限モデルは
ADR-0006・ADR-0009 §4）。付与できる権限コードは `permissions` マスタに存在するもの
（`idp.system.admin` / `idp.tenant.admin`）に限り、**scope（`tenant_id`）の明示が必須**。
初期管理者（`admin@example.com`）には seed で `idp.system.admin`（scope = root）が付与済み。

- `idp.tenant.admin`: 対象テナントを scope に指定する（当該テナント内の管理のみ。配下へは及ばない）。
- `idp.system.admin`: scope は root のみ（CHECK 制約 `user_permissions_system_admin_scope_chk` が
  root 以外の scope を拒否する）。

```sql
-- 付与（idp.tenant.admin を対象テナント scope で。email はテナント内一意のため tenant_id で絞る）
INSERT INTO user_permissions (user_id, permission_code, tenant_id)
SELECT id, 'idp.tenant.admin', '<対象テナントUUID>' FROM users
  WHERE tenant_id = '<所属元テナントUUID>' AND email = 'someone@example.com'
ON DUPLICATE KEY UPDATE user_id = user_id;

-- 剥奪
DELETE up FROM user_permissions up
  JOIN users u ON u.id = up.user_id
  WHERE u.tenant_id = '<所属元テナントUUID>' AND u.email = 'someone@example.com'
    AND up.permission_code = 'idp.tenant.admin' AND up.tenant_id = '<対象テナントUUID>';
```

権限を保有する利用者は、有効な SSO セッション（一度ログイン済み）で `GET /admin/whoami` に
アクセスでき、自身の `user_id` が返る（保護の疎通確認用）。

## ゲスト招待をメールで届けたいとき

1. root 管理者で `/{root_tenant_id}/admin/settings` を開き、システム設定区画に SMTP（ホスト・ポート・
   認証・差出人アドレス・TLS）を保存する。
2. 参加先テナントの管理者が `/{tenant_id}/admin/invitations` から招待を作成すると、被招待者のメール
   アドレスへ承諾リンク付きの招待メールが自動送信される（結果画面に送信の成否が表示される）。
3. SMTP 未設定・送信失敗のときは、結果画面に表示される招待トークンを安全な方法で本人へ伝える
   （被招待者は所属元テナントでログイン後、`/{tenant_id}/invitations/accept` にトークンを提示する）。

## パスワードを忘れた利用者を復旧させたいとき

- SMTP が設定済みなら、利用者自身がログイン画面の「パスワードをお忘れですか？」
  （`/{tenant_id}/forgot-password`）からリセットメールを受け取り再設定できる（リンクの有効期限は
  既定 1 時間・1 回限り。成功時は既存セッションが全て失効する）。
- SMTP 未設定の場合はこの機能は使えない。管理者が利用者管理画面から再作成するか、SMTP を設定する。

## 自己登録（/auth/register）を開放したいとき

1. 対象テナントの管理者で `/{tenant_id}/admin/settings` を開く。
2. テナント設定区画の「自己登録を許可する」にチェックを入れて保存する（既定は無効）。
3. 無効へ戻すにはチェックを外して保存する。

## 環境変数を設定したいとき

| 変数 | 既定値 | 用途 |
|---|---|---|
| `ISSUER` | `http://localhost:8080` | OIDC issuer（末尾スラッシュ無しに正規化） |
| `BIND_ADDR` | `0.0.0.0:8080` | 待ち受けアドレス |
| `DATABASE_URL` | `mysql://idp:idp@127.0.0.1:3306/idp` | MariaDB DSN |
| `DB_MAX_CONNECTIONS` | `10` | 接続プール上限 |
| `LOG_FORMAT` | `json` | `json` / `pretty` |
| `KEY_ENCRYPTION_KEY` | 開発用固定値 | 署名秘密鍵の暗号化キー（base64、32 バイト）。**`ISSUER` が https のとき未設定なら起動失敗** |
| `INTERNAL_SERVICE_TOKEN` | 開発用固定値 | web→api の `/internal/*` 共有シークレット（api・web で同値）。**`ISSUER` が https のとき未設定なら起動失敗** |
| `COOKIE_SECURE` | issuer が https なら `true` | Cookie の `Secure` 属性 |
| `AUTH_SESSION_TTL_SECS` | `600` | AuthSession の有効期間 |
| `AUTHORIZATION_CODE_TTL_SECS` | `60` | authorization code の有効期間 |
| `SSO_IDLE_TTL_SECS` | `28800` | SSO idle タイムアウト（8h） |
| `SSO_ABSOLUTE_TTL_SECS` | `86400` | SSO absolute タイムアウト（24h） |
| `ACCESS_TOKEN_TTL_SECS` | `900` | Access Token 有効期間 |
| `ID_TOKEN_TTL_SECS` | `3600` | ID Token 有効期間 |
| `CLOCK_SKEW_SECS` | `60` | JWT 検証時のクロックスキュー許容 |
| `PUBLIC_WEB_BASE_URL` | `ISSUER` と同値 | 招待メール・パスワードリセット等のリンクの土台（web 画面の公開 URL）。web を別オリジンへ置く構成でのみ設定 |
| `PASSWORD_RESET_TTL_SECS` | `3600` | パスワードリセットトークンの有効期間 |
| `EMAIL_VERIFICATION_TTL_SECS` | `86400` | 自己登録アカウントのメール検証トークンの有効期間（SEC6b） |
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

api・web の各サービスが持つ（ADR-0007）。外部からはリバースプロキシ経由で到達する。

- api: `GET /healthz`（liveness）／`GET /readyz`（DB 到達＋スキーマ version 照合）。
- web: `GET /healthz`（liveness）／`GET /readyz`（api への到達性を確認）。

## リバースプロキシと公開範囲（ADR-0007 §2・ADR-0009 §6、MT13）

ブラウザは**単一オリジン**（リバースプロキシ、既定 `WEB_PORT`）に来て、プロキシがパスで振り分ける。
web の画面 URL はテナント経路化されており（`/{tenant_id}/login` 等）、管理コンソール（HTML）は
api の JSON 管理 API と同じ `/{tenant_id}/admin/...` 名前空間を共有するため、この経路のみ
`Accept` ヘッダ（`text/html` を含むか）で振り分ける。

- `/{tenant_id}/admin(/...)?` → `Accept: text/html` を含む（ブラウザの画面遷移）なら **web**（管理コンソール）、
  それ以外（`curl` 等の JSON API クライアント）は **api**（JSON 管理 API）
- `/{tenant_id}/(login|password-change|consent|mfa/*|account/*|passkey/*)` → **web**（HTML 画面）
- `/internal/*` → **遮断**（外部公開しない。web→api の内部呼び出しは Compose ネットワーク内で直結）
- それ以外（`/{tenant_id}/authorize`・`/token`・`/userinfo`・`/.well-known`・`/healthz`・OpenAPI）→ **api**

ルーティング定義は `docker/nginx.conf`。api・web は既定で**ホストへ直接公開しない**（プロキシ経由のみ）。
web→api の `/internal/*` は共有シークレット `INTERNAL_SERVICE_TOKEN`（api・web で同値）で保護する。
デバッグで api/web を直に叩きたい場合は `docker-compose.yml` の該当 `ports:` を一時的に有効化する。

### MariaDB の公開範囲と保守接続

デプロイ用 Compose（`docker-compose.deploy.yml`）では、MariaDB を既定でホストへ publish しない。
通常の保守作業は Compose ネットワーク内の `mariadb` コンテナへ `exec` して実行する。

```sh
docker compose -f docker-compose.deploy.yml exec -T mariadb sh -c \
  'exec mariadb -u"$MARIADB_USER" -p"$MARIADB_PASSWORD" "$MARIADB_DATABASE"'
```

ホスト上の DB クライアントから一時的に接続する必要がある場合だけ、loopback bind の
`docker-compose.db-debug.yml` を明示的に重ねる。外部インターフェースへ公開しないため、
`MARIADB_BIND_HOST` は原則 `127.0.0.1` のままにする。

```sh
docker compose -f docker-compose.deploy.yml -f docker-compose.db-debug.yml \
  --profile db-debug up -d mariadb
```

## イメージをビルドしたいとき（ビルド側。ソースがあるホスト）

ソースとデプロイ先は別ホスト。**ソース側ではビルドのみ行い、起動はしない**（配置は deploy.sh）。

```sh
./scripts/build.sh                  # イメージビルド → dist/ に tar ＋ デプロイ一式を出力
IMAGE_TAG=1.0.0 ./scripts/build.sh  # イメージタグを指定（既定 latest）
```

`dist/` にはイメージ tar（api/web/migrate）・デプロイ用 `docker-compose.yml`・`docker/nginx.conf`・
`.env.example`・`.env.staging.example`・`.env.production.example`・`deploy.sh`・照合用 manifest が入る。この `dist/` をディレクトリごとデプロイ先へ
転送する。詳細は `scripts/README.md`。

## デプロイしたいとき（デプロイ先。初回・更新とも）

転送した `dist/` の中で `deploy.sh` を実行する。冪等（既存 `.env` は上書きしない）。
**ソース不要・ビルドしない**。

```sh
cd /opt/idp/dist   # 転送先（例）
./deploy.sh app
```

内容: 初回は秘密情報（DB パスワード・`KEY_ENCRYPTION_KEY`・`INTERNAL_SERVICE_TOKEN`・`CSRF_SECRET`）を
乱数生成して `.env` を作成（確認する項目は `ISSUER` と `WEB_PORT`。同一ホストの stg/prod は sample env で `WEB_PORT` / `IMAGE_TAG` を分ける）→ 同梱 tar からイメージを
`docker load`（manifest と照合。読込済みならスキップ）→ MariaDB 起動 → マイグレーション
（DDL + マスタデータ）適用 → api・web・proxy を起動 → `/readyz` で起動確認。

使う compose は同梱の `docker-compose.yml`（`build:` を持たず `image:` 参照。リポジトリ内から実行した
場合はルートの `docker-compose.deploy.yml`）。前提: `docker`（Compose v2）と `openssl`。

## マイグレーションだけを適用したいとき（デプロイ先）

```sh
./deploy.sh migrate
```

DDL・マスタデータの適用は常駐させない専用ジョブ（`migrate` サービス）で単独実行される。
ホストに sqlx-cli がある場合は従来どおり `DATABASE_URL=... sqlx migrate run` でもよい。

## DB を初期化してやり直したいとき（デプロイ先）

```sh
./deploy.sh reset
```

DB volume を削除してからマイグレーション・起動をやり直す。破壊的操作（確認なしで即実行される）。
`.env`（秘密情報・サイト固定値）は保持される。

## 同一ホストに stg / prod を置く場合

`docker-compose.deploy.yml` はコンテナ内の proxy を常に `8080` で待ち受けさせ、ホスト側の外部公開ポートだけを `.env` の `WEB_PORT` で変える。
同じホストに 2 環境を置く場合、同じ `WEB_PORT` は同時に bind できないため、例として以下のように分ける。

| 環境 | 配置例 | `.env` テンプレート | 外部 URL 例 | `WEB_PORT` | `IMAGE_TAG` |
| --- | --- | --- | --- | --- | --- |
| stg | `/opt/idp/stg` | `.env.staging.example` | `http://<host>:8061` | `8061` | `stg` |
| prod | `/opt/idp/prod` | `.env.production.example` | `http://<host>:8060` | `8060` | `prod` |

`ISSUER` と `PUBLIC_WEB_BASE_URL` は、ブラウザが外から到達する URL（例: `http://192.0.2.10:8061`）に合わせる。
同一ホストでは `IMAGE_TAG` も `stg` / `prod` のように分け、`latest` を両環境で共有しない。

```sh
# stg 用 bundle 例
IMAGE_TAG=stg ./scripts/build.sh dist-stg
cp dist-stg/.env.staging.example dist-stg/.env
# dist-stg/.env の ISSUER / PUBLIC_WEB_BASE_URL と CHANGE-ME を実値へ変更

# prod 用 bundle 例
IMAGE_TAG=prod ./scripts/build.sh dist-prod
cp dist-prod/.env.production.example dist-prod/.env
# dist-prod/.env の ISSUER / PUBLIC_WEB_BASE_URL と CHANGE-ME を実値へ変更
```

## ロールバックしたいとき

- アプリ: 前のバージョンの `dist/` を残しておき、そこで `./deploy.sh app` を実行する
  （tar から前のイメージが読み込まれる）。
- スキーマ: migration は expand/contract 前提のため、直前バージョンのアプリは新スキーマ上でも動く。
  DDL 自体を戻す必要がある場合のみ次を実行する（`.down.sql` を適用）。

```sh
docker compose -f docker-compose.deploy.yml run --rm --entrypoint sqlx migrate migrate revert --source /migrate/migrations
```

## 初期管理ユーザーのパスワードを変更したいとき

初期管理ユーザー `admin@example.com`（root テナント所属）は「変更前提のデフォルト値」として seed
される（既定パスワードはメールアドレスと同じ `admin@example.com`、`must_change_password = 1`）。本番では初回ログイン後すぐに
変更する。パスワード変更（リセット）画面の実装後は初回ログイン時に強制誘導される（ADR-0009 §5。
それまでの間に代替手段で変更した場合は `must_change_password` を手動で 0 に戻す）。

画面実装までの代替: `/auth/register` で新しい管理ユーザーを作成し（パスワードはアプリが argon2 で
ハッシュ化）、seed 管理ユーザーを無効化する。

```sh
# 1. 新しい管理ユーザーを登録（アプリがパスワードをハッシュ化）
curl -fsS -X POST http://localhost:8080/auth/register \
  -H 'content-type: application/json' \
  -d '{"email":"admin@your-domain.example","preferred_username":"admin2","password":"<強いパスワード>"}'
```

```sql
-- 2. seed 管理ユーザーを無効化する（削除ではなく DISABLED にして監査を残す）
UPDATE users SET status = 'DISABLED'
  WHERE email = 'admin@example.com'
    AND tenant_id = (SELECT id FROM tenants WHERE parent_tenant_id IS NULL);
```

## 秘密鍵の暗号化キー（KEY_ENCRYPTION_KEY）をローテーションしたいとき

`KEY_ENCRYPTION_KEY` は `signing_keys.private_key_encrypted` の暗号化に使う。値を変えると既存の
暗号化秘密鍵を復号できなくなるため、単純な差し替えは不可。MVP では次の手順で入れ替える。

```sql
-- 1. 現行 ACTIVE 鍵を RETIRED にする（JWKS には残り、既存トークンの検証は継続可能）
UPDATE signing_keys SET status = 'RETIRED' WHERE status = 'ACTIVE';
```

```sh
# 2. .env の KEY_ENCRYPTION_KEY を新しい値へ更新して api を再起動する（署名鍵は api が所有）。
#    ACTIVE 鍵が無いため起動時ブートストラップが新鍵を新キーで暗号化して生成する。
openssl rand -base64 32     # 新しい KEY_ENCRYPTION_KEY
docker compose up -d api
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
