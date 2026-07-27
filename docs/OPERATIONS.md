# OPERATIONS

「〇〇したいとき、〇〇する」の手順のみをまとめる。設計の背景は `ARCHITECTURE.md`、
API 仕様は自動生成の OpenAPI（起動後 `/api/openapi.json`・Swagger UI `/api/docs`）を参照。

## 開発環境を起動したいとき

api（DB 直結。既定 :8080）と web（HTML 画面。既定 :8081）を別プロセスで起動する（ADR-0007）。

```sh
docker compose up -d mariadb          # MariaDB 10.11 を起動
sqlx migrate run                       # マイグレーション適用（要 DATABASE_URL）
# 別々のシェルで（web は api を API_BASE_URL で呼ぶ。PUBLIC_WEB_BASE_URL は両者に同値で渡す）
PUBLIC_WEB_BASE_URL=http://localhost:8081 cargo run -p idp-api   # api 起動（既定 0.0.0.0:8080）
PUBLIC_WEB_BASE_URL=http://localhost:8081 API_BASE_URL=http://localhost:8080 \
  cargo run -p idp-web                                           # web 起動（既定 0.0.0.0:8081）
```

ブラウザは通常は同梱リバースプロキシ経由で使う。ローカルで直に触る場合、ログイン画面・
管理コンソールは web（:8081）、OIDC protocol・JSON 管理 API は api（:8080）。両者は同一の
`INTERNAL_SERVICE_TOKEN` を共有する（web→api の `/internal/*` 呼び出しに必要）。
待ち受けポートの全体像は「リバースプロキシと公開範囲」の「待ち受けポート一覧」を参照。

## マイグレーションを適用したいとき

```sh
DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' sqlx migrate run
```

新規作成の規約は `migrations/README.md` と `.claude/skills/db-migration/` を参照。
アプリは起動時に version を照合するだけで適用は行わない。

## root テナントの UUID

root テナントの UUID は**固定値** `00000000-0000-7000-8000-000000000001`（全環境共通で git 管理。ADR-0011）。
システム管理者のログイン URL は `/00000000-0000-7000-8000-000000000001/...`。DB 再初期化しても変わらない。

> 以前は seed が動的採番していたため環境ごとに異なっていた。固定化の経緯は ADR-0011 を参照。

念のため DB から確認する場合:

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

再作成後も root テナント UUID は固定値 `00000000-0000-7000-8000-000000000001` のまま変わらない（ADR-0011）。

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

## エラー・警告ログを確認したいとき

api・web が出力した WARN / ERROR は `log` テーブルへ保存され、管理コンソールの
**「エラー・警告ログ」**（`/{tenant_id}/admin/logs`）から参照できる。監査ログが「誰が何をしたか」を
残すのに対し、こちらは「システムが何を失敗したか」を残す。

**閲覧には `idp.system.admin`（root 管理者）が必要**。全テナントの記録が同じテーブルに載るため、
テナント管理者には開かない（テナント単位の追跡は監査ログを使う）。

画面では レベル（ERROR / WARN）・サービス（api / web）・出力元モジュール（前方一致）・
correlation ID・期間で絞り込める。`correlation_id` は監査ログと同じ値なので、同じリクエストの
「監査イベント」と「内部エラー」を突き合わせられる。

管理 API を直接叩く場合は `GET /{tenant_id}/admin/logs`。

```bash
# 直近のエラー（新しい順、既定 50 件）。root 管理者の SSO セッション Cookie が必要。
curl -sS "$ISSUER/$ROOT_TENANT_ID/admin/logs?level=ERROR" \
  -H "Cookie: sso_session_id=<セッションID>"

# サービス・出力元モジュール・期間で絞る（from/to は RFC3339）。
curl -sS "$ISSUER/$ROOT_TENANT_ID/admin/logs?service=web&target=idp_web::handlers&from=2026-07-01T00:00:00Z" \
  -H "Cookie: sso_session_id=<セッションID>"
```

保持期間は `APP_LOG_RETENTION_DAYS`（既定 30 日）。これより古い行は 1 時間ごとに削除される。
`0` にすると削除されない（テーブルが際限なく増えるため、外部へログを退避している場合のみ選ぶ）。

INFO 以下は DB へ保存しない（コンテナの標準出力に出る構造化ログを参照する）。

`RUST_LOG` は**標準出力の絞り込みだけ**に効く。`RUST_LOG=warn` のように絞っても、この画面には
WARN / ERROR が correlation ID 付きで残り続ける（運用のためのログレベル設定で、障害調査に使う
画面が黙って空になるのを避けるため）。

## 利用者に管理権限を付与／剥奪したいとき

管理コンソールの権限付与 UI は未実装のため、SQL で `user_permissions` を操作する（権限モデルは
ADR-0006・ADR-0009 §4。権限コードとエンドポイント別の要求権限の一覧は `docs/PERMISSIONS.md`）。
付与できる権限コードは `permissions` マスタに存在するもの
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

## 利用者を探したいとき（MT22）

1. 対象テナントの管理者で `/{tenant_id}/admin/members` を開く。
2. 検索ボックスにメールアドレスまたは氏名の**一部**を入れて絞り込む。
3. 一覧は 1 ページ 50 件で、下部の「前へ」「次へ」でページを送る。件数は一覧上部に出る。

- 検索は**現在のページだけでなくテナント全体**が対象（絞り込みは API 側で行う）。
- 一覧に出るのは**そのテナントのメンバー**（HOME と GUEST）で、招待中（未承諾）のゲストも状態
  `INVITED` として出る。所属元が他テナントのゲストも出る（そのゲストの `users` レコードは
  操作できず、一覧では停止・解除のみ行える）。
- 検索語の `%` や `_` はそのままの文字として扱う（ワイルドカードにはならない）。

## ゲストのアクセスを一時的に止めたいとき（MT24）

休職・委託の中断などで、ゲストのアクセスを**あとで戻す前提で**止めたいときは解除ではなく一時停止を使う。

1. 参加先テナントの管理者で `/{tenant_id}/admin/members` を開く。
2. 対象ゲストの行の「一時停止」を押す。再開するときは同じ行の「再開」を押す。

- **停止と解除の違い**: 停止はメンバーシップ行と当該テナント scope の権限行を残すため、再開すれば
  停止前の状態（権限を含む）に戻る。解除（「メンバーシップ解除」）は権限行も消すので、戻すには
  招待からやり直しになる。
- 停止すると、そのテナントで発行済みのリフレッシュトークンを失効させる。これをしないと、停止が効くのは
  最長でリフレッシュトークンの寿命（既定 30 日）先になる。**所属元テナントなど他テナントで使っている
  トークンは失効させない**（停止は 1 テナントに対する措置のため）。
- SSO セッションは失効させない（ホスト単位で共有され、消すと所属元テナントのログインまで巻き込むため）。
  当該テナントへのアクセスは次回の `/authorize` で止まる。
- **HOME（所属元）のメンバーは停止できない。** 所属元を止めるとログインする先が無くなるため、
  アカウントごと止めるときは同画面の「無効化」を使う。
- 招待中（未承諾）のゲストは停止対象にならない（まだアクセスを持たない）。招待を取り消すなら解除する。
- 停止・再開は `tenant_membership.suspended` / `tenant_membership.resumed` として監査ログに残る。

## MFA の端末を失った利用者を復旧させたいとき

認証アプリ（TOTP）やパスキーを登録した端末を失うと、本人はログインできないため自分では解除できない。
テナント管理者が代わりに解除する。

1. 対象テナントの管理者で `/{tenant_id}/admin/members` を開く。
2. 対象利用者の行の「MFA 解除」を押す（所属元が当該テナントの利用者のみ。ゲストは所属元テナントの
   管理者が操作する）。
3. 利用者へ連絡し、パスワードでログインしたうえで設定画面から新しい端末を登録してもらう。

- **TOTP とパスキーは同時に解除される。** 片方でも残っていると本人はログインできないままで、
  復旧手段として成立しないため。
- 解除と同時に**その利用者の有効なセッション・トークンを全て失効させる**。この操作の契機は
  「端末の紛失・盗難」であり、紛失した端末が生きたログイン状態を保持している可能性があるため。
- MFA 未設定の利用者に対して実行してもエラーにはならず、「解除するものはありませんでした」と表示される。
- 自分自身には実行できない。管理者自身の MFA を外す場合は設定画面のセルフサービスを使う
  （端末を失って自分もログインできない場合は、別の管理者に依頼する）。
- 実行は `user.mfa_reset` として監査ログに残る（外した要素の種別と件数のみ。シークレットは記録しない）。
- 解除後、その利用者は**パスワードのみ**でログインできる状態になる。本人確認を済ませてから実行する。

## 自己登録（/auth/register）を開放したいとき

1. 対象テナントの管理者で `/{tenant_id}/admin/settings` を開く。
2. テナント設定区画の「自己登録を許可する」にチェックを入れて保存する（既定は無効）。
3. 無効へ戻すにはチェックを外して保存する。

## 環境変数を設定したいとき

| 変数 | 既定値 | 用途 |
|---|---|---|
| `ISSUER` | `http://localhost:8080` | OIDC issuer（末尾スラッシュ無しに正規化）。ディスカバリ文書の各 URL と ID Token の `iss` の基底。**DB 上書き可**（下記。反映には api・web 両方の再起動が必要） |
| `BIND_ADDR` | `0.0.0.0:8080` | 待ち受けアドレス |
| `DATABASE_URL` | `mysql://idp:idp@127.0.0.1:3306/idp` | MariaDB DSN |
| `DB_MAX_CONNECTIONS` | `10` | 接続プール上限 |
| `LOG_FORMAT` | `json` | `json` / `pretty` |
| `KEY_ENCRYPTION_KEY` | 開発用固定値 | 署名秘密鍵の暗号化キー（base64、32 バイト）。**`ISSUER` が https のとき未設定なら起動失敗** |
| `INTERNAL_SERVICE_TOKEN` | 開発用固定値 | web→api の `/internal/*` 共有シークレット（api・web で同値）。**`ISSUER` が https のとき未設定なら起動失敗** |
| `COOKIE_SECURE` | 自サービスの公開オリジンが https なら `true` | Cookie の `Secure` 属性。**DB 上書き可**（下記） |
| `AUTH_SESSION_TTL_SECS` | `600` | AuthSession の有効期間。**DB 上書き可**（下記） |
| `AUTHORIZATION_CODE_TTL_SECS` | `60` | authorization code の有効期間 |
| `SSO_IDLE_TTL_SECS` | `28800` | SSO idle タイムアウト（8h） |
| `SSO_ABSOLUTE_TTL_SECS` | `86400` | SSO absolute タイムアウト（24h） |
| `ACCESS_TOKEN_TTL_SECS` | `900` | Access Token 有効期間 |
| `ID_TOKEN_TTL_SECS` | `3600` | ID Token 有効期間 |
| `CLOCK_SKEW_SECS` | `60` | JWT 検証時のクロックスキュー許容 |
| `PUBLIC_WEB_BASE_URL` | `ISSUER` と同値 | web 画面の公開 URL。`/authorize` からのログインハンドオフと招待・リセットメールのリンクの土台。**api・web で同値必須（ENV でのみ設定可。DB 上書き不可）**。web を別オリジンへ置く構成でのみ設定 |
| `COOKIE_DOMAIN` | 未設定（既定） | 旧 ADR-0012 構成でブラウザに残った `Domain` 付きセッション Cookie を掃除する旧 Domain 値。セッション Cookie は常に host-only で発行される（ADR-0018）。移行期間のみ設定し、掃除後は未設定へ戻す（**api・web で同値必須**） |
| `PASSWORD_RESET_TTL_SECS` | `3600` | パスワードリセットトークンの有効期間 |
| `EMAIL_VERIFICATION_TTL_SECS` | `86400` | 自己登録アカウントのメール検証トークンの有効期間（SEC6b） |
| `HSTS_MAX_AGE` | `0`（無効） | `Strict-Transport-Security` の `max-age`（秒）。**DB 上書き可**（下記） |
| `APP_LOG_RETENTION_DAYS` | `30` | エラー・警告ログ（`log` テーブル）の保持日数。`0` = 削除しない。**DB 上書き可** |
| `RUST_LOG` | `info,idp=debug` | ログフィルタ |

環境変数より **DB（`system_settings`）の値が優先される**（ADR-0010）。DB で変更するには root 管理者で
`/{root_tenant_id}/admin/settings` を開き、システム設定区画のランタイム設定を編集する。

## ランタイム設定を DB で変更したいとき

1. root テナントの system 管理者で `/{root_tenant_id}/admin/settings` を開く。
2. システム設定区画のランタイム設定一覧で、出所が `DB_MANAGED` の項目を編集して保存する
   （`ENV_LOCKED` の項目は画面から変更できない。`.env` を編集して再デプロイする）。
3. **サービスを再起動して反映する。** 設定は起動時にしか読み込まれない（ADR-0014）。
   同じ画面の「再起動して反映する」ボタン（下記「保存した設定を反映したいとき」）で実行できる。
   各項目の説明に「api の再起動が必要」か「api と web の両方の再起動が必要」かが出る。
4. 画面を再読み込みし、**「保存した設定がまだ効いていません」の警告が消えたこと**を確認する。
   保存しただけで再起動していない項目には「保存済み・未反映」バッジが付く。api だけを再起動して
   web を忘れた状態も、この警告に「web に未反映」として出る。

- 上書きを**解除**した場合も再起動するまでは戻らない（未反映として警告に出る）。
- `ISSUER`・`COOKIE_SECURE`・`HSTS_MAX_AGE`・`AUTH_SESSION_TTL_SECS` は api と web の**両方**が使う
  （ADR-0013・ADR-0017）。web は起動時に api から値を受け取るため、**api → web の順に両方を再起動する**。
  api を再起動するまでは保存した値は誰にも反映されない（web が先に再起動しても、api が配るのは
  api 自身が起動時に読み込んだ値のため、新しい値を先取りすることはない）。web の再起動を忘れると
  api だけが新しい値で動くため、必ず両方を再起動する。
- 値を空にして保存すると上書きが解除され、環境変数（無ければ組み込み既定値）へ戻る。
- api へ到達できないと web は起動に失敗する（設定を取り違えたまま動かさないため）。
  `could not read DB-managed runtime settings from api` が出たら、まず api の死活と
  `INTERNAL_SERVICE_TOKEN` が api・web で同値かを確認する。

### `ISSUER`（ディスカバリ文書・`iss` の URL）を変えたいとき

`/.well-known/openid-configuration` の各 URL や ID Token の `iss` が `http://localhost:8080` のままなら、
`ISSUER` が既定値のままである。上記の手順で `ISSUER` に公開 URL（例 `https://idp.example.com`）を
保存し、api → web を再起動する。

- 値は **スキーム（http/https）とホストを持つ絶対 URL**。末尾スラッシュは自動で落ちる。
  クエリ・フラグメント・資格情報を含む値は保存できない（400）。
- **https にするには、先に `KEY_ENCRYPTION_KEY`・`INTERNAL_SERVICE_TOKEN`・`CSRF_SECRET` を
  環境変数で設定して再起動しておく。** これらが開発用の既定値のままだと api も web も https では
  起動しないため、保存の時点で拒否される（409）。
- 別オリジンで web を公開している場合、`PUBLIC_WEB_BASE_URL` は `ENV_LOCKED` なので `.env` 側の
  変更が必要（ADR-0012）。`COOKIE_DOMAIN` を設定している構成では、`ISSUER` のホストがその
  ドメイン配下で、`PUBLIC_WEB_BASE_URL` とスキーム（http/https）が一致している必要がある。
  外れる値は保存の時点で拒否される（409）。

409 で拒否されたときは、**具体的にどの条件で落ちたかが api のログに出る**（画面には共通の案内のみ）。

```sh
docker compose logs api | grep 'would prevent the next startup'
```

**ホスト名まで変える場合の影響**（スキーム・ポートだけの変更では起きないものも含む）:

| 影響 | 内容 | 対処 |
|---|---|---|
| 登録済み Passkey が使えなくなる | WebAuthn の RP ID は issuer のホスト名から導出する。ホストが変わると別 RP 扱いになる | 利用者に再登録してもらう（`docs/OPERATIONS.md`「MFA の端末を失った利用者を復旧させたいとき」の手順で解除できる） |
| RP 側の設定が古い issuer のままになる | RP は `iss` の完全一致を検証する | 各 RP のディスカバリ URL / issuer 設定を更新する |
| ログイン中の利用者がログアウトする | Cookie はホスト単位で保存される | 再ログインしてもらう |

## 保存した設定を反映したいとき（api・web の再起動）

1. root テナントの system 管理者で `/{root_tenant_id}/admin/settings` を開く。
2. 一番下の「再起動して反映する」で **api と web を再起動** する（確認ダイアログが出る。
   処理中のログイン・API 呼び出しは打ち切られ、数秒間どちらのサービスも応答しない）。
3. 待機画面が自動で設定画面へ戻る。「保存した設定がまだ効いていません」の警告が消えていれば反映完了。

- **停止するだけで、起動し直すのは配置側の再起動ポリシー**（ADR-0017）。終了コードは 0 なので、
  次のいずれかが必要になる。ポリシーが無い環境では**停止したままになる**。

  | 配置 | 必要な設定 |
  |---|---|
  | Docker Compose | `restart: unless-stopped` または `always`（本リポジトリの compose は設定済み） |
  | systemd | `Restart=always` |
  | Kubernetes | `restartPolicy: Always`（Deployment の既定） |

- 順序は **api → web**（web は起動時に api から共有設定を受け取るため）。ボタンはこの順で実行する。
  api への要求が失敗した場合は web を止めない（画面が消えて再起動を指示できなくなるため）。
- 画面が戻らないときは、再起動ポリシーを確認したうえでシェルから起動する。
- **api・web を 1 インスタンスずつ動かす配置が前提**（本リポジトリの Compose 構成）。複数レプリカへ
  スケールしている場合、このボタンは要求を受け取ったレプリカしか止めない。残りは古い設定のまま
  応答し続けるため、下記のようにデプロイ全体をロールアウトする。

  ```sh
  kubectl rollout restart deployment/idp-api && kubectl rollout restart deployment/idp-web
  ```

```sh
# Compose の場合（api → web の順）
docker compose restart api
docker compose restart web
```

- 再起動の要求は監査ログに `service.restart_requested` として残る。

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

## マイグレーション（スキーマ）の適用状態を確認したいとき

DB を直接参照せずに、いま DB へ適用されているマイグレーション version を確認できる。

- **バージョン情報画面（web）**: ブラウザで `GET /version` を開く。「データベース（マイグレーション）」欄に
  「適用済みバージョン」（DB の `_sqlx_migrations` 最大 version）と「期待バージョン」（稼働中 api に埋め込まれた
  最大 version）、および状態を表示する。状態は次の3つを区別する。
  - **最新（スキーマ一致）**: 適用済み ≥ 期待。
  - **DB が遅れています（migrate 未適用）**: 適用済み < 期待。
  - **DB 読み取り不可（運用障害）**: DB へ到達できても `_sqlx_migrations` を読めない（接続断・権限等。api ログにも記録）。
- **JSON（api）**: `GET /version/schema` が `{"expected": <n>, "db_readable": <bool>, "applied": <n|null>}` を返す（認証不要）。

「適用済み < 期待」の場合は DB が古い（`migrate` 未適用）。適用手順は上記「マイグレーションを適用したいとき」
／デプロイ先は「マイグレーションだけを適用したいとき（デプロイ先）」を参照。

> 注意（fail-fast との関係）: api は起動時に「DB が期待 version 以上」を検査し、**未満なら起動を中止**する
> （ADR-0004。同じ理由で Compose では web も api の健全化を待つ）。したがって **DB が遅れている状態では
> `/version` 画面・`/version/schema` 自体が配信されない**ことがある（画面は「api 未到達」を表示）。この場合は
> api コンテナのログに出力される `schema version` 照合行（`expected` / `applied`）で状態を確認する。本画面は
> 主に「デプロイ後に期待 version まで適用できたか（適用済み＝期待）」の確認に用いる。

## リバースプロキシと公開範囲（ADR-0007 §2・ADR-0015・ADR-0016）

同梱リバースプロキシ（`proxy` サービス）が唯一の公開点で、api・web コンテナは**ホストへ直接公開
しない**。web→api の `/internal/*` は共有シークレット `INTERNAL_SERVICE_TOKEN`（api・web で同値）で
保護し、プロキシは**どの公開ポートでも** `/internal/*` に 404 を返す（多層防御）。デバッグで api/web を
直に叩きたい場合は `docker-compose.yml` の該当 `ports:` を一時的に有効化する。

公開の形は `.env` の `PUBLISH_TOPOLOGY` で選ぶ。

| 値 | 公開ポート | 振り分け | nginx 設定 |
|---|---|---|---|
| `domain-split`（既定） | `WEB_PORT`（web）・`API_PORT`（api） | リッスンポート | `docker/nginx.domain-split.conf` |
| `single-origin` | `WEB_PORT` のみ | パス・`Accept`・メソッド | `docker/nginx.conf` |

既定は `domain-split` で、**ポートとサービスが 1:1** になる（ADR-0016）。前段のリバースプロキシ
（Synology DSM 等）が TLS 終端とドメイン振り分けを行い、ポート単位で同梱プロキシへ流す。実ドメインで
公開する手順は下記「api と web を別ドメイン（サブドメイン）で公開したいとき」を参照。

`single-origin` に切り替えると 1 ポートをパスで振り分ける（下記「単一オリジンで公開したいとき」）。
未設定は既定に落ちるが、いずれでもない値は起動を止める（誤記のまま別トポロジで動かさない）。

### 待ち受けポート一覧

ポートは 3 段ある。**前段プロキシ → ホスト公開ポート（`.env` で変える）→ コンテナ内ポート（固定）**。
コンテナ内ポートは `.env` で変えない（Compose が固定値を注入する）。

#### ホストで公開するポート（`.env` で設定する）

| 用途 | `.env` のキー | 既定値 | 転送先（コンテナ内） | トポロジ |
|---|---|---|---|---|
| web（ログイン画面・管理コンソール） | `WEB_BIND_HOST` / `WEB_PORT` | `127.0.0.1` / `8060` | `proxy:8080` | 両方 |
| api（OIDC protocol・JSON 管理 API） | `API_BIND_HOST` / `API_PORT` | `127.0.0.1` / `8070` | `proxy:8081` | `domain-split` のみ |
| MariaDB（開発 Compose・保守 override のみ） | `MARIADB_BIND_HOST` / `MARIADB_PORT` | `127.0.0.1` / `3306` | `mariadb:3306` | 両方 |
| Redis（`profiles: optional`。未使用） | `REDIS_PORT` | `6379` | `redis:6379` | 両方 |

- bind の既定は**ループバック**（`127.0.0.1`）。前段プロキシが同一ホストにある前提。別ホストの前段から
  届かせる場合だけ広げる（その場合は前段・ファイアウォールでも `/internal/*` を遮断する）。
- `single-origin` では `API_PORT` を公開しない（`API_BIND_HOST` / `API_PORT` は未使用）。
- 上表の既定値は Compose の組み込みフォールバック（ローカル開発向け）。stg/prod のデプロイ用
  テンプレート（`.env.staging.example` / `.env.production.example`）は実際の公開ポートを設定済みで、
  prod = `10000`（web）/ `10001`（api）、stg = `10010`（web）/ `10011`（api）。
- 同一ホストに stg/prod を併置する場合は `WEB_PORT`・`API_PORT`・`MARIADB_PORT` を環境ごとに分ける。
- デプロイ用 Compose（`docker-compose.deploy.yml`）は MariaDB をホスト公開しない（下記「MariaDB の
  公開範囲と保守接続」）。

#### コンテナが listen するポート（固定。Compose が注入する）

| サービス | listen | 何を受けるか | 転送先 |
|---|---|---|---|
| `proxy`（nginx） | `8080` | web 面。`WEB_PORT` からの転送 | `web:8081` |
| `proxy`（nginx） | `8081` | api 面。`API_PORT` からの転送（`domain-split` のみ） | `api:8080` |
| `api` | `8080`（`BIND_ADDR=0.0.0.0:8080`） | proxy からの api 面・web からの `/internal/*` 直結 | MariaDB |
| `web` | `8081`（`WEB_BIND_ADDR=0.0.0.0:8081`） | proxy からの web 面 | `API_BASE_URL=http://api:8080` |
| `mariadb` | `3306` | api・migrate からの sqlx 接続 | — |

- **proxy の 8080 が web 面**である点に注意する（api コンテナの 8080 とは別物）。proxy のヘルスチェックと
  ベース Compose のポート公開定義を両トポロジで無変更に保つための割り当て（ADR-0015 §Decision 4）。
- `single-origin` では proxy の 8081 は使わない（`nginx.conf` は 8080 だけを listen する）。
- web→api の呼び出しは Compose ネットワーク内で `http://api:8080` へ直結し、**プロキシを通らない**。
  `API_BASE_URL` は内部到達先であり、公開ドメイン（`ISSUER`）とは独立。

#### ローカル開発（コンテナを使わずホストで実行するとき）

| プロセス | 既定 listen | 変更キー |
|---|---|---|
| `cargo run -p idp-api`（`idp`） | `0.0.0.0:8080` | `BIND_ADDR` |
| `cargo run -p idp-web`（`idp-web`） | `0.0.0.0:8081` | `WEB_BIND_ADDR` |
| MariaDB（`docker compose up -d mariadb`） | `127.0.0.1:3306` | `MARIADB_BIND_HOST` / `MARIADB_PORT` |

この場合はプロキシを立てないため、web の `API_BASE_URL` を `http://localhost:8080`（api の直アドレス）
にし、`PUBLIC_WEB_BASE_URL`（`http://localhost:8081`）を **api・web の両プロセスへ同値で**渡す。
未設定だと両者とも `ISSUER`（既定 `http://localhost:8080`）へフォールバックし、`/authorize` が
ログイン画面へ飛ばす先が web ではなく api になる。

### 単一オリジンで公開したいとき（`PUBLISH_TOPOLOGY=single-origin`）

前段プロキシを持たず 1 ポートだけ開ける配置では、単一オリジン・パスルーティングを選ぶ。ブラウザは
リバースプロキシ（`WEB_PORT`）だけに来て、プロキシがパスで振り分ける。web の画面 URL はテナント
経路化されており（`/{tenant_id}/login` 等）、管理コンソール（HTML）は api の JSON 管理 API と同じ
`/{tenant_id}/admin/...` 名前空間を共有するため、この経路のみ `Accept` ヘッダ（`text/html` を含むか）で
振り分ける。

- `/{tenant_id}/admin(/...)?` → `Accept: text/html` を含む（ブラウザの画面遷移）なら **web**（管理コンソール）、
  それ以外（`curl` 等の JSON API クライアント）は **api**（JSON 管理 API）
- `/{tenant_id}/(login|password-change|consent|mfa/*|account/*|passkey/*)` → **web**（HTML 画面）
- `/internal/*` → **遮断**（外部公開しない。web→api の内部呼び出しは Compose ネットワーク内で直結）
- それ以外（`/{tenant_id}/authorize`・`/token`・`/userinfo`・`/.well-known`・`/healthz`・OpenAPI）→ **api**

ルーティング定義は `docker/nginx.conf`。切り替え手順は次のとおり。

1. `.env` を単一オリジンへ揃える。

   ```sh
   PUBLISH_TOPOLOGY=single-origin
   ISSUER=http://localhost:8060              # api・web とも同一オリジン（= WEB_PORT）
   PUBLIC_WEB_BASE_URL=http://localhost:8060 # ISSUER と同値にする
   ```

2. `./deploy.sh app` で再デプロイする。`API_PORT` の公開は自動的に無くなる（override を重ねない）。

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

## api と web を別ドメイン（サブドメイン）で公開したいとき（ADR-0012・ADR-0015・ADR-0016）

**これが既定のトポロジ**（`PUBLISH_TOPOLOGY=domain-split`）。api と web をドメイン単位で分けて公開する。
**両者は同一の登録可能ドメイン（eTLD+1）のサブドメインであること**。全く無関係なドメイン間の分割は
サポートしない。

**api は web の子サブドメインにする**（例: web `id.example.com` / api `api.id.example.com`。
ADR-0018 決定 1）。セッション Cookie は web の host-only になった（ADR-0018 決定 2）ため通常運用で
`Domain` 付き Cookie は存在しないが、旧構成からの移行期に掃除用 `COOKIE_DOMAIN` を使う場合、
兄弟構成では apex（`example.com`）しか指定できず、同じ親ドメイン配下の他環境・他サービスへ
削除 Cookie の対象範囲が広がる。入れ子なら `id.example.com` まで絞れる。

同梱リバースプロキシは**リッスンポートでサービスを分ける**（ADR-0015）。前段のリバースプロキシ
（Synology DSM 等）が TLS 終端とドメイン振り分けを行い、ポート単位でここへ流す。

```
https://id.example.com     → ${WEB_BIND_HOST}:${WEB_PORT} → 同梱 nginx :8080 → web
https://api.id.example.com → ${API_BIND_HOST}:${API_PORT} → 同梱 nginx :8081 → api
```

`.env.example` 由来の既定はローカル向けの `http://localhost:8070`（api）/ `http://localhost:8060`（web）
なので、実ドメインで公開するときは下記の手順で公開オリジンと Cookie を設定する。

### 手順

1. `.env` でトポロジ（既定のまま）と公開ポートを確認する。

   ```sh
   PUBLISH_TOPOLOGY=domain-split   # 既定。明記しておくと意図が読み取れる
   WEB_BIND_HOST=127.0.0.1     # 前段プロキシが同一ホストなら loopback のままでよい
   WEB_PORT=8060               # web（HTML 画面）の公開ポート
   API_BIND_HOST=127.0.0.1
   API_PORT=8070               # api（OIDC protocol・JSON 管理 API）の公開ポート
   ```

2. 公開オリジンと Cookie を設定する（**3 つとも api/web で同じ値にする**。`COOKIE_DOMAIN` は
   設定しない = 既定。ADR-0018 決定 4）。

   ```sh
   ISSUER=https://api.id.example.com           # api の公開オリジン（web の子サブドメイン）
   PUBLIC_WEB_BASE_URL=https://id.example.com  # web の公開オリジン
   COOKIE_SECURE=true
   ```

3. 前段プロキシで 2 つのドメインを各ポートへ向け、証明書を設定する。
   `TRUST_FORWARDED_HEADERS=true`・`HSTS_MAX_AGE` は両ドメインに同様に適用する。

4. `./deploy.sh app` で再デプロイする（`docker-compose.domain-split.yml` は deploy.sh が自動で
   重ねる。手で `-f` を指定する必要はない）。api・web の両方の再起動が必要。

### 確認

```sh
curl -fsS http://127.0.0.1:8060/readyz      # web
curl -fsS http://127.0.0.1:8070/readyz      # api
curl -fsS https://api.id.example.com/.well-known/openid-configuration | jq .issuer   # api ドメイン
curl -sS -o /dev/null -w '%{http_code}\n' https://api.id.example.com/internal/runtime-settings  # 404
```

管理ログインは web ドメイン側（`https://id.example.com/{root テナント UUID}/login`）。
RP に登録する OIDC エンドポイントは api ドメイン側。

### 注意

- `API_BASE_URL`（web のみ）はサーバ間の内部到達先であり、公開ドメインとは独立（Compose ネットワーク内の
  `http://api:8080` のままでよい）。
- `/internal/*` は同梱 nginx が**どちらのポートでも 404** を返す。api・web コンテナはホストへ
  publish されないため、公開点は同梱プロキシだけ。前段プロキシが**別ホスト**にあり
  `WEB_BIND_HOST` / `API_BIND_HOST` を広げる場合は、前段・ファイアウォールでも `/internal/*` を
  遮断する。
- 同一ホストに stg/prod を併置する場合は `WEB_PORT` と同様に `API_PORT` も環境ごとに分ける。
- 単一オリジン構成にするには上記「単一オリジンで公開したいとき」の手順に従う。

注意:

- **セッション Cookie（`sso_session_id`・`auth_session_id`）は web の host-only Cookie**（ADR-0018
  決定 2）。api はブラウザ Cookie を読み書きせず、`/authorize` は単回・短命のハンドルを URL に載せて
  web へハンドオフする。`COOKIE_DOMAIN` を設定する必要はない（既定は未設定）。
- 旧 ADR-0012 構成（`Domain` 付き Cookie）から移行する場合のみ、掃除のため移行期間だけ
  `COOKIE_DOMAIN` に旧値を設定する。設定中の Set-Cookie には旧 `Domain` 付き Cookie を消す削除
  Cookie が自動で併送される（ブラウザ側の手動対応は不要）。掃除が済んだら未設定へ戻す。
- `COOKIE_DOMAIN` は起動時に検証され、`ISSUER`・`PUBLIC_WEB_BASE_URL` 双方の親ドメインでない値や
  public suffix（`com`・`co.uk` 等）そのものを設定すると**起動に失敗する**（fail-fast）。

### `PUBLIC_WEB_BASE_URL` を DB 管理から ENV へ移行する（破壊的変更）

`PUBLIC_WEB_BASE_URL` は api/web で同値必須のため ENV 専用（DB 上書き不可）になった。過去に
管理コンソールのランタイム設定（DB `system_settings`）で上書きしていた環境は、**同じ値を api の
`.env`（環境変数）へ移してから更新する**。DB に残った値は無視される（削除は任意）。

```sh
# 1. 現在の DB 値を確認する
docker compose -f docker-compose.deploy.yml exec -T mariadb sh -c \
  'exec mariadb -u"$MARIADB_USER" -p"$MARIADB_PASSWORD" "$MARIADB_DATABASE" \
   -e "SELECT value FROM system_settings WHERE \`key\`='"'"'PUBLIC_WEB_BASE_URL'"'"';"'
# 2. その値を .env の PUBLIC_WEB_BASE_URL に設定し、api（と web）を再起動する
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
乱数生成して `.env` を作成（確認する項目は公開 URL の `ISSUER`（api）・`PUBLIC_WEB_BASE_URL`（web）と
公開ポートの `WEB_PORT` / `API_PORT`。同一ホストの stg/prod は sample env で公開ポート / `IMAGE_TAG` を
分ける）→ 同梱 tar からイメージを
`docker load`（manifest と照合。読込済みならスキップ）→ MariaDB 起動 → マイグレーション
（DDL + マスタデータ）適用 → api・web・proxy を起動 → `/readyz` で起動確認。

使う compose は同梱の `docker-compose.yml`（`build:` を持たず `image:` 参照。リポジトリ内から実行した
場合はルートの `docker-compose.deploy.yml`）。前提: `docker`（Compose v2）と `openssl`。

## デプロイ先だけで取得→ビルド→デプロイしたいとき（一ホスト方式）

デプロイ先で Docker が動くなら、`dist/` を転送する代わりに `build-remote.sh` 一本で
git 取得からデプロイまでを完結できる。デプロイ先に置くのは最初にこの 1 本だけでよい
（以後スクリプトが更新されても実行時に自己更新する）。

```sh
cd /opt/idp        # build-remote.sh を置いた場所（例）
./build-remote.sh app        # git 取得 → 自己更新 → build.sh → deploy.sh app
```

内容: git からソースを取得（`clone` / `fetch`）→ リポジトリの `build-remote.sh` と不一致なら
自己更新して再実行 → デプロイ先で `build.sh` を実行してイメージをローカルにビルド →
生成した `dist/deploy.sh` に `app` / `migrate` / `reset` を委譲。取得元・ブランチ・取得先は
`IDP_REPO_URL` / `IDP_BRANCH` / `IDP_SRC_DIR` で変更できる。前提: `git`・`docker`・`openssl`。
詳細は `scripts/README.md`。

## デプロイ先に git が無いとき（dev コンテナでビルド → 取り込み → デプロイ）

Synology DSM のようにデプロイ先へ直接 git を入れられない場合は、**ビルドを dev コンテナ内で
行い**、生成した `dist/` をデプロイ先へ取り込む `build-remote-container.sh` を使う。3 ステップ
（BUILD → PICK → DEPLOY）を 1 本で実行する（旧来の別 `pick.sh` は本スクリプトへ統合済み）。

前提: デプロイ先で Docker が動くこと。git・ツールチェーンを持つ dev コンテナ（例 `ubuntu-dev`）が
起動し、その中にリポジトリ（`scripts/build.sh` がある working dir）があること。コンテナの
ワークスペースがホストから見えており、`dist/` の場所を絶対パスで指せること。

**初回だけの手順（git 不要。ファイル配置のみ）**

1. デプロイ先ディレクトリ（例 `/volume1/docker/idp/stg`）へ、リポジトリの
   `scripts/build-remote-container.sh` を 1 回コピーして実行権を付ける。ホストから見える
   コンテナ内リポジトリのパスから直接コピーできる。

   ```sh
   cp /var/services/homes/<you>/.../work/project/<proj>/scripts/build-remote-container.sh \
      /volume1/docker/idp/stg/
   chmod +x /volume1/docker/idp/stg/build-remote-container.sh
   ```

2. 自分の構成を指す。スクリプトと同じ場所に **`build-remote-container.env`**（`KEY=VALUE` 形式）を
   置くだけでよい（`export` 等のコマンド実行は不要。ファイル配置のみ）。**`IDP_DIST_DIR`（ホストから
   見えるビルド済み `dist/` の絶対パス）は必須**。

   ```sh
   # /volume1/docker/idp/stg/build-remote-container.env
   # 各行は KEY=VALUE。行頭の # はコメント。値の後ろに ` # …` を書いても除去される。
   IDP_DEV_CONTAINER=ubuntu-dev
   IDP_DEV_USER=sshuser
   IDP_DEV_WORKDIR=/work/project/<proj>
   IDP_DIST_DIR=/var/services/homes/<you>/.../work/project/<proj>/dist
   ```

   リポジトリの `scripts/build-remote-container.env` に既定サンプルがあるので、これをデプロイ先へ
   コピーして値を合わせてもよい。

   > **ディレクトリ構成 `/<プロジェクト名>/<環境>` を前提**に、**環境**（`stg`/`prod` 等）はデプロイ先
   > ディレクトリ名から、**プロジェクト名**はその親ディレクトリ名から自動取得される（例:
   > `/volume1/docker/idp/prod` → プロジェクト `idp`・環境 `prod`）。この構成に従っていれば
   > `PROJECT` の指定は不要。従わない場合だけ `IDP_PROJECT`／`PROJECT` で明示する（優先順位:
   > `IDP_PROJECT` > 設定ファイル `PROJECT` > 親ディレクトリ名 > 既定 `idp`）。

   > このファイルは**ビルド実行の設定**専用で、`deploy.sh` / Compose が読む**デプロイ用 `.env`
   > （秘密情報）とは別物**。デプロイ用 `.env` にこれらを書いても効かない。環境変数を明示した場合は
   > そちらが優先される。**`build-remote-container.sh` 冒頭の既定値は直接書き換えないこと**（下記の
   > 自己更新でスクリプトが丸ごと最新版へ差し替わり、直接編集した値は失われる。設定は必ずこの
   > `build-remote-container.env` か環境変数で与える）。

3. `.env` は最小設定でよい。初回実行で `deploy.sh` が `.env.example` から `.env` を自動生成し、
   秘密情報（`KEY_ENCRYPTION_KEY`・DB パスワード・`CSRF_SECRET` 等）を乱数生成する。生成後、
   デプロイ先の `.env` で **公開 URL（`ISSUER`＝api / `PUBLIC_WEB_BASE_URL`＝web）と公開ポート
   （`WEB_PORT` / `API_PORT`）** だけ環境に合わせて確認・編集し、もう一度実行する。

**以後の運用（自動）**

```sh
cd /volume1/docker/idp/stg
./build-remote-container.sh migrate    # BUILD（コンテナ内 git pull → build.sh）→ PICK → deploy.sh migrate
./build-remote-container.sh app        # 通常デプロイ
```

`.env` は初回生成後は**上書きしない**（秘密情報は不変。DB・暗号化署名鍵を保全）。バージョン更新で
`.env.example` に増えた**設定キーだけ**は `deploy.sh` が既存 `.env` へ自動追記する（既存値・秘密は
不変。`COMPOSE_PROJECT_NAME` は volume 保護のため対象外）。個別の値を変えたいときは `.env` を手編集する。

**`build-remote-container.sh` 自身の自動更新**: このスクリプトは `dist/` に含まれない手置き
ブートストラップのため、`git pull` では更新されない。そこで実行のたびに、SYNC（コンテナ内 `git pull`）
の直後に dev コンテナ内の最新版と byte 比較し、**古ければ最新版へ自分自身を差し替えて自動再実行する**
（初回に限らず毎回。`build-remote-container.env` は対象外で、手元の設定はそのまま保持される）。
そのため、通常はデプロイ先の `build-remote-container.sh` を手動で更新する必要はない。

> ただし自動更新が働くのは、デプロイ先の `build-remote-container.sh` が**既に self-update 対応版**の
> 場合に限る。まだ未対応の古い版が置かれている環境（例: `build-remote-container.env` を読み込まず
> `IDP_DIST_DIR` 未設定エラーで即停止する版）では、**一度だけ**リポジトリの
> `scripts/build-remote-container.sh` を手動でコピーして置き換える（上の「初回だけの手順」1. と同じ操作）。
> 以後の更新は自動化される。

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

`docker-compose.deploy.yml` はコンテナ内の proxy を常に `8080`（web 面）/ `8081`（api 面）で待ち受けさせ、
ホスト側の外部公開ポートだけを `.env` の `WEB_PORT` / `API_PORT` で変える。同じホストに 2 環境を置く
場合、同じポートは同時に bind できないため、例として以下のように分ける（既定の `domain-split` では
`API_PORT` も分ける）。

| 環境 | 配置例 | `.env` テンプレート | web の公開 URL | `WEB_PORT` | api の公開 URL | `API_PORT` | `IMAGE_TAG` |
| --- | --- | --- | --- | --- | --- | --- | --- |
| stg | `/opt/idp/stg` | `.env.staging.example` | `https://idpstg.nolumia.com` | `10010` | `https://api.idpstg.nolumia.com` | `10011` | `stg` |
| prod | `/opt/idp/prod` | `.env.production.example` | `https://idp.nolumia.com` | `10000` | `https://api.idp.nolumia.com` | `10001` | `prod` |

前段のリバースプロキシ（Synology DSM 等）で TLS を終端し、上表のドメインを同一ホストの
`127.0.0.1:<WEB_PORT>` / `127.0.0.1:<API_PORT>` へ流す。`PUBLIC_WEB_BASE_URL` は web に、`ISSUER` は
api に、それぞれブラウザ・RP が外から到達する URL（上表の公開 URL）を設定する。
`single-origin` に切り替えた場合は両者を `WEB_PORT` の同一オリジンに揃え、`API_PORT` は使わない。

api は web の子サブドメイン（`api.idp.nolumia.com` / `api.idpstg.nolumia.com`。ADR-0018 決定 1）。
セッション Cookie は各 web ホストの host-only（ADR-0018 決定 2）のため、prod と stg の Cookie
スコープは交わらない。`COOKIE_DOMAIN` は設定しない（既定）。

> **移行メモ**: 旧構成（web `idp.nolumia.com` / api `idpapi.nolumia.com` の兄弟 +
> `COOKIE_DOMAIN=nolumia.com`）から移行する場合、ブラウザに `Domain=nolumia.com` の Cookie が
> 残っている。移行後しばらく `COOKIE_DOMAIN=nolumia.com` を設定したまま運用すると、ログイン・
> ログアウト時に旧 Cookie の削除が併送されて掃除される。掃除期間が終わったら未設定へ戻す。
> また **`ISSUER` が変わる**ため、RP 側の再設定（discovery・`iss`）が必要。DNS に
> `api.idp.nolumia.com` / `api.idpstg.nolumia.com` を追加し、証明書は web・api 両方のホスト名を
> SAN に含める（ワイルドカード `*.idp.nolumia.com` は bare な `idp.nolumia.com` に一致しない）。
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

`CHANGE-ME` の置換を忘れたまま実行した場合、`deploy.sh` はコンテナ起動前に該当キー名と
生成コマンド（`openssl rand -base64 32` 等）を表示して停止する。表示に従って `.env` を
修正し、再実行する。

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
される（ログイン識別子＝ユーザー名も既定パスワードもメールアドレスと同じ `admin@example.com`、
`must_change_password = 1`）。ログインは email ではなくユーザー名（`preferred_username`）で照合する
（ADR-0009 §8）ため、ログイン画面のユーザー名欄には `admin@example.com` を入力する。本番では初回ログイン後すぐに
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
