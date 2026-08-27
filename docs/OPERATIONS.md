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

### 撤去を伴うマイグレーション（contract）を適用するとき

列・表を落とすマイグレーションは、**それを前提とするコードが全ノードへ行き渡ってから**適用する。
ローリングデプロイの途中で当てると、古いプロセスが落とした先を読み書きして失敗する（どの
マイグレーションがこれに当たり、何を前提とするかは `migrations/README.md` に書いてある）。

適用が **guard で止まる**ことがある。データが揃っていないまま落とすと一部の利用者だけが
ログインできなくなるため、意図的に失敗させている。エラーは制約名がそのまま出る。

```
ERROR 4025 (23000): CONSTRAINT `the_registry_must_match_users_preferred_username` failed ...
```

この場合は該当する利用者を洗い出し、値の重複を解消してから再実行する（guard 表は再実行できる）。

```sql
-- 0039: users.preferred_username と登録簿の主識別子が食い違っている利用者
SELECT u.id, u.tenant_id, u.preferred_username, p.display_value AS registry_value
FROM users u LEFT JOIN user_login_identifiers p ON p.primary_of_user = u.id
WHERE (u.preferred_username IS NOT NULL AND TRIM(u.preferred_username) <> ''
       AND (p.id IS NULL OR p.normalized_value <> LOWER(TRIM(u.preferred_username))))
   OR ((u.preferred_username IS NULL OR TRIM(u.preferred_username) = '') AND p.id IS NOT NULL);
```

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

管理 API の変更系（POST / PUT / PATCH / DELETE）は、`Origin`（無ければ `Referer`）を送る場合
`PUBLIC_WEB_BASE_URL` か `ISSUER` のオリジンと一致していないと 403 になる。ブラウザの JavaScript から
直接呼ぶときは、この 2 つのいずれかのオリジンのページから呼ぶ。`curl` のように両ヘッダを送らない
クライアントは影響を受けない。

confidential クライアントの認証方式は `token_endpoint_auth_method` で選ぶ（管理コンソールの
登録・編集フォームにも項目がある）。**既定は `private_key_jwt`**（ADR-0036）で、人ではない
呼び出し元（CI・バッチ・サーバ間連携）にはこれを使う（下記「システム（人ではない呼び出し元）に
認証させたいとき」）。共有シークレットを使うなら `client_secret_basic`（`Authorization: Basic`
ヘッダ）か、RP 側のライブラリが body に `client_id` / `client_secret` を載せる実装なら
`client_secret_post` を**明示的に指定する**。`/token`・`/introspect`・`/revoke` は
登録した方式でのみ認証を受け付け、1 回の要求で複数の方式を提示すると `invalid_request` になる。
`client_secret_basic` と `client_secret_post` の間で方式を変えても `client_secret` の値は変わらない
（提示場所だけが変わる）。public クライアントには設定できない（常に `none`）。

ログアウト系 URI（`post_logout_redirect_uris` / `frontchannel_logout_uri` /
`backchannel_logout_uri`）は `redirect_uris` と同じ制約（絶対 http(s)・フラグメント禁止・
ワイルドカード禁止）を満たす必要がある。`post_logout_redirect_uri` へ実際に戻すには、
ログアウト要求で **`id_token_hint`（推奨）か `client_id` のどちらか**を送り、その RP に登録済みの
URI を指定する。`id_token_hint` は期限切れでもよいが、他テナントの ID Token・Access Token は
受け付けない。どちらも送らない場合はテナント内のいずれかの RP に登録された URI であれば通る。`backchannel_logout_uri` はさらに、ループバック・
プライベート・リンクローカル等のアドレスを**リテラルで**指定できない（内部サービスへ向けるときは
ホスト名で指定する）。

次の例は共有シークレットのクライアントを作る。`token_endpoint_auth_method` を省略すると
`private_key_jwt` になり、`jwks` も無ければ 400 になる。

```bash
# 有効な SSO セッションの Cookie を付けて呼ぶ（ブラウザのセッションでも可）。
curl -sS -X POST "$ISSUER/$TENANT_ID/admin/clients" \
  -H 'Content-Type: application/json' \
  -H "Cookie: sso_session_id=<セッションID>" \
  -d '{
    "app_name": "My App",
    "client_type": "confidential",
    "redirect_uris": ["https://app.example.com/callback"],
    "scopes": ["openid", "profile", "email"],
    "token_endpoint_auth_method": "client_secret_basic"
  }'
```

公開鍵方式（`private_key_jwt`）で登録する手順は「システム（人ではない呼び出し元）に
認証させたいとき」を参照。

- 一覧: `GET /admin/clients`、取得: `GET /admin/clients/{client_id}`
- 更新（app_name / redirect_uris / scopes / status）: `PATCH /admin/clients/{client_id}`
  （省略した項目は「変更しない」。既定に戻すのではない）
- シークレット再発行（confidential のみ）: `POST /admin/clients/{client_id}/secret`

redirect_uri は完全一致・複数登録に対応し、フラグメント／ワイルドカードは拒否する。要求 scope は
`openid` を含む OIDC scope（openid/profile/email）のみ。

> 管理画面（サーバレンダリング UI）は A2 の進行に合わせて追加予定。それまでは上記 API を用いる。
> 管理者向けの初回ログイン後の SSO セッション確立は通常の `/authorize`→`/login` フローで行う。

## クライアントを削除したいとき

管理コンソールのクライアント詳細画面（`/{tenant_id}/admin/clients/{client_id}`）の「削除」から行う。
API では `DELETE /{tenant_id}/admin/clients/{client_id}`（204）。

**論理削除である**（ADR-0035）。一覧から消え、そのクライアントでのログイン・トークン取得は即座に
できなくなるが、**行そのものは残る**。発行済みトークン・同意・監査ログが `client_id` で紐づいて
おり、実体を消すと監査で「どのアプリだったか」を追えなくなるためである。

- 削除済みは取得・更新・secret 再発行も 404 になる。管理画面から復活させる導線は無い。
- 発行済みのアクセストークンは有効期限まで有効なまま（削除は新規発行を止めるもの）。即座に
  無効化したい場合は `/revoke` を使う。
- 監査ログには `client.deleted` が残る。

## システム（人ではない呼び出し元）に認証させたいとき

CI・バッチ・サーバ間連携には、利用者アカウントを共有するのではなく **confidential クライアント +
`client_credentials` grant** を使う。資格情報には `private_key_jwt`（署名済み assertion）を選ぶ
—— 共有シークレットを IdP 側にも設定ファイルにも置かずに済む（ADR-0030）。

### 1. 鍵ペアを作る（呼び出し元の手元で）

秘密鍵は呼び出し元だけが持つ。IdP へ渡すのは公開鍵だけである。

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out machine.key
openssl rsa -in machine.key -pubout -out machine.pub
```

`machine.pub` を JWK（`kty` / `kid` / `n` / `e`）へ変換し、JWK Set の形にまとめる。`kid` は
ローテーションで新旧を見分けるための名前なので、`2026-08` のように日付を入れておくとよい。

変換は openssl の出力から組み立てられる（追加のライブラリは要らない）。次を `pub2jwk.py` として置く。

```python
#!/usr/bin/env python3
"""RSA 公開鍵を JWK Set へ変換する。
使い方: openssl rsa -pubin -in machine.pub -text -noout | python3 pub2jwk.py <kid>"""
import base64, json, re, sys

def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

kid, text = sys.argv[1], sys.stdin.read()

# Modulus は 16 進のバイト列。openssl は符号用の 00 を先頭に付けるので JWK では外す。
mod = bytes.fromhex(re.sub(r"[\s:]", "", re.search(
    r"Modulus:\s*\n((?:\s+[0-9a-f:]+\n)+)", text).group(1))).lstrip(b"\x00")
e = int(re.search(r"Exponent:\s*(\d+)", text).group(1))

print(json.dumps({"keys": [{"kty": "RSA", "kid": kid, "n": b64u(mod),
                            "e": b64u(e.to_bytes((e.bit_length() + 7) // 8, "big"))}]},
                 separators=(",", ":")))
```

```bash
openssl rsa -pubin -in machine.pub -text -noout | python3 pub2jwk.py 2026-08 > jwks.json

# 登録 API の `jwks` は JSON **文字列**で受け取る。次の 1 行で埋め込める形（エスケープ済み）にする。
JWKS=$(python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().strip()))' < jwks.json)
```

### 2. クライアントを登録する

**管理コンソールから登録する場合**は、`/{tenant_id}/admin/clients/new` で次のように選ぶ。

| 項目 | 値 |
|---|---|
| アプリ名 | システムの役割が分かる名前（例 `Nightly Report Job`） |
| **用途** | **「システムが API を呼ぶ（利用者不在）」**（初期選択のまま） |
| スコープ | `openid` は必須のため外せない。システム用では他の 3 つ（`profile`・`email`・`offline_access`）に用は無いので、既定のまま。**業務上の権限は scope では渡さない**（アプリが `sub` = `client_id` を見て判断する。ADR-0033） |
| 認証方式 | `private_key_jwt`（初期選択のまま） |
| 検証鍵（JWKS） | 前項の `jwks.json` の中身 |

用途が「システム」のとき、リダイレクト URI と client type の欄は出ない（利用者が不在なので
リダイレクト先を持たず、confidential 以外あり得ないため）。ブラウザログイン用の RP を登録する
ときは、用途を「ブラウザで利用者をログインさせる」へ選び直すと両方の欄が現れる。`private_key_jwt` では client secret は発行されない。

**API から登録する場合**は次のとおり。`jwks` には前項の `$JWKS`（`jwks.json` を JSON 文字列へ
エスケープしたもの）をそのまま入れる。ヒアドキュメントの終端を引用符で囲まないことで、body の
中で変数が展開される。`redirect_uris` はシステム用では空でよい（`allow_client_credentials` が true の
confidential クライアントに限る。ADR-0032）。

```bash
curl -sS -X POST "$ISSUER/$TENANT_ID/admin/clients" \
  -H 'Content-Type: application/json' \
  -H "Cookie: sso_session_id=<セッションID>" \
  -d "$(cat <<JSON
{
  "app_name": "Nightly Report Job",
  "client_type": "confidential",
  "redirect_uris": [],
  "scopes": ["openid"],
  "allow_client_credentials": true,
  "token_endpoint_auth_method": "private_key_jwt",
  "jwks": $JWKS
}
JSON
)"
```

応答の `client_id` を控える（次項の assertion の `iss` / `sub` に使う）。`client_secret` は
発行されない（この方式のクライアントは共有秘密を持たない）。登録できる鍵は**公開鍵のみ**で、
RSA または EC P-256、各鍵に `kid` が要る。秘密鍵成分を含む JWK は拒否する。

> 画面から登録してもよい。管理コンソールの**クライアント**（`/{tenant_id}/admin/clients`）で
> 「クライアント認証方式」に `private_key_jwt` を選ぶと「検証鍵（JWK Set）」の入力欄が使えるので、
> そこへ `jwks.json` の中身を**そのまま**貼る（画面ではエスケープは要らない）。鍵の入れ替えも
> 同じ欄で行う。

### 3. トークンを取る

呼び出し元は毎回 assertion を署名して送る。同じ assertion は 2 回使えないので、`jti` は要求ごとに
新しくする（UUID などでよい）。

| クレーム | 値 |
|---|---|
| `iss` / `sub` | `client_id` |
| `aud` | `<ISSUER>/<tenant_id>/token`（`<ISSUER>/<tenant_id>` でも可） |
| `exp` | 現在時刻 + 数分（**5 分以内**。超えると拒否される） |
| `jti` | 要求ごとに一意な値（必須） |

assertion の署名も openssl だけでできる。次を `sign-assertion.sh` として置く。

```bash
#!/usr/bin/env bash
# 使い方: sign-assertion.sh <秘密鍵> <kid> <client_id> <aud>
set -euo pipefail
KEY=$1 KID=$2 CID=$3 AUD=$4
b64u() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
NOW=$(date +%s)
HEADER=$(printf '{"alg":"RS256","typ":"JWT","kid":"%s"}' "$KID" | b64u)
PAYLOAD=$(printf '{"iss":"%s","sub":"%s","aud":"%s","exp":%d,"jti":"%s"}' \
  "$CID" "$CID" "$AUD" "$((NOW+180))" "$(openssl rand -hex 16)" | b64u)
SIG=$(printf '%s.%s' "$HEADER" "$PAYLOAD" | openssl dgst -sha256 -sign "$KEY" -binary | b64u)
printf '%s.%s.%s\n' "$HEADER" "$PAYLOAD" "$SIG"
```

```bash
ASSERTION=$(bash sign-assertion.sh machine.key 2026-08 "$CLIENT_ID" "$ISSUER/$TENANT_ID/token")

curl -sS -X POST "$ISSUER/$TENANT_ID/token" \
  -d grant_type=client_credentials \
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  --data-urlencode "client_assertion=$ASSERTION"
```

実運用では、この 2 つは呼び出し元の言語の JWT ライブラリ（`jose`・`PyJWT`・`nimbus-jose-jwt` 等）で
置き換えてよい。上のスクリプトは、ライブラリを入れずに疎通を確かめたいときのためのものである。

返るのはアクセストークンだけで、ID Token も Refresh Token も返らない（利用者が居ないため）。
要求できる scope は登録した `scopes` の範囲内で、`offline_access` は使えない。

### 4. この IdP 自身を操作させたいとき（管理 API）

利用者・クライアント・監査ログといった **IdP 自身の管理操作**をシステムから行わせる場合は、
そのクライアントへ**管理権限コード**を付与し、トークン要求に `resource` を添える（ADR-0037）。

#### 4-1. 権限を付ける

管理コンソールを操作できる管理者（`idp.clients:write` 保有者）が付ける。

```bash
curl -sS -X POST "$API_BASE_URL/$TENANT_ID/admin/clients/$CLIENT_ID/permissions" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"permission_code": "idp.users:read"}'
```

付与できるのは細粒度コードだけである。**`idp.tenant.admin` / `idp.system.admin` は付与できない**
（400）。必要な操作に対応するコードを選ぶ:

| リソース | 読み取り | 変更 |
|---|---|---|
| 利用者（ログイン識別子・パスワード再発行・MFA 解除を含む） | `idp.users:read` | `idp.users:write` |
| クライアント（RP。secret 再発行・権限付与を含む） | `idp.clients:read` | `idp.clients:write` |
| メンバー・招待 | `idp.members:read` | `idp.members:write` |
| 権限の付与状況 | `idp.permissions:read` | `idp.permissions:write` |
| 監査ログ | `idp.audit:read` | — |
| 署名鍵 | `idp.keys:read` | `idp.keys:write` |
| 自テナントの設定 | `idp.tenant-settings:read` | `idp.tenant-settings:write` |
| 認証ポリシー | `idp.authentication-policies:read` | `idp.authentication-policies:write` |
| 外部 IdP | `idp.external-idps:read` | `idp.external-idps:write` |
| SAML SP | `idp.saml-service-providers:read` | `idp.saml-service-providers:write` |

`:write` は同じリソースの `:read` を含む。**テナントの作成・削除、システム設定、再起動、
テナント横断のログ参照は分割していない**（`idp.system.admin` が必要で、クライアントには渡せない）。

一覧・剥奪:

```bash
curl -sS "$API_BASE_URL/$TENANT_ID/admin/clients/$CLIENT_ID/permissions" \
  -H "Authorization: Bearer $ADMIN_TOKEN"

curl -sS -X DELETE \
  "$API_BASE_URL/$TENANT_ID/admin/clients/$CLIENT_ID/permissions/idp.users:read" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

#### 4-2. 管理トークンを取る

`resource` に `{issuer}/{tenant_id}/admin` を指定する。**省略すると管理 API では使えない
トークン**（`aud` が `/userinfo`）が返り、管理 API は 401 を返す。

```bash
ASSERTION=$(bash sign-assertion.sh machine.key 2026-08 "$CLIENT_ID" "$ISSUER/$TENANT_ID/token")

TOKEN=$(curl -sS -X POST "$ISSUER/$TENANT_ID/token" \
  -d grant_type=client_credentials \
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  --data-urlencode "client_assertion=$ASSERTION" \
  --data-urlencode "resource=$ISSUER/$TENANT_ID/admin" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
```

#### 4-3. 管理 API を呼ぶ

```bash
curl -sS "$ISSUER/$TENANT_ID/admin/users?query=alice" \
  -H "Authorization: Bearer $TOKEN"
```

エンドポイントの一覧と要求形式は OpenAPI（`/api/openapi.json`・Swagger UI）を見る。

#### うまくいかないときの見どころ

| 症状 | 原因 |
|---|---|
| `/token` が `invalid_target` | 権限を 1 つも付けていない、または `resource` がこの IdP の管理 API を指していない |
| 管理 API が 401 | `resource` を付けずに取ったトークン／別テナント向けのトークン／期限切れ（既定 300 秒。`MANAGEMENT_TOKEN_TTL_SECS`） |
| 管理 API が 403 | そのエンドポイントに対応する権限コードを持っていない |

トークンはテナント毎である。複数テナントを操作するなら、テナントごとに取り直す。
クライアントを無効化・削除すると、発行済みトークンも**次のリクエストで**通らなくなる。

### 5. 鍵を入れ替えたいとき（ローテーション）

止めずに入れ替えられる。

1. `PATCH /admin/clients/{client_id}` の `jwks` へ**新旧を並べた** JWK Set を送る。
2. 呼び出し元の署名鍵を新しい鍵へ切り替える（この間はどちらの鍵の assertion も通る）。
3. 落ち着いたら、`jwks` から旧鍵を外した JWK Set を再度送る。以後、旧鍵の assertion は通らない。

漏洩した鍵をすぐ止めたい場合は、3 を先に行う（その鍵で署名した assertion は即座に拒否される）。

### 認証が通らないときの見どころ

失敗の応答は一律 `invalid_client` で、どの条件で落ちたかは明かさない。`/token` については理由が
監査ログ（`audit_log` の `ClientAuthenticationFailed` イベントの `reason`）に残るので、そちらを見る
（`/introspect`・`/revoke` は理由を記録しない）。

| `reason` | 意味 |
|---|---|
| `unsupported_assertion_type` | `client_assertion_type` が `jwt-bearer` ではない |
| `unknown_assertion_key` | ヘッダの `kid` に対応する鍵が登録されていない |
| `invalid_assertion_signature` | 署名が登録鍵と合わない |
| `expired_client_assertion` | `exp` が過去（時計ずれの許容は 60 秒） |
| `assertion_lifetime_too_long` | `exp` が 5 分より先を指している |
| `assertion_audience_mismatch` | `aud` がこのテナントを指していない |
| `assertion_subject_mismatch` | `iss` / `sub` が `client_id` と一致しない |
| `missing_assertion_jti` | `jti` が無い |
| `replayed_client_assertion` | 同じ `jti` の assertion を使い回している |
| `unsupported_auth_method` | 登録した方式と違う方式で提示した（secret を送った等） |

## SMS でワンタイムコードを送れるようにしたいとき

**設定画面（`/{tenant_id}/admin/settings`）の「ショートメッセージ（SMS）」で設定する**
（`idp.system.admin` 必須）。

本 IdP は SMS 事業者の SDK を持たない。設定したゲートウェイ URL へ **JSON を 1 本 POST する**
だけで、事業者ごとの API 差異は運用側の小さな中継（関数・Webhook）が吸収する。送る形:

```json
{ "to": "+819012345678", "text": "Your verification code is 123456.", "from": "IDP" }
```

- `to` は E.164 正規化済みの番号、`from` は差出人表示（設定したときだけ載る）。
- 認証ヘッダ（名前と値）を設定すると、その名前のヘッダに値を載せて送る。値は暗号化して保存し
  画面には二度と出さない（空欄のまま保存すれば現行維持）。
- **内部アドレス（localhost・私設ネットワーク）は指定できない。** 設定を書き換えられる立場から
  内部ネットワークへ POST させないため、クライアント登録の redirect URI と同じ判定で弾く。
- ゲートウェイ URL が空のあいだは SMS 送信は無効で、利用者の画面にも登録導線を出さない。

利用者側は**設定 → 認証器**（`/{tenant_id}/settings/authenticators`）で携帯電話番号を登録し、
届いた確認コードを入力する（登録できるのは 1 番号。登録し直すと置き換わる）。以後、MFA の
入力画面に「SMS でコードを受け取る」が出る。

- 電話番号は認証器の登録簿（`user_authenticators.target`）に持つ。メール OTP の送信先アドレスと
  同じ扱いで、**ログ・監査・エラーには出さない**（監査には用途だけを残す）。
- 番号の登録は機微操作として step-up（直前の本人確認）を要求する。ここが素通しだと、放置された
  画面から第二要素の送信先を差し替えられる。

## 外部 IdP でログインできるようにしたいとき

管理コンソールの**外部 IdP**（`/{tenant_id}/admin/external-idps`）で登録する（`idp.tenant.admin` 必須）。
フォームの「プロトコル」で OpenID Connect と SAML 2.0 を選ぶ。

OpenID Connect のとき必要なのは、相手 IdP の `issuer`・認可エンドポイント・トークンエンドポイント・
JWKS URI と、そこで発行してもらったクライアント ID／シークレット。

SAML 2.0 のときは、相手 IdP の entityID（`issuer` 欄）・SSO URL・署名証明書。相手の
メタデータ XML があれば、画面上部の「SAML メタデータから読み込む」にファイルを選ぶか XML を
貼り付けると、この 3 つがフォームに転記される（読み込むだけで登録はされない。内容を確認してから
登録する）。

- 一覧に**相手 IdP 側へ登録する URL** が出る（OIDC はコールバック URL、SAML は ACS URL と
  SP entityID）。相手にはこの値を登録してもらう。
- 署名証明書は**空行区切りで複数書ける**。相手が証明書を更新する期間は新旧 2 枚を並べておく
  （1 枚しか置けないと、切り替わった瞬間にログインが止まる）。
- クライアントシークレットは暗号化して保存し、**画面には二度と出さない**。編集時に空欄のまま
  保存すると変更されない（値を入れたときだけ置き換わる）。
- **プロトコルは登録後に変更できない。** 切り替えるには別のプロバイダとして登録し直す
  （既存の連携が別プロトコルの識別子を指したまま残るため）。
- 「検証済みメール一致で既存アカウントへ連携する」は、**メールアドレスの検証を信頼できる相手
  にだけ**有効にする。信頼できない相手に許すと、相手側でメールアドレスを詐称するだけで
  こちらの既存アカウントへ入れてしまう。なお SAML のアサーションはメールの検証を主張できないため、
  この設定を有効にしても SAML では自動連携されない（事前に連携済みの利用者だけがログインできる）。

## 利用者のログイン識別子を追加したいとき

メンバー一覧の各利用者の「ログイン識別子」から開く
（`/{tenant_id}/admin/users/{user_id}/login-identifiers`。`idp.tenant.admin` 必須）。
別名のユーザー名・メールアドレス・電話番号・社員番号でログインできるようにする。

- 一覧には**登録した値**と**照合キー**（実際に一致する正規化後の値）を並べて出す。書き方の違う
  値を登録してしまった場合はここで気づける（電話番号の区切り記号など）。
- 「主」と付いた行は主たるログイン識別子で、ここからは変更・削除できない。変えるならプロフィール
  編集、止めるならアカウントの無効化を使う。
- 無効化した識別子は行として残る（削除しない限り、その値が他の利用者へ移ることはない）。

## ロックされたアカウントを解除したいとき

管理コンソールの**メンバー一覧**（`/{tenant_id}/admin/members`）で、ロック中の利用者には
「ロック中」バッジと**ロック解除**ボタンが出る。押すと即座に解除される（期限を待たなくてよい）。

API を直接叩く場合:

```bash
curl -sS -X POST "$ISSUER/$TENANT_ID/admin/users/<user_id>/unlock" \
  -H "Cookie: sso_session_id=<セッションID>"
```

- ロック期限のクリアと**失敗回数のリセットを同時に**行う。片方だけでは次の 1 回の失敗で
  即座に再ロックされ、しかも段階的ロックの段が 1 つ進んで前より長くなる。
- ロックされていない利用者に実行しても成功する（応答の `was_locked` で区別できる）。
- 実行は `user.account_unlocked` として監査ログに残る。
- ロック時間は失敗が重なるたびに `LOGIN_LOCK_DURATION_SECS` から倍々で伸び、
  `LOGIN_MAX_LOCK_DURATION_SECS`（既定 24 時間）で頭打ちになる。ログイン成功で失敗回数は 0 に戻り、
  次のロックは初回の長さからやり直しになる。

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

保持期間は `AUDIT_LOG_RETENTION_DAYS`。**既定は `0` ＝ 削除しない**（監査ログの保存期間は法令・
契約で決まるため、既定値で消し始めない）。日数を設定すると、それより古い行が 1 時間ごとに
削除される。既に大量に溜まった状態で有効化した場合は 1 万行ずつ削除し、消し切るまで 1 秒間隔で
続ける（認可フローの書き込みを長時間止めないため）。

## メトリクスを監視したいとき

Prometheus 形式のメトリクスを `GET /internal/metrics` で配信する（G6）。

**内部面にあり、サービストークンが要る。** `/internal/*` はリバースプロキシで外部から遮断する
前提の面で、多層防御として `X-Internal-Auth-Token`（`INTERNAL_SERVICE_TOKEN` と同値）も必須。
メトリクスは「誰がいつ何回失敗したか」を集約した情報であり、公開面に出す値ではない。

```yaml
# prometheus.yml
scrape_configs:
  - job_name: idp-api
    metrics_path: /internal/metrics
    static_configs:
      - targets: ["idp-api:8080"]
    http_headers:
      X-Internal-Auth-Token:
        secrets: ["<INTERNAL_SERVICE_TOKEN と同じ値>"]
```

出る値:

| メトリクス | 種別 | ラベル | 主な用途 |
|---|---|---|---|
| `idp_audit_events_total` | counter | `event_type`・`result` | ログイン成功率・トークン発行レート・鍵ローテーションの成否 |
| `idp_http_request_duration_seconds` | histogram | `method`・`route`・`status` | エンドポイント別のレイテンシ（p50/p95/p99） |
| `idp_db_pool_connections` | gauge | `state`（`total` / `idle`） | sqlx コネクションプールの枯渇 |

すべてに `service="api"` が付く。

例:

```promql
# ログイン成功率（5 分平均）
sum(rate(idp_audit_events_total{event_type="login.succeeded"}[5m]))
  / sum(rate(idp_audit_events_total{event_type=~"login.(succeeded|failed)"}[5m]))

# /token の p95 レイテンシ
histogram_quantile(0.95, sum by (le) (rate(idp_http_request_duration_seconds_bucket{route="/{tenant_id}/token"}[5m])))

# プール枯渇（貸出可能な接続が 0 の状態が続いている）
idp_db_pool_connections{state="idle"} == 0
```

**ラベルにテナント ID・利用者 ID・クライアント ID は入らない。** 入れると監視側の時系列が
利用者数に比例して増えるため、意図的に落としてある。「どのテナントで失敗したか」は監査ログ
（`GET /admin/audit-logs`）で追う。

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

## ログインを制限したいとき（認証ポリシー・アカウントロック）

テナント管理者（`idp.tenant.admin`）は「このクライアントはログイン禁止」「このユーザーは MFA 必須」
等の規則を宣言できる（ADR-0020）。管理コンソールの **`/{tenant_id}/admin/authentication-policies`**
から一覧・作成・編集・削除できる（AP1）。API を直接叩くこともできる（エンドポイント仕様は
Swagger UI `/api/docs` を参照）。

画面で編集するときの注意:

- **保存は全項目置換**である。編集フォームには現在の条件がすべて出るので、消したくない条件は
  そのまま残して保存する。
- 可変長の条件（対象クライアント・利用者・CIDR・`acr_values`）は 1 行 1 件で入力する。
- 適用時間帯は 1 行 1 帯で `曜日 開始-終了 オフセット`（例 `mon,tue,wed,thu,fri 09:00-18:00 +09:00`）。
  曜日の `*` は全曜日、オフセット省略時は `+00:00`。**1 行でも読めないと保存自体を拒否する**
  （読めた行だけ保存すると、書いたはずの条件が黙って消えるため）。
- 一覧の上に出る「どのポリシーにも一致しないときの動作」は `AUTH_POLICY_DEFAULT_EFFECT` の現在値。
  同じ `deny` 1 件でも、既定が `allow` か `deny` かで意味が変わるため必ず併せて見る。

```bash
# 一覧
curl -b "sso_session_id=<管理者セッション>" \
  https://<api>/{tenant_id}/admin/authentication-policies

# 例: 特定クライアントのログインを拒否する
curl -b "sso_session_id=<管理者セッション>" -H 'Content-Type: application/json' \
  -d '{"policy_code":"deny-legacy","policy_name":"Deny legacy app","priority":1,
       "effect":"deny","client_ids":["legacy-app"]}' \
  https://<api>/{tenant_id}/admin/authentication-policies

# 例: 特定ユーザーに MFA を必須にする（TOTP 未設定のユーザーはログイン不可になる）
curl -b "sso_session_id=<管理者セッション>" -H 'Content-Type: application/json' \
  -d '{"policy_code":"mfa-admins","policy_name":"MFA for admins","priority":10,
       "effect":"require_mfa","user_ids":["<ユーザーUUID>"]}' \
  https://<api>/{tenant_id}/admin/authentication-policies
```

- 条件（`client_ids` / `user_ids`）は空 = 制限しない、複数条件は AND。`deny` は常に他へ優先する。
- 一致するポリシーが無いときの既定動作はランタイム設定 `AUTH_POLICY_DEFAULT_EFFECT`
  （既定 `allow`。`deny` にすると許可ポリシーを明示した対象しかログインできない）。
- アカウントロックの閾値はランタイム設定 `LOGIN_MAX_FAILED_ATTEMPTS`（既定 10 回）・
  `LOGIN_LOCK_DURATION_SECS`（既定 900 秒）で調整する（設定手順は「ランタイム設定を DB で
  変更したいとき」参照。反映には再起動が必要）。

## パスワードの要件を強くしたいとき（AP7）

すべてランタイム設定で調整する（設定手順は「ランタイム設定を DB で変更したいとき」参照。反映には
api の再起動が必要）。パスワードを設定する全経路（自己登録・強制変更・セルフサービス変更・
パスワードリセット）に一律で効く。

| キー | 既定 | 内容 |
|---|---|---|
| `PASSWORD_MIN_LENGTH` | `8` | 最小文字数 |
| `PASSWORD_HISTORY_COUNT` | `5` | 再利用を禁じる直近パスワードの数（現行を含む）。`0` で無効 |
| `PASSWORD_MAX_AGE_DAYS` | `0`（無期限） | 有効日数。超えた利用者は次のログインで変更画面へ誘導する |
| `PASSWORD_BREACH_CHECK_ENABLED` | `false` | 漏えい済みパスワードを拒否する |
| `PASSWORD_BREACH_API_BASE_URL` | Pwned Passwords | 漏えい照合の接続先（互換ミラーを立てる場合に変える） |
| `PASSWORD_BREACH_CHECK_TIMEOUT_SECS` | `3` | 漏えい照合 1 回の上限時間 |

- **有効期限はログインを拒否しない。** 期限切れの利用者はパスワード変更フォームへ送られ、変更すれば
  そのままログインが続く。設定時刻を記録していない利用者（列を追加する前から在るアカウント）は
  アカウント作成時刻を起点に測る。
- **漏えい照合には外向き HTTPS が要る。** 送るのはパスワードの SHA-1 の**先頭 5 桁だけ**で、
  パスワードも利用者も渡らない。照合先へ到達できないときはパスワードを拒否せずに通す（外部の不調で
  資格情報の交換が止まる方が危険なため）。閉じた環境では互換のミラーを立てて
  `PASSWORD_BREACH_API_BASE_URL` を向ける。
- `PASSWORD_MIN_LENGTH` を既定より大きくした場合、ブラウザ側の入力チェック（フォームの
  `minlength`）は 8 のままで、超過分は送信後にサーバが拒否する。

## ゲスト招待をメールで届けたいとき

1. root 管理者で `/{root_tenant_id}/admin/settings` を開き、システム設定区画に SMTP（ホスト・ポート・
   認証・差出人アドレス・TLS）を保存する。
2. 参加先テナントの管理者が `/{tenant_id}/admin/invitations` から招待を作成すると、被招待者のメール
   アドレスへ承諾リンク付きの招待メールが自動送信される（結果画面に送信の成否が表示される）。
3. SMTP 未設定・送信失敗のときは、結果画面に表示される招待トークンを安全な方法で本人へ伝える
   （被招待者は所属元テナントでログイン後、`/{tenant_id}/invitations/accept` にトークンを提示する）。
4. 承諾後は、ゲストは参加先テナントのログイン画面（`/{tenant_id}/login`・`/{tenant_id}/admin/login`）
   から所属元テナントと同じ資格情報で直接ログインできる。メンバーシップを停止すると、この
   ログインも同時に止まる（所属元テナントへのログインには影響しない）。

## パスワードを忘れた利用者を復旧させたいとき

利用者・管理者とも、ログイン画面（管理コンソールのログイン画面を含む）の「パスワードをお忘れですか？」
＝ `/{tenant_id}/forgot-password` から再設定できる。リンクの有効期限は既定 1 時間・1 回限りで、
再設定に成功すると既存セッションが全て失効する。

- **SMTP が設定済みのとき**: 入力したメールアドレス宛にリセットリンクが届く。
- **SMTP 未設定のとき**: リンクは**サーバのコンソール（標準出力）へ出る**。運用者がログから拾って
  本人へ安全な方法で渡す。
- **SMTP 設定を読み出せないとき**（DB 障害・`KEY_ENCRYPTION_KEY` 不一致で SMTP パスワードを復号
  できない等）も、復旧手段を残すためコンソールへ出る。つまり **SMTP を設定していてもコンソールに
  出ることがある**（`log` に `failed to load SMTP settings for password reset` が WARN で出る）。
  コンソール出力を許容できない環境では下記の `PASSWORD_RESET_CONSOLE_LINK_ENABLED=false` で塞ぐ。

```sh
# Compose 環境（api のログにリセット URL が出る）
docker compose logs api | grep password-reset

# 出力例（JSON ログ）
# {"level":"INFO","reset_url":"https://idp.example.com/<tenant_id>/password-reset?token=...", …}
```

- **リンクを見た者はそのアカウントのパスワードを再設定できる。** ログを運用者以外が読める環境では
  `PASSWORD_RESET_CONSOLE_LINK_ENABLED=false`（「ランタイム設定を DB で変更したいとき」）で塞ぐ。
  塞いだ場合、SMTP 未設定ではこの機能は使えない（管理者が下記の再発行を行う）。
- リンクは `INFO` で出るため `log` テーブル・管理コンソールのログ画面には残らない。`RUST_LOG` で
  `info` を落としている場合は出ないので、その間だけ既定（未設定）へ戻す。
- **管理者が他の利用者のパスワードを再発行する**（本人の操作を待たない）場合は、
  `/{tenant_id}/admin/members` の対象利用者から再発行する。生成された一時パスワードは画面に
  一度だけ表示され、本人は次回ログイン時に変更を求められる。

## 利用者を探したいとき（MT22）

1. 対象テナントの管理者で `/{tenant_id}/admin/members` を開く。
2. 検索ボックスにメールアドレスまたは氏名の**一部**を入れて絞り込む。
3. 一覧は 1 ページ 50 件で、下部の「前へ」「次へ」でページを送る。件数は一覧上部に出る。

- 検索は**現在のページだけでなくテナント全体**が対象（絞り込みは API 側で行う）。
- 一覧に出るのは**そのテナントのメンバー**（HOME と GUEST）で、招待中（未承諾）のゲストも状態
  `INVITED` として出る。所属元が他テナントのゲストも出る（そのゲストの `users` レコードは
  操作できず、一覧では停止・解除のみ行える）。
- 検索語の `%` や `_` はそのままの文字として扱う（ワイルドカードにはならない）。

## 電話番号・社員番号でログインさせたいとき（AP8）

ログイン欄に入力できる値は既定では利用者の主たるログイン識別子（ユーザー名）1 本だが、
管理 API から**別の識別子を足せる**（ADR-0025）。組織がすでに配っている番号でログインさせたいとき、
改姓でユーザー名を変える前に旧い名前を残しておきたいときに使う。

```bash
# 追加（identifier_type は username / email / phone_number / employee_number）
curl -X POST "https://<api>/{tenant_id}/admin/users/{user_id}/login-identifiers" \
  -H "Content-Type: application/json" -b "sso_session_id=<admin session>" \
  -d '{"identifier_type":"phone_number","value":"090-1234-5678"}'

# 一覧（無効な行も返る）
curl "https://<api>/{tenant_id}/admin/users/{user_id}/login-identifiers" -b "sso_session_id=<admin session>"

# 1 本だけ止める（行は残す）
curl -X PATCH "https://<api>/{tenant_id}/admin/users/{user_id}/login-identifiers/{identifier_id}" \
  -H "Content-Type: application/json" -b "sso_session_id=<admin session>" -d '{"is_active":false}'

# 削除
curl -X DELETE "https://<api>/{tenant_id}/admin/users/{user_id}/login-identifiers/{identifier_id}" \
  -b "sso_session_id=<admin session>"
```

- `idp.tenant.admin` が必要。対象は**所属元（HOME）が当該テナントの利用者**のみ。
- 一覧の先頭には、その利用者の**主たるログイン識別子**（ユーザー名）が `"is_primary": true` の
  行として出る。他の識別子と同じ 1 行だが、識別子単位の有効/無効・削除の対象にはならない
  （変えるならプロフィール編集、止めるならアカウントの無効化を使う）。
- 照合は種別ごとに正規化して行う（電話番号は区切り記号を無視。ユーザー名・メールは大小を無視。
  社員番号は大小を無視）。応答の `normalized_value` が実際に一致する値なので、登録直後に
  これを見て意図どおりか確かめる。
- **電話番号の国際表記と国内表記は別物として扱う。** `+81 90 1234 5678` と `090-1234-5678` は
  別のキーになる（国番号と国内プレフィクスの対応は国ごとに違い、推測すると別人の番号に当たり
  得るため）。両方でログインさせたいなら**両方を登録**する。
- 社員番号は空白を含められない（正規化で空白を落とすため、含む値は登録した書き方では引けなくなる）。
- **止めるときは削除ではなく `is_active: false`。** 行が残るため、その値を他の利用者が登録できない。
  削除すると別人が同じ値を取れてしまい、宛先が黙って変わる。
- **すでにログインに使える値**は 409 で拒否される。他人のログイン識別子・他人のメールアドレスの
  ほか、**その利用者自身の主たる識別子**も対象（同じ値が 2 行あると、片方を無効化しても
  もう片方で認証が通り、「止めたのに使える」識別子ができるため）。
- **メールアドレスでのログインは既定では無効。** 有効にするには `email` 種別の識別子を明示的に
  足す。所有確認（検証メール）は行わないので、管理者がアドレスの正しさを保証する扱いになる。
- 追加・切替・削除は `user.login_identifier_added` / `.updated` / `.removed` として監査に残る
  （残すのは**種別のみ**。電話番号・メールアドレスは PII なので値は残さない）。

## 同じユーザー名のゲストが参加先テナントへ入れないとき（テナントへドメインを割り当てる）

参加先テナントのログイン画面は「そのテナントの HOME 利用者 ∪ 参加中のゲスト」を解決する。ゲストは
所属元をまたいで集まるので、**同じユーザー名のゲストが 2 人参加すると、その名前ではどちらも入れなく
なる**（どちらを指すか決められないため、通さない側に倒している）。当人には「正しいパスワードなのに
入れない」としか見えない。所属元テナントの画面からは従来どおり入れる。

解消するには、その利用者の**所属元テナントにドメインを割り当て**、ドメイン修飾した綴りで入って
もらう。ドメインは 1 つのテナントだけのものなので、`利用者名@ドメイン` からは所属元が 1 つに決まる。

1. root の system 管理者（`idp.system.admin`）で割り当てる。対象は root 自身または直下の子テナント。

   ```bash
   curl -fsS -X POST "https://<host>/{root_tenant_id}/admin/tenants/{tenant_id}/domains" \
     -H 'content-type: application/json' -b "$COOKIE" \
     -d '{"domain":"corp.example"}'
   ```

2. 割り当て済みの一覧・解除:

   ```bash
   curl -fsS "https://<host>/{root_tenant_id}/admin/tenants/{tenant_id}/domains" -b "$COOKIE"
   curl -fsS -X DELETE "https://<host>/{root_tenant_id}/admin/tenants/{tenant_id}/domains/{domain_id}" -b "$COOKIE"
   ```

3. 当人にはログイン欄へ `利用者名@corp.example` と入れてもらう（メールアドレスである必要はない。
   その綴りは「corp.example のあの利用者」を指す名前として働く）。

注意:

- **ドメインの一意性はシステム全体**である。すでに他のテナントが押さえていれば 409 になる（どの
  テナントが持っているかは返さない）。早い者勝ちにしないため、割り当てられるのは root の system
  管理者だけである。
- **所有の確認（DNS など）は行わない。** 割り当てを誤ると、そのドメインを名乗る入力が誤ったテナント
  へ向く。実在と所有は運用者が確認してから登録する。割り当て・解除は
  `tenant.domain_added` / `tenant.domain_removed` として監査に残る。
- 国際化ドメインは **punycode（`xn--` 形式）**で登録する。日本語のまま登録しようとすると 400 になる。
- **既存の入り方は変わらない。** 裸のユーザー名と、割り当てていないドメイン（`gmail.com` 等）は
  従来どおりの解決を通る。ドメインを割り当てても、その利用者が所属元テナントの画面から裸の名前で
  入ることに影響はない。

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

## 組織ごとアクセスを止めたいとき（テナントの無効化）

契約終了などで組織そのものの利用を止めるときは、root の system 管理者で
`/{root_tenant_id}/admin/tenants` から対象テナントを `DISABLED` にする。

- 無効化すると、そのテナントの API（`/{tenant_id}/...`）は 404 になる。web が描くログイン画面は
  URL としては開けたままだが、送信してもログインは成立しない（エラー画面になる）。
- **そのテナントを所属元とする利用者は、ゲストとして参加している他テナントからも入れなくなる。**
  参加先テナント側で何もする必要はない（メンバーシップ行・権限行はそのまま残る）。
- 逆向きはこれに当たらない。参加先テナントを無効化しても、ゲストの所属元テナントへのログインには
  影響しない。
- `ACTIVE` へ戻せば、所属元・参加先とも元どおり入れるようになる（可逆な操作で、行は消さない）。
- 発行済みの SSO セッション・リフレッシュトークンは明示的には失効させないが、**次に使われた時点で
  止まる**。SSO セッションは次回の判定（ログイン・`/authorize`・管理コンソールのアクセス）で、
  リフレッシュトークンは次回の更新（`/{tenant_id}/token`）で拒否される（`invalid_grant`）。
  参加先テナントで発行されたリフレッシュトークンも同じく止まる —— 無効化したテナント自身の
  `/{tenant_id}/token` は 404 になる一方、ゲストとして参加している他テナントの `/{tenant_id}/token`
  は生きているため、そちらはトークン発行時の所属元テナント判定で塞いでいる。
- 発行済みの**アクセストークン**は、その寿命（`ACCESS_TOKEN_TTL_SECS`。既定 15 分）が切れるまでは
  有効なままである（自己完結型の JWT で、RP は検証のたびに DB を見ないため）。**この 15 分を
  運用操作で縮める手立ては無い。** `/{tenant_id}/revoke`（RFC 7009）はトークン文字列そのものと
  当該クライアントの認証を要求する RP 向けの窓口で、管理者はどちらも持たない（無効化したテナント
  自身の `/{tenant_id}/revoke` は `/token` と同じく 404 になる）。参加先テナント単位で今すぐ
  止めたいときは、そのテナントのゲストメンバーシップを一時停止する
  （上記「ゲストのアクセスを一時的に止めたいとき（MT24）」。当該テナントのリフレッシュトークンが
  失効し、アクセストークンも寿命切れで止まる）。

## MFA の端末を失った利用者を復旧させたいとき

**まず本人に自力復旧を試してもらう。** リカバリーコードを発行済みなら、MFA 入力画面の同じ入力欄へ
コードを 1 本入力すればログインできる。メールアドレスが検証済みなら、同じ画面の
「メールでコードを送る」でワンタイムコードを受け取ることもできる。どちらも通らない場合のみ、
以下の管理者による解除を行う。

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

## 利用者に自分のセッション・連携アプリ・認証器を管理させたいとき

設定画面のセルフサービスで完結する。管理者の操作は要らない。

| 画面 | できること |
|---|---|
| `/{tenant_id}/settings/security` | ログイン中のセッション一覧と個別失効、連携済みアプリ（同意）の取り消し |
| `/{tenant_id}/settings/authenticators` | 認証器（TOTP・パスキー・メール OTP・リカバリーコード）の一覧、一時停止／再開／失効、リカバリーコードの発行 |

- 一覧の「現在のセッション」は失効させられない（操作すると「現在のセッションは失効できません」と
  返る。誤って自分を締め出さないため）。今使っているセッションを終わらせるのはログアウト操作。
- **リカバリーコードは発行時に一度だけ表示される**（DB にはハッシュのみ保存）。再表示はできないため、
  発行し直す運用になる。発行し直すと**古いコードは全て無効**になる。
- リカバリーコードは MFA 入力画面の同じ入力欄へそのまま入力する（別画面へ移動する必要はない）。
  1 コードにつき 1 回だけ使える。
- **認証器の追加・削除・状態変更とセッションの失効は Step-up 認証（本人確認のやり直し）の対象**で、
  直近の本人確認から `STEP_UP_MAX_AGE_SECS`（既定 300 秒）を超えていると
  `/{tenant_id}/settings/verify` へ誘導される。MFA を設定している利用者には第 2 要素での確認を求める。
  連携アプリの取り消しは対象外（取り消しても被害が広がらず、いつでもやり直せるため）。

## 外部 IdP を API から登録したいとき

画面での手順は「外部 IdP でログインできるようにしたいとき」を参照。ここは同じ操作を API で
行う場合の入口だけを示す（`idp.tenant.admin` 必須。`idp.system.admin` でも可）。

相手 IdP 側には、本 IdP の受け口を登録してもらう。OIDC のコールバック URL は
`<PUBLIC_WEB_BASE_URL>/{tenant_id}/external/{provider_code}/callback`、SAML の ACS URL は
`<PUBLIC_WEB_BASE_URL>/{tenant_id}/external/{provider_code}/saml/acs`（登録後、
`GET /admin/external-idps` の `redirect_uri`・`saml_acs_url`・`saml_sp_entity_id` にも同じ値が出る）。

```bash
# OIDC
curl -sS -X POST "$ISSUER/{tenant_id}/admin/external-idps" \
  -H 'Content-Type: application/json' \
  -H "Cookie: sso_session_id=<セッションID>" \
  -d '{
    "provider_code": "corp",
    "display_name": "Corp SSO",
    "protocol": "oidc",
    "issuer": "https://login.corp.example.com",
    "authorization_endpoint": "https://login.corp.example.com/authorize",
    "token_endpoint": "https://login.corp.example.com/token",
    "jwks_uri": "https://login.corp.example.com/jwks.json",
    "client_id": "…",
    "client_secret": "…"
  }'

# SAML（entityID・SSO URL・署名証明書は相手のメタデータから取り込める:
#   POST /{tenant_id}/admin/external-idps/import-metadata -d '{"metadata_xml": "<EntityDescriptor …>"}'）
curl -sS -X POST "$ISSUER/{tenant_id}/admin/external-idps" \
  -H 'Content-Type: application/json' \
  -H "Cookie: sso_session_id=<セッションID>" \
  -d '{
    "provider_code": "corp-saml",
    "display_name": "Corp SAML",
    "protocol": "saml",
    "issuer": "https://login.corp.example.com/metadata",
    "saml_sso_url": "https://login.corp.example.com/sso",
    "saml_certificates": ["MIIB…"]
  }'
```

- 一覧: `GET /{tenant_id}/admin/external-idps`、更新: `PATCH …/{id}`、削除: `DELETE …/{id}`。
- 更新でプロトコル固有の設定（エンドポイント・SSO URL・証明書）を変えるときは、**`protocol` を
  一緒に送る**。送らないとその区画は変更されない（まとめて差し替える作りのため）。プロトコル
  そのものの変更は受け付けない。
- **`client_secret` は応答に含まれない**（暗号化保存。設定済みかは `has_client_secret` で分かる）。
  更新時に省略すれば既存値を維持し、空文字を送ると削除して public クライアント化する。
- エンドポイントは **https のみ**・内部宛先（ループバック・プライベート・リンクローカル）は拒否する
  （本 IdP のサーバに任意の URL を叩かせないため）。
- 利用者の同一性は外部 IdP の **`iss` + `sub`**（SAML では `<Issuer>` + `NameID`）だけで判定する
  （メールアドレスは同一性の根拠にしない）。既定では**事前に連携済みの利用者しかログインできない**。
  `allow_auto_link` を有効にすると、外部 IdP が `email_verified: true` を返した場合に限り同じメール
  アドレスの既存利用者へ自動連携する。外部 IdP のメール検証を信用できるときだけ有効にする
  （SAML はこの主張を持たないため自動連携は働かない）。
- 無効化は `enabled: false`（設定は残したままボタンだけ消える）。削除すると**連携済みの対応付けも
  一緒に消える**ため、再度ログインさせるには連携をやり直す必要がある。

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
| `KEY_ENCRYPTION_KEY` | 開発用固定値 | 署名秘密鍵の暗号化キー（base64、32 バイト）。**`ISSUER` がループバック以外のとき未設定なら起動失敗** |
| `INTERNAL_SERVICE_TOKEN` | 開発用固定値 | web→api の `/internal/*` 共有シークレット（api・web で同値。**32 文字以上**）。**`ISSUER` がループバック以外のとき未設定なら起動失敗** |
| `COOKIE_SECURE` | 自サービスの公開オリジンが https なら `true` | Cookie の `Secure` 属性。**DB 上書き可**（下記） |
| `AUTH_SESSION_TTL_SECS` | `600` | AuthSession の有効期間。**DB 上書き可**（下記） |
| `AUTHORIZATION_CODE_TTL_SECS` | `60` | authorization code の有効期間 |
| `SSO_IDLE_TTL_SECS` | `28800` | SSO idle タイムアウト（8h） |
| `SSO_ABSOLUTE_TTL_SECS` | `86400` | SSO absolute タイムアウト（24h） |
| `ACCESS_TOKEN_TTL_SECS` | `900` | Access Token 有効期間 |
| `MANAGEMENT_TOKEN_TTL_SECS` | `300` | 管理 API のアクセストークンの有効期間（ADR-0037）。管理コンソールは毎回取り直すので短くてよい |
| `ID_TOKEN_TTL_SECS` | `3600` | ID Token 有効期間 |
| `CLOCK_SKEW_SECS` | `60` | JWT 検証時のクロックスキュー許容 |
| `PUBLIC_WEB_BASE_URL` | `ISSUER` と同値 | web 画面の公開 URL。`/authorize` からのログインハンドオフと招待・リセットメールのリンクの土台。**api・web で同値必須（ENV でのみ設定可。DB 上書き不可）**。web を別オリジンへ置く構成でのみ設定 |
| `COOKIE_DOMAIN` | 未設定（既定） | 旧 ADR-0012 構成でブラウザに残った `Domain` 付きセッション Cookie を掃除する旧 Domain 値。セッション Cookie は常に host-only で発行される（ADR-0018）。移行期間のみ設定し、掃除後は未設定へ戻す（**api・web で同値必須**） |
| `PASSWORD_RESET_TTL_SECS` | `3600` | パスワードリセットトークンの有効期間 |
| `PASSWORD_RESET_CONSOLE_LINK_ENABLED` | `true` | SMTP で送れないとき（未設定、および設定を読み出せないとき）、リセットリンクをサーバのコンソール（標準出力）へ出すか。メール配送が無い環境で管理者が自力復旧するための経路（上記「パスワードを忘れた利用者を復旧させたいとき」）。ログを運用者以外が読める環境では `false` にする。**DB 上書き可** |
| `EMAIL_VERIFICATION_TTL_SECS` | `86400` | 自己登録アカウントのメール検証トークンの有効期間（SEC6b） |
| `HSTS_MAX_AGE` | `0`（無効） | `Strict-Transport-Security` の `max-age`（秒）。**DB 上書き可**（下記） |
| `APP_LOG_RETENTION_DAYS` | `30` | エラー・警告ログ（`log` テーブル）の保持日数。`0` = 削除しない。**DB 上書き可** |
| `LOGIN_MAX_LOCK_DURATION_SECS` | `86400` | 段階的ロックの上限（秒。AP6）。ロック時間は失敗が重なるたびに `LOGIN_LOCK_DURATION_SECS` から倍々で伸び、この値で頭打ちになる。`LOGIN_LOCK_DURATION_SECS` 以下にすると段階化しない。**DB 上書き可** |
| `AUDIT_LOG_RETENTION_DAYS` | `0`（削除しない） | 監査ログ（`audit_log` テーブル）の保持日数。保存期間は法令・契約で決まるため既定では削除しない。**DB 上書き可** |
| `TOKEN_ENDPOINT_MAX_CONCURRENCY` | `8` | `/token`・`/introspect`・`/revoke` の同時処理数の上限（SEC10）。Argon2id（19 MiB）照合のピークメモリは「上限 × 19 MiB」。溢れた要求は待たせず 503。`0` は無制限（非推奨）。**DB 上書き可** |
| `TOKEN_ENDPOINT_RATE_LIMIT_MAX_REQUESTS` | `300` | 上記 3 本の接続元 IP 単位のレート制限（SEC10）。`0` は無効。`TRUST_FORWARDED_HEADERS=true` のときのみ効く。**DB 上書き可** |
| `TOKEN_ENDPOINT_RATE_LIMIT_WINDOW_SECS` | `60` | 上記レート制限のウィンドウ（秒）。**DB 上書き可** |
| `STEP_UP_MAX_AGE_SECS` | `300` | 機微操作（パスワード変更・認証器の追加削除・セッション失効）の前に本人確認をやり直させる間隔（秒）。**DB 上書き可** |
| `BACKCHANNEL_LOGOUT_MAX_ATTEMPTS` | `8` | Back-channel logout 通知の再送上限。指数バックオフ（30 秒 → 最大 1 時間）。**DB 上書き可** |
| `BACKCHANNEL_LOGOUT_POLL_INTERVAL_SECS` | `15` | Back-channel logout 送信ワーカーが送信キューを見る間隔（秒）。**DB 上書き可** |
| `BACKCHANNEL_LOGOUT_RETENTION_DAYS` | `7` | 決着済み（送信成功・打ち切り）の送信キュー行の保持日数。`0` = 削除しない。**DB 上書き可** |
| `EXPIRED_RECORD_PURGE_INTERVAL_SECS` | `3600` | 期限切れレコード（認可セッション・authorization code・refresh token・SSO セッション・失効 jti・パスキーチャレンジ・各種一時トークン）を掃除する間隔（秒）。`0` = 掃除しない（表が際限なく増えるため非推奨）。**DB 上書き可** |
| `CORS_ALLOWED_ORIGINS` | 空 | ブラウザからの越境アクセスを追加で許可するオリジン（カンマ区切り）。既定ではテナント内 public クライアントの `redirect_uris` から導いたオリジンのみ許可する。**DB 上書き可** |
| `API_DOCS_ENABLED` | `false` | Swagger UI（`/api/docs`）と OpenAPI 文書（`/api/openapi.json`）を配信するか。api 面は公開されるため、有効にすると管理 API を含む全仕様が無認証で読める。開発・検証環境でのみ `true` にする。**DB 上書き可** |
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
- **`localhost` 以外のホストにするには、先に `KEY_ENCRYPTION_KEY`・`INTERNAL_SERVICE_TOKEN`・
  `CSRF_SECRET` を環境変数で設定して再起動しておく。** これらが開発用の既定値のままだと api も web も
  起動しないため、保存の時点で拒否される（409）。判定は https だけでなく「ループバック以外の公開
  オリジン」で行う（前段で TLS を終端して `ISSUER` を http にした配置も本番扱い）。
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
| 登録済み Passkey が使えなくなる（`PUBLIC_WEB_BASE_URL` のホスト変更時） | WebAuthn の RP ID は web の公開ベース URL（`PUBLIC_WEB_BASE_URL`。未設定時は issuer に追従）のホスト名から導出する（ADR-0019 決定 2）。ホストが変わると別 RP 扱いになる | 利用者に再登録してもらう（`docs/OPERATIONS.md`「MFA の端末を失った利用者を復旧させたいとき」の手順で解除できる） |
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

**先に `API_DOCS_ENABLED=true` を設定する**（既定は無効。api 面は公開されるため、有効にすると
管理 API を含む全エンドポイントの仕様が無認証で読める）。開発用 `docker-compose.yml` では既に
有効になっている。設定後、サーバ起動して次へアクセスする（手書きの API 仕様書は無い）。

- OpenAPI JSON: `GET /api/openapi.json`
- Swagger UI: `GET /api/docs`

無効のまま仕様だけ見たい場合は、ローカルで `API_DOCS_ENABLED=true cargo run -p idp-api` する。

## 死活・準備状態を確認したいとき

api・web の各サービスが持つ（ADR-0007・ADR-0031）。外部からはリバースプロキシ経由で到達する。

| パス | 認証 | api | web |
|---|---|---|---|
| `GET /healthz` | 不要 | プロセスが生きているか | 同左 |
| `GET /readyz` | 不要 | DB 到達＋スキーマ version 照合 | api への到達性 |
| `GET /internal/health` | **サービストークン** | 版数・稼働時間・サーバー時刻・DB とスキーマの検査 | 版数・稼働時間・サーバー時刻・api への到達性 |

`/healthz` は**どちらのサービスが答えたか**を本文で名乗る。domain-split（ADR-0019）では web と api が
別ホスト（`idp.*` / `identity.*`）なので、プロキシや DNS の向き先違いを疑うときにホスト名は
根拠にならない。

```bash
curl -sS https://idp.nolumia.com/healthz        # → {"status":"ok","service":"web"}
curl -sS https://identity.nolumia.com/healthz   # → {"status":"ok","service":"api"}
```

### 詳細（`/internal/health`）

版数・起動時刻・稼働時間・サーバー時刻・依存先の検査結果をまとめて返す。切り分けのたびに
複数のエンドポイントを叩き回らずに済む。

**プロキシ経由では 404 になる**（`docker/nginx.domain-split.conf`・`docker/nginx.conf` の
どちらにも `location /internal/ { return 404; }` がある）。読むには Compose ネットワーク内から叩く。

トークンはコンテナ側の環境変数を使うので、`sh -c` で実行する（ホスト側では展開されない）。

```bash
# api の詳細ヘルス
docker compose exec web sh -c \
  'curl -sS http://api:8080/internal/health -H "x-internal-auth-token: $INTERNAL_SERVICE_TOKEN"'

# web の詳細ヘルス
docker compose exec api sh -c \
  'curl -sS http://web:8081/internal/health -H "x-internal-auth-token: $INTERNAL_SERVICE_TOKEN"'
```

```json
{ "service": "api", "status": "pass",
  "version": { "package_version": "0.1.0", "git_version": "abc1234" },
  "started_at": "2026-08-25T00:00:00Z", "uptime_seconds": 3600,
  "server_time": "2026-08-25T01:00:00Z",
  "checks": [ { "name": "database", "status": "pass" },
              { "name": "schema", "status": "pass", "detail": "applied=43 expected=43" } ] }
```

- `status` は `checks` から決まる（1 つでも `fail` なら `fail`）。監視はこの 1 値を見ればよい。
- `checks` の `detail` に内部エラーの原文は載せない。原文は api・web のログを見る。
- 設計上の理由（何をどこまで出すか・`server_time` を返す狙い）は ADR-0031 を参照。

## マイグレーション（スキーマ）の適用状態を確認したいとき

DB を直接参照せずに、いま DB へ適用されているマイグレーション version を確認できる。

- **バージョン情報画面（管理コンソール）**: 管理者としてログインし、`GET /{tenant_id}/admin/version` を開く
  （コンソール下部のフッターのリンクからも入れる）。無認証では見られない（ADR-0034）。「データベース（マイグレーション）」欄に
  「適用済みバージョン」（DB の `_sqlx_migrations` 最大 version）と「期待バージョン」（稼働中 api に埋め込まれた
  最大 version）、および状態を表示する。状態は次の3つを区別する。
  - **最新（スキーマ一致）**: 適用済み ≥ 期待。
  - **DB が遅れています（migrate 未適用）**: 適用済み < 期待。
  - **DB 読み取り不可（運用障害）**: DB へ到達できても `_sqlx_migrations` を読めない（接続断・権限等。api ログにも記録）。
- **JSON（api）**: `GET /internal/version/schema` が `{"expected": <n>, "db_readable": <bool>, "applied": <n|null>}` を返す。
  **サービストークンが必要**で、プロキシ経由では 404（`/internal/*` の扱いは「死活・準備状態を確認したいとき」を参照）。
  同じ内容は `GET /internal/health` の `checks[schema]` にも入っている。

「適用済み < 期待」の場合は DB が古い（`migrate` 未適用）。適用手順は上記「マイグレーションを適用したいとき」
／デプロイ先は「マイグレーションだけを適用したいとき（デプロイ先）」を参照。

> 注意（fail-fast との関係）: api は起動時に「DB が期待 version 以上」を検査し、**未満なら起動を中止**する
> （ADR-0004。同じ理由で Compose では web も api の健全化を待つ）。したがって **DB が遅れている状態では
> スキーマ状態が取得できない**ことがある（画面は「api 未到達」を表示。版数だけは web 自身が知っているので読める）。この場合は
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
   `TRUST_FORWARDED_HEADERS=true`・`HSTS_MAX_AGE` は両ドメインに同様に適用する
   （`TRUST_FORWARDED_HEADERS` は api・web の**両サービス**が読む。未設定＝`false` のままだと、
   ログインの監査ログとレート制限の IP がプロキシのアドレスになり利用者を識別できない）。

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

**api は増やさない。** `docker compose up --scale api=N`（N > 1）や、複数ホストへの api の並列配置は
サポートしていない。レートリミッタ・キャッシュがプロセス内メモリで、署名鍵のローテーションに
排他制御が無いため。理由と影響の一覧は README「スケール前提」を参照。web は増やしてよい。

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

## DB パスワードを変えたいとき／`Access denied for user 'idp'` で止まるとき（デプロイ先）

`.env` の `MARIADB_PASSWORD` を新しい値へ書き換えて再デプロイする。

```sh
# .env の MARIADB_PASSWORD を新しい値に書き換えてから
./deploy.sh app
```

MariaDB は data volume 初回作成時のパスワードを固定し、以後の `.env` 変更を既存 volume へ反映しない。
`deploy.sh` は migration 前のプリフライトでこの不一致を検出し、`.env` を正として **root 経由で DB 側の
`idp` ユーザーのパスワードを `.env` の値へ同期してから続行する**（データは保持される）。したがって
`MARIADB_ROOT_PASSWORD` が既存 volume と一致している限り、パスワード変更は再デプロイだけで完了する。

`MARIADB_ROOT_PASSWORD` も一致しない場合（`.env` を作り直した・別環境の `.env` を持ち込んだ）は
プリフライトで停止する。この状態では `KEY_ENCRYPTION_KEY` も変わっており、既存 DB の暗号化済み署名鍵は
元の `.env` 無しでは復号できない。対処は次のいずれか。

- データを保持したい → 元の `.env`（バックアップ）へ戻して再デプロイする
- データを破棄してよい（初期構築・staging 等）→ `./deploy.sh reset`（既存データは消える）

## 同一ホストに stg / prod を置く場合

`docker-compose.deploy.yml` はコンテナ内の proxy を常に `8080`（web 面）/ `8081`（api 面）で待ち受けさせ、
ホスト側の外部公開ポートだけを `.env` の `WEB_PORT` / `API_PORT` で変える。同じホストに 2 環境を置く
場合、同じポートは同時に bind できないため、例として以下のように分ける（既定の `domain-split` では
`API_PORT` も分ける）。

| 環境 | 配置例 | `.env` テンプレート | web の公開 URL | `WEB_PORT` | api の公開 URL | `API_PORT` | `IMAGE_TAG` |
| --- | --- | --- | --- | --- | --- | --- | --- |
| stg | `/opt/idp/stg` | `.env.staging.example` | `https://idpstg.nolumia.com` | `10010` | `https://identitystg.nolumia.com` | `10011` | `stg` |
| prod | `/opt/idp/prod` | `.env.production.example` | `https://idp.nolumia.com` | `10000` | `https://identity.nolumia.com` | `10001` | `prod` |

前段のリバースプロキシ（Synology DSM 等）で TLS を終端し、上表のドメインを同一ホストの
`127.0.0.1:<WEB_PORT>` / `127.0.0.1:<API_PORT>` へ流す。`PUBLIC_WEB_BASE_URL` は web に、`ISSUER` は
api に、それぞれブラウザ・RP が外から到達する URL（上表の公開 URL）を設定する。
`single-origin` に切り替えた場合は両者を `WEB_PORT` の同一オリジンに揃え、`API_PORT` は使わない。

api は web の兄弟サブドメイン（`identity.nolumia.com` / `identitystg.nolumia.com`。ADR-0019 決定 1。
どちらも apex 直下の 1 ラベルなので、ワイルドカード証明書 `*.nolumia.com` 1 枚で web・api の
両ホストを覆える）。セッション Cookie は各 web ホストの host-only（ADR-0018 決定 2・4）のため、
prod と stg の Cookie スコープは交わらない。**`COOKIE_DOMAIN` は設定しない**（兄弟命名で設定すると
apex まで Cookie が広がる。下記の掃除用途のみ例外）。

> **移行メモ**: 旧 ADR-0012 構成（`COOKIE_DOMAIN=nolumia.com` の Domain 付き Cookie）から
> 移行する場合、ブラウザに `Domain=nolumia.com` の Cookie が残っている。移行後しばらく
> `COOKIE_DOMAIN=nolumia.com` を設定したまま運用すると、ログイン・ログアウト時に旧 Cookie の
> 削除が併送されて掃除される。掃除期間が終わったら未設定へ戻す。
> **`ISSUER` を変更した場合**は RP 側の再設定（discovery・`iss`、SAML SP はメタデータ再取り込み）が
> 必要。
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
`must_change_password = 1`）。ログインは email ではなくユーザー名で照合する
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
