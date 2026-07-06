# OIDC Identity Provider 設計書（MVP）

## 1. 概要

本書は、Rustで実装する OpenID Connect（OIDC）対応 Identity Provider（IdP）のMVP設計を定義する。
本IdPは **OpenID Connect Core 1.0** に準拠し、OAuth 2.1 draft および RFC 9700 の推奨事項を取り込む。

| 項目                      | 方針                                 |
| ----------------------- | ---------------------------------- |
| 対応フロー                   | Authorization Code Flow            |
| PKCE                    | 必須                                 |
| `code_challenge_method` | `S256` のみ                          |
| 対応scope                 | `openid`、拡張として `profile` / `email` |
| ID Token                | JWT / RS256                        |
| Access Token            | JWT / RS256                        |
| Refresh Token           | MVP対象外                             |
| Implicit Flow / ROPC    | 対応しない                              |
| SSO                     | IdPドメインのCookieセッションで実現             |

***

## 2. 設計方針

### 2.1 時刻管理

* 全データはUTCで保持
* JWTの時刻は UNIX秒（`iat` / `exp` / `auth_time`）
* クロックスキュー許容：±60秒

### 2.2 セキュリティ方針

* Authorization Code Flow のみ対応
* PKCE は public / confidential を問わず必須
* `code_challenge_method=plain` は許可しない
* `state` / `nonce` は OIDC 仕様上は任意だが、本IdPではポリシーとして必須化
* `state` はIdPでは検証せず、認可レスポンスで透過的に返却
* authorization code は一度のみ利用可、DBに平文保存しない
* client secret はハッシュ化保存
* JWT署名鍵は `kid` で識別、JWKSで公開
* 全エンドポイントHTTPS必須、本番環境ではHSTSを有効化

### 2.3 redirect\_uri 方針

* 登録済みURIとの完全一致のみ許可
* フラグメント付き / ワイルドカードは禁止
* Web / SPA は `https` のみ
* 開発用途に限り `http://localhost[:port]` を許可
* Native App の loopback redirect URI も port を含めて完全一致

### 2.4 SSOセッション方針

SSOは、IdPドメインのブラウザCookieセッションで実現する。

* `/login` 成功時に SSOセッションを発行
* Cookieにはセッションの平文値、DB/Redisにはハッシュ値を保存
* 次回 `/authorize` 時、SSO Cookie からユーザーを復元できる場合は再ログインを省略
* SSOセッションが無効・期限切れの場合は `/login` に遷移

Cookie属性：`HttpOnly` / `Secure` / `SameSite=Lax` / `Path=/`

ログアウト機能はMVP対象外。

***

## 3. データモデル

> **実装上の注記**: 本節のデータ型は PostgreSQL 表記だが、本プロジェクトの実装 DB は **MariaDB** である
> （`docs/adr/0005-rust-mariadb-stack.md`）。`UUID`→`CHAR(36)`、`CITEXT`→`VARCHAR`+大小無視照合、
> `timestamptz`→`DATETIME(6)`(UTC)、`inet`→`VARCHAR(45)`、`text[]`→`JSON`、`enum`→`VARCHAR`+`CHECK`、
> 部分 UNIQUE 索引→通常の UNIQUE 索引（MariaDB は複数 NULL を許容）と読み替える。詳細は `CLAUDE.md`「DB モデリング」。

### 3.1 Users

```text
id UUID PK
sub UUID UNIQUE NOT NULL

email CITEXT UNIQUE NOT NULL
email_verified bool NOT NULL default false
preferred_username CITEXT nullable
name text nullable

password_hash text NOT NULL
status enum(ACTIVE, DISABLED, LOCKED) NOT NULL default ACTIVE

failed_login_count int NOT NULL default 0
locked_until timestamptz nullable

created_at timestamptz
updated_at timestamptz
```

* `sub` は外部公開用、`id` は内部識別子
* MVPではメール検証フロー対象外のため、登録時 `status = ACTIVE`
* `email_verified` は将来のメール検証フローに備えて保持
* `name` は `profile` scope 用の表示名

`preferred_username` は nullable のため部分ユニークインデックスで制御：

```sql
CREATE UNIQUE INDEX users_preferred_username_uidx
  ON users (preferred_username)
  WHERE preferred_username IS NOT NULL;
```

***

### 3.2 Clients

```text
id UUID PK
client_id text UNIQUE NOT NULL
client_secret_hash text nullable

client_type enum(public, confidential) NOT NULL
client_status enum(ACTIVE, DISABLED) NOT NULL default ACTIVE

app_name text NOT NULL
redirect_uris text[] NOT NULL

grant_types text[] NOT NULL default ['authorization_code']
response_types text[] NOT NULL default ['code']
scopes text[] NOT NULL

token_endpoint_auth_method enum(client_secret_basic, none) NOT NULL
require_pkce bool NOT NULL default true

created_at timestamptz
updated_at timestamptz
```

| client\_type | secret | token\_endpoint\_auth\_method |
| ------------ | ------ | ----------------------------- |
| public       | なし     | `none`                        |
| confidential | 必須     | `client_secret_basic`         |

***

### 3.3 AuthSessions

`/authorize` から `/login` 完了までの一時的な認可リクエスト状態を保持する。

```text
id UUID PK

client_id text NOT NULL
redirect_uri text NOT NULL
scope text[] NOT NULL

state text NOT NULL
nonce text NOT NULL

code_challenge text NOT NULL
code_challenge_method text NOT NULL default 'S256'

authenticated_user_id UUID nullable
auth_time timestamptz nullable

expires_at timestamptz NOT NULL

created_at timestamptz
updated_at timestamptz
```

* `AuthSessions.id` は128bit以上の推測不能なランダム値
* 有効期限：10分
* DBではなくRedis等のセッションストアでもよい
* `/authorize` 時に `auth_session_id` を短命Cookieとして発行（`Max-Age=600`、`HttpOnly` / `Secure` / `SameSite=Lax`）
* `/login` ではCookieの `auth_session_id` を参照
* code発行後は AuthSession を削除し、Cookie も失効させる

***

### 3.4 SsoSessions

IdPのSSOログイン状態を保持する。

```text
session_hash text PK

user_id UUID NOT NULL
auth_time timestamptz NOT NULL

idle_expires_at timestamptz NOT NULL
absolute_expires_at timestamptz NOT NULL

user_agent text nullable
ip_address inet nullable

created_at timestamptz
updated_at timestamptz
```

* Cookieには `session_id`、DB/Redisには `session_hash = SHA-256(session_id)` のみ保存
* `session_id` は256bit以上の暗号学的乱数
* idle timeout：8時間 / absolute timeout：24時間
* `/authorize` 時に有効なSSOセッションがあれば、再ログインせず authorization code を発行
* SSO復元時、`idle_expires_at` は現在時刻+8時間に更新（`absolute_expires_at` は変更しない）

***

### 3.5 AuthorizationCodes

```text
code_hash text PK

user_id UUID NOT NULL
client_id text NOT NULL
redirect_uri text NOT NULL
scope text[] NOT NULL

nonce text NOT NULL
auth_time timestamptz NOT NULL

code_challenge text NOT NULL
code_challenge_method text NOT NULL default 'S256'

expires_at timestamptz NOT NULL
used_at timestamptz nullable

created_at timestamptz
updated_at timestamptz
```

authorization code は256bit以上の暗号学的乱数として生成し、DBには平文保存せず `code_hash = SHA-256(authorization_code)` を保存する。

token endpoint では、検証成功時に原子的に `used_at` を更新する：

```sql
UPDATE authorization_codes
SET used_at = now(), updated_at = now()
WHERE code_hash = :code_hash
  AND used_at IS NULL
  AND expires_at > now()
RETURNING *
```

有効期限：1分

***

### 3.6 SigningKeys

```text
kid text PK
algorithm text NOT NULL default 'RS256'

public_key text NOT NULL
private_key_encrypted text NOT NULL

status enum(ACTIVE, RETIRED) NOT NULL

not_before timestamptz NOT NULL
not_after timestamptz NOT NULL

created_at timestamptz
updated_at timestamptz
```

* ACTIVE鍵で新規JWTに署名
* RETIRED鍵は検証用としてJWKSに残す
* RETIRED鍵は、最大トークン有効期限 + クロックスキュー経過後に非公開化
* 秘密鍵の暗号化キーはDB外で管理

***

## 4. API設計

### 4.1 ユーザー登録

```http
POST /auth/register
```

#### リクエスト

```json
{
  "email": "user@example.com",
  "preferred_username": "user01",
  "password": "password",
  "name": "User Name"
}
```

#### レスポンス

```json
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "status": "ACTIVE"
}
```

***

### 4.2 認可エンドポイント

```http
GET /authorize
```

#### パラメータ

```text
response_type=code
client_id
redirect_uri
scope
state
nonce
code_challenge
code_challenge_method=S256
```

#### 検証項目

* `client_id` が存在し、client が `ACTIVE`
* `redirect_uri` が登録値と完全一致
* `response_type=code`
* `scope` に `openid` を含む
* **要求 scope が `Clients.scopes` の部分集合**
* `state` / `nonce` が存在
* `code_challenge_method=S256` かつ `code_challenge` が存在

#### 動作

1. 認可リクエストを検証する
2. SSO Cookie確認
   * **SSOセッションあり**：ユーザーを復元し、authorization code を発行 → `redirect_uri` にリダイレクト
   * **SSOセッションなし**：AuthSession を作成し、`auth_session_id` Cookie を発行して `/login` へ遷移

> authorization code 発行ロジックは 4.3 と共通モジュールとして実装する。

#### 成功レスポンス

```http
302 Found
Location: https://client.example.com/callback?code=...&state=...
```

#### エラー方針

* `client_id` または `redirect_uri` が無効な場合はリダイレクトしない
* それ以外のエラーは `redirect_uri` にエラーを付与して返す

#### MVPで無視するパラメータ

`prompt` / `max_age` / `login_hint` / `acr_values`

***

### 4.3 ログイン

```http
POST /login
```

#### パラメータ

```text
username
password
csrf_token
```

`auth_session_id` は短命Cookieから取得する。

> **実装メモ（ADR-0007）**: 将来的にログイン画面（web）と認可サーバ（api）は別サービスへ分割される。
> その場合も**外部から見た契約は本節のまま不変**（RP は `/authorize`→`/login`→code 付き redirect を観測する）。
> 分割後は web が `/login` フォームを描画し、資格情報・`auth_session_id` 参照・接続元情報を api の
> 内部エンドポイント `POST /internal/authenticate`（OIDC 標準外）へ転送する。資格情報検証・ロックアウト・
> SSO/code 発行は api（唯一の DB 所有者）が行い、Cookie 組み立てとエラー文言のローカライズは web が担う。

#### 動作

1. Cookieの `auth_session_id` から AuthSession を取得
2. CSRF token を検証
3. username / password を検証
4. アカウント状態とロック状態を確認
5. 認証成功時、SSOセッションを発行
6. AuthSession に user id と `auth_time` を設定
7. authorization code を発行（4.2 と共通モジュール）
8. AuthSession を削除し、`auth_session_id` Cookie を失効させる
9. client の `redirect_uri` にリダイレクト

#### ロックポリシー

* username単位で連続10回失敗 → 15分ロック
* IP単位でもレート制限
* ログイン成功時に `failed_login_count = 0`、`locked_until = NULL` にリセット

***

### 4.4 トークン発行

```http
POST /token
Content-Type: application/x-www-form-urlencoded
```

#### クライアント認証

| client\_type | 認証方式                  |
| ------------ | --------------------- |
| confidential | `client_secret_basic` |
| public       | なし                    |

#### パラメータ

```text
grant_type=authorization_code
code
redirect_uri
code_verifier
client_id
```

#### client\_id の扱い

* public client では body の `client_id` を必須
* confidential client では Basic認証ヘッダ内の `client_id` を優先
* 両方ある場合、不一致なら `invalid_request`

#### 検証項目

* client が存在し、`ACTIVE`
* confidential client の場合、client authentication に成功
* authorization code が存在・未使用・期限内
* `client_id` / `redirect_uri` が一致
* user が `ACTIVE`
* PKCE検証成功

#### code\_verifier 検証

* 長さ：43〜128文字
* 文字種：`A-Z` / `a-z` / `0-9` / `-` / `.` / `_` / `~`

#### PKCE検証

```text
BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) == code_challenge
```

発行する Access Token / ID Token の `scope` は `AuthorizationCodes.scope` を引き継ぐ。

#### レスポンス

```json
{
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 900,
  "id_token": "...",
  "scope": "openid"
}
```

#### レスポンスヘッダ

```http
Cache-Control: no-store
Pragma: no-cache
```

***

### 4.5 OIDC Discovery

```http
GET /.well-known/openid-configuration
```

* `issuer` は末尾スラッシュなしで定義
* Discoveryの `issuer` と ID Token の `iss` は完全一致

#### レスポンス例

```json
{
  "issuer": "https://idp.example.com",
  "authorization_endpoint": "https://idp.example.com/authorize",
  "token_endpoint": "https://idp.example.com/token",
  "userinfo_endpoint": "https://idp.example.com/userinfo",
  "jwks_uri": "https://idp.example.com/.well-known/jwks.json",
  "scopes_supported": ["openid", "profile", "email"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "none"],
  "code_challenge_methods_supported": ["S256"],
  "claims_supported": [
    "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
    "email", "email_verified", "preferred_username", "name"
  ]
}
```

***

### 4.6 JWKS

```http
GET /.well-known/jwks.json
```

#### レスポンス例

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "2026-06-01-rs256-1",
      "alg": "RS256",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

***

### 4.7 UserInfo

```http
GET /userinfo
Authorization: Bearer <access_token>
```

#### 検証項目

* JWT署名
* JWTヘッダの `typ == "at+jwt"`
* `iss` / `aud` / `exp`
* `scope`
* user が `ACTIVE`

#### レスポンス

```json
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "email_verified": true,
  "preferred_username": "user01",
  "name": "User Name"
}
```

#### scope制御

| scope     | 返却クレーム                       |
| --------- | ---------------------------- |
| `openid`  | `sub`                        |
| `email`   | `email`, `email_verified`    |
| `profile` | `preferred_username`, `name` |

***

## 5. トークン仕様

### 5.1 ID Token

#### Header

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "<key-id>"
}
```

#### Payload

```json
{
  "iss": "https://idp.example.com",
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "aud": "client-id",
  "exp": 1710003600,
  "iat": 1710000000,
  "auth_time": 1710000000,
  "nonce": "client-generated-nonce",
  "jti": "token-id"
}
```

#### 必須クレーム

`iss` / `sub` / `aud` / `exp` / `iat` / `auth_time` / `nonce` / `jti`

#### 任意クレーム

`email` / `email_verified` / `preferred_username` / `name`

#### auth\_time 方針

* `/login` を経由した場合：今回の認証時刻
* SSOセッション復元の場合：**`SsoSessions.auth_time`（初回ログイン時刻）をコピー**

#### 有効期限

ID Token lifetime = 3600秒

***

### 5.2 Access Token

MVPでは `/userinfo` 用のJWTとして発行する。

#### Header

```json
{
  "alg": "RS256",
  "typ": "at+jwt",
  "kid": "<key-id>"
}
```

#### Payload

```json
{
  "iss": "https://idp.example.com",
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "aud": "https://idp.example.com/userinfo",
  "client_id": "client-id",
  "scope": "openid email profile",
  "exp": 1710000900,
  "iat": 1710000000,
  "jti": "token-id"
}
```

#### 必須クレーム

`iss` / `sub` / `aud` / `client_id` / `scope` / `exp` / `iat` / `jti`

#### 有効期限

Access Token lifetime = 900秒

#### aud方針

MVPでは `aud` を `/userinfo` endpoint に固定。将来、外部リソースサーバを管理対象にする場合は動的に決定する。

***

## 6. 処理フロー

```text
Client -> IdP: GET /authorize

IdP:
  認可リクエスト検証
  SSO Cookie確認

  [SSOセッションあり]
    user復元
    authorization code発行
    -> redirect_uriへリダイレクト

  [SSOセッションなし]
    AuthSession作成
    auth_session_id Cookie発行
    -> /loginへ遷移

User -> IdP: POST /login

IdP:
  auth_session_id CookieからAuthSession取得
  認証成功
  SSOセッション発行
  auth_time記録
  authorization code発行
  AuthSession削除 / Cookie失効
  -> redirect_uri?code=...&state=...

Client -> IdP: POST /token

IdP:
  authorization code検証
  PKCE検証
  used_at更新
  ID Token / Access Token発行
```

***

## 7. 監査ログ

MVPでも以下は構造化ログとして出力する。

```text
login.succeeded
login.failed
login.locked

authorization_code.issued
authorization_code.used
authorization_code.reuse_detected

token.issued
client.authentication_failed

sso_session.created
sso_session.resumed
sso_session.expired
sso_session.terminated   # 将来のLogout用に予約

user_permission.granted  # 管理者による利用者権限の付与（ADR-0006）
user_permission.revoked  # 管理者による利用者権限の剥奪（ADR-0006）

client.registered        # 管理者によるクライアント（RP）登録（§9.3）
client.updated           # 管理者によるクライアント更新
client.secret_rotated    # 管理者による client_secret 再発行
```

#### ログ項目

```text
event_type
timestamp
user_id nullable
client_id nullable
ip_address
user_agent
result
reason nullable
correlation_id
```

***

## 8. MVP対象外

* Refresh Token
* MFA
* Consent画面
* Dynamic Client Registration
* Revocation Endpoint
* Introspection Endpoint
* Front-channel / Back-channel Logout
* JAR / PAR / DPoP / mTLS
* 外部リソースサーバ管理
* 管理コンソール
* `prompt` / `max_age` の正式対応

***

## 9. 今後拡張

### 9.1 Refresh Token

* `RefreshTokens` テーブル追加（ハッシュ保存）
* refresh token rotation / reuse detection
* `offline_access` scope 要求時のみ発行

### 9.2 Consent

* clientごとの同意済みscope記録
* consent画面 / 同意取り消し機能

### 9.3 Client管理

* client登録API / secret再発行 / 無効化
* redirect URI / scope 変更
* `private_key_jwt` 対応

### 9.4 Token管理

* revocation endpoint
* introspection endpoint
* user単位の全セッション無効化

***

## 10. MVP完了条件

1. ユーザー登録ができる
2. 登録済みclientから `/authorize` を開始できる
3. 未ログイン時に `/login` へ遷移できる
4. ログイン成功後、SSOセッションを発行できる
5. ログイン成功後、authorization code を発行できる
6. 2回目以降の `/authorize` で、SSOセッションにより再ログインなしで code を発行できる
7. `state` を認可レスポンスで返却できる
8. `/token` で PKCE S256 を検証できる
9. authorization code を一度だけ利用できる
10. ID Token / Access Token を RS256 で署名できる
11. JWKS / Discovery endpoint を返却できる
12. `/userinfo` で scope に応じた claim を返却できる
13. ログイン、code発行、token発行、client認証失敗を監査ログに出力できる

***

## 11. まとめ

本MVPでは、OIDC IdPとして必要な最小構成に加え、**SSOとして成立するためのIdP Cookieセッション**を実装対象に含める。

実装対象：

```text
Authorization Code Flow
PKCE S256
SSO Cookie Session
AuthSession
ID Token / Access Token
Discovery / JWKS / UserInfo
client authentication
authorization code one-time use
監査ログ
```

Refresh Token、MFA、Consent、Revocation、Introspection、PAR、JAR、DPoP などは将来拡張とする。
