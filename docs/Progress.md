# Progress

進行中・未着手タスクのみを管理する（完了したら本ファイルから削除し、必要なら `CHANGELOG.md` / `history/` へ）。

タスクは改訂後 ADR-0009（テナント独立・Entra ID 型 / UUIDv7 / 完全一致 scope / 初期 DDL 刷新）の
Phase 計画、および ADR-0010（ゼロタッチ配置・設定値の出所管理）に沿う。

## 優先度の算出

| 項目 | 小 (1) | 中 (3) | 大 (5) |
|---|---:|---:|---:|
| 影響度（修正範囲） | 単一機能・単一プロンプト | 複数機能 | システム全体・広範囲 |
| 重要度（セキュリティリスク） | なし | 社内情報への影響 | 個人情報・機密情報への影響 |
| 難易度 | 簡単 | 標準 | 難しい |

| 工数 | 補正値 |
|---|---:|
| 小 | 1 |
| 中 | 2 |
| 大 | 3 |

`優先度スコア = (影響度 × 重要度 × 難易度) ÷ 工数補正値`。バックログは優先度スコアの
降順で並べる。同点はセキュリティリスク、前提タスク、障害復旧性の順で先にする。

## 推奨モデルの基準

各タスクの **難易度（工数）× リスク（影響度）** で Claude モデルを割り当てる。リスクは
「テナント分離・認可境界・トークン検証・自動生成シークレット・データ基盤の整合」を重く見る。

| モデル | 割り当て基準 |
|---|---|
| **Opus 4.8** | 高リスク（セキュリティ境界・分離防御線・保証の要）または高難度（広範囲波及・設計判断を伴う） |
| **Sonnet 5** | 仕様が明確な機能実装・中程度の面。標準的な難度で判断も限定的 |
| **Haiku 4.5** | 定型・低リスク（確立パターンの反復、限定的な UI・文言・設定） |

## バックログ

| 優先度 | ID | 課題内容 | 工数 | 影響度 | 重要度 | 難易度 |
|---:|---|---|---:|---:|---:|---:|
| 15 | AP5 | Step-up 認証（仕様 §15。認証済みユーザーへの再認証・強い認証の要求。MFA 設定変更・パスワード変更等の重要操作に適用。AP4 が前提）（⬜未着手） | 大 | 中 | 中 | 大 |
| 15 | AP9 | 認証器の統合管理（仕様 §5。`user_authenticators` への統合・状態管理（pending/active/suspended/revoked）・リカバリーコード・email/sms OTP）（⬜未着手） | 大 | 中 | 中 | 大 |
| 15 | AP10 | 外部 IdP 認証（仕様 §13。外部 OIDC/SAML IdP を認証器として使う。`iss`+`sub` での外部ユーザー識別・トークン検証・IdP 制限ポリシー）（⬜未着手） | 大 | 大 | 中 | 大 |
| 15 | G4 | `client_credentials` grant 未対応（サーバ間＝M2M 連携が一切できない）（⬜未着手） | 大 | 大 | 中 | 中 |
| 14 | G5 | Back-channel logout が撃ちっぱなし（リトライ・永続キュー無し）＋ `logout_token` に `sid`・`exp` が無くセッション単位ログアウトができない（⬜未着手） | 中 | 中 | 中 | 中 |
| 14 | G10 | 利用者セルフサービスの欠落（ログイン中セッションの一覧・失効／連携済みアプリ（consent）の確認・取り消し。`ClientConsentRepository::revoke`・`list_for_user` は実装済みだが呼び出し元が無い）（⬜未着手） | 中 | 中 | 中 | 中 |
| 14 | AP2 | 認証ポリシーの評価をポータル・管理コンソールログインへも適用する（現状は OIDC フローのみ。ADR-0020）（⬜未着手） | 中 | 中 | 中 | 中 |
| 14 | AP4 | 認証セッションへの認証方式・強度・MFA 完了状態の記録（仕様 §14.3・§18.1。`sso_sessions` へ `authentication_methods`・`authentication_strength`・`mfa_completed_at` を追加。MFA 経過時間による再認証（§18.2）と Step-up の判定材料）（⬜未着手） | 中 | 中 | 中 | 中 |
| 9 | SEC5 | CSRF double-submit の種（`admin_csrf_id`/`portal_csrf_id`）がオリジン非分離 → `__Host-` 前置（⬜未着手） | 小 | 中 | 中 | 小 |
| 9 | SEC7 | 認証成功時に `auth_session_id` を再生成しない（`sso_session_id` は再生成済みで非対称）（⬜未着手） | 小 | 小 | 中 | 中 |
| 9 | SEC9 | クエリ文字列（`?auth_session=`・`?code_challenge=`）が `TraceLayer` 既定スパン経由でログに出うる（⬜未着手） | 小 | 中 | 中 | 小 |
| 8 | SEC1 | web が `X-Forwarded-For` を無条件信頼（api の `TRUST_FORWARDED_HEADERS` ゲートを迂回）→ レート制限回避・監査ログ汚染（⬜未着手） | 中 | 中 | 大 | 小 |
| 8 | SEC6 | `auth_sessions.id` だけ DB に平文保存（他の bearer credential は全てハッシュ）（⬜未着手） | 中 | 小 | 大 | 中 |
| 8 | SEC8 | 再利用検知時に子孫トークンファミリを失効させない（authorization code・refresh token の両方）（⬜未着手） | 中 | 小 | 大 | 中 |
| 8 | AP3 | 認証ポリシーの条件種別を拡張する（ネットワークゾーン・国・端末・時間帯・requested_acr 等。仕様 §8）と `require_specific_method` 効果（⬜未着手） | 大 | 中 | 中 | 大 |
| 8 | AP8 | ログイン識別子の複数化（仕様 §4。`user_login_identifiers`: 電話番号・社員番号等の種別、表示値と正規化値の分離、識別子単位の無効化）（⬜未着手） | 大 | 大 | 小 | 大 |
| 5 | SEC12 | 低リスク改善のまとめ（CSP `unsafe-inline`・Swagger 無認証・`require_pkce` 死に設定・同意 POST の Cookie 非束縛・argon2 パラメータ非明示・auth_sessions の GC/照合/`expect()`）（⬜未着手） | 中 | 中 | 小 | 中 |
| 5 | AP1 | 認証ポリシーの管理画面（web コンソール UI。現状は API のみ）（⬜未着手） | 中 | 中 | 小 | 中 |
| 5 | AP7 | パスワードポリシーの拡張（仕様 §11.2。漏えい済みパスワード検出・過去パスワード再利用禁止・有効期限。現状は最小文字数のみ）（⬜未着手） | 中 | 小 | 中 | 中 |
| 5 | G1 | CORS 未実装（api・nginx とも）。public client（SPA）がブラウザから `/token`・`/userinfo`・`/.well-known/*` を呼べない（⬜未着手） | 中 | 中 | 小 | 中 |
| 5 | G2 | 期限切れレコードの GC が `log` テーブルにしか無い（`auth_sessions`・`authorization_codes`・`refresh_tokens`・`sso_sessions`・`revoked_access_tokens`・`passkey_challenges`・各種トークン表が無限に増える）（⬜未着手） | 中 | 中 | 中 | 小 |
| 5 | G9 | api のシングルインスタンス前提が明文化されていない（レートリミッタ・キャッシュがプロセス内メモリ、鍵ローテーションが排他制御無し）（⬜未着手） | 小 | 大 | 小 | 小 |
| 5 | G11 | web crate に統合テストが無い（`crates/web/tests/` 不在。ルータ経由の検証は `scripts/e2e.sh` 頼み）（⬜未着手） | 中 | 中 | 小 | 中 |
| 5 | G12 | `/authorize` の任意パラメータ未対応（`login_hint`・`ui_locales`・`id_token_hint`・`acr_values`・`response_mode`・`prompt=select_account`）と Discovery の広告不足（⬜未着手） | 中 | 中 | 小 | 中 |
| 3 | SEC10 | `/token`・`/introspect`・`/revoke` にレート制限が無い（Argon2 増幅型 DoS）（⬜未着手） | 小 | 小 | 中 | 小 |
| 3 | AP6 | アカウントロックの管理者解除（仕様 §17.1・§24.6。`locked_until` を即時クリアする管理操作。現状は期限経過待ちのみ）と段階的ロック（⬜未着手） | 小 | 小 | 中 | 小 |
| 3 | G3 | `client_secret_post` 未対応（`client_secret_basic` / `none` のみ。RP ライブラリ既定との相互運用性）（⬜未着手） | 小 | 中 | 小 | 小 |
| 3 | G8 | `audit_log` に絞り込み用の索引（`client_id`・`user_id`・`result`・複合 `(tenant_id, occurred_at)`）と保持期間の仕組みが無い（`log` にはある）（⬜未着手） | 小 | 中 | 小 | 小 |
| 2 | G6 | メトリクスが無い（`/metrics` 非公開。ログイン成功率・トークン発行レート・レイテンシ・DB プール枯渇を監視できない）（⬜未着手） | 中 | 中 | 小 | 小 |
| 1 | G7 | 一覧 API のページング欠落（`list_clients`・`list_tenants`・権限一覧は全件返す。members・audit にはある）（⬜未着手） | 小 | 小 | 小 | 小 |

## 詳細

### ユーザー認証・認証ポリシー仕様書の残実装（AP1〜AP10）

ADR-0020 で `authentication_policies`（deny / require_mfa / allow、client_ids・user_ids 条件）・
管理 API・OIDC ログインフロー（パスワード・パスキー・強制パスワード変更）への適用・アカウント
ロックの設定化（`LOGIN_MAX_FAILED_ATTEMPTS` / `LOGIN_LOCK_DURATION_SECS`）を導入済み。
仕様書に対する残実装をタスク化する:

- **AP1** 管理画面（web コンソール UI）。現状は API のみ（手順は `docs/OPERATIONS.md`）。
- **AP2** ポータル・管理コンソールログインへの評価適用。ポータルはクライアント文脈が無いため
  `user_ids` 条件と require_mfa が主対象。
- **AP3** 条件種別の拡張（仕様 §8: ネットワークゾーン・国・端末信頼・時間帯・requested_acr 等）と
  `require_specific_method` 効果。WebAuthn 必須・UV 必須等の要求（§12.2）を含む。
- **AP4** 認証セッションへの `authentication_methods`・`authentication_strength`・
  `mfa_completed_at` の記録（§14.3・§18.1）。MFA 経過時間による再認証（§18.2
  `max_authentication_age`）と AP5 の判定材料になるため先行させる。
- **AP5** Step-up 認証（§15）。MFA 設定変更・パスワード変更・外部 IdP 紐付け等の重要操作へ、
  現在の認証強度・前回認証時刻に応じた追加認証を要求する。AP4 が前提。
- **AP6** アカウントロックの管理者即時解除（`locked_until` クリア）と段階的ロック（§17.1）。
- **AP7** パスワードポリシーの拡張（§11.2）。
- **AP8** ログイン識別子の複数化（§4 `user_login_identifiers`）。`users.email` /
  `preferred_username` 直付けからの移行（expand/contract）を伴う。
- **AP9** 認証器の統合管理（§5 `user_authenticators`）。TOTP・WebAuthn の別テーブルを状態付きの
  統合モデルへ寄せ、リカバリーコード・email/sms OTP を追加する。AP8 と同じく DDL 移行が主コスト。
- **AP10** 外部 IdP 認証（§13）。外部 OIDC/SAML IdP を認証器として使い、`iss`+`sub` で内部
  ユーザーへ紐付ける。IdP 制限・外部 MFA 信頼の判定は認証ポリシーの条件として表現する。

### セキュリティレビュー（SEC1〜SEC12）

api / web の別サブドメイン構成を対象にした調査で検出した課題。**「api には対策があるのに web 側に無い」
非対称**が主軸。良好な点（回帰させない）: redirect_uri/post_logout の完全一致、code の 256bit・SHA-256・
60 秒・原子的ワンタイム、PKCE S256 の無条件強制、client_secret の Argon2 保存、sso_session_id の
256bit・ハッシュ保存・ログイン毎の再生成、ADR-0018 の Cookie 非依存ハンドオフ（単回・60 秒・テナント固定束縛）。

#### SEC1. web の `X-Forwarded-For` 無条件信頼

api は `request_context()` が `trust_forwarded`（`TRUST_FORWARDED_HEADERS`、既定 false）でゲートする
（`crates/api/src/presentation/handlers/mod.rs:58-72`。コメント「ヘッダ偽装対策; S1」）のに対し、web の
`forwarded_context()`（`crates/web/src/handlers/mod.rs:78-83`）はゲート無しで先頭値を採用する。ADR-0018 以降
ログインの入口は web で、web が組み立てた IP を `/internal/authenticate` ボディで api のレートリミッタ・監査へ
渡すため、api 側ゲートがログイン経路で迂回される。攻撃者は `X-Forwarded-For` を毎回変えて IP レート制限
（30回/5分）を回避、送らなければ IP が `None` になりレート制限自体をスキップ（`crates/core/src/application/login.rs:203`
の `if let Some(ip)` ガード）、監査ログの IP も任意汚染できる。対策: web にも `TRUST_FORWARDED_HEADERS`
相当のゲートと、非信頼時の `ConnectInfo` フォールバックを入れる。

#### SEC5. CSRF double-submit の種がオリジン非分離

`admin_csrf_id` / `portal_csrf_id`（`crates/web/src/cookies.rs:21-27`）はセッション非依存の種を置く
double-submit。Cookie はサブドメイン間で分離されないため、同一親ドメインのサブドメインを奪った攻撃者が
`Domain=親` の種を強制しトークンを偽造しうる。`console_csrf_token`（`sso_session_id` 由来）はこの弱点なし。
対策: 未認証フォーム系の種に `__Host-` プレフィックスを付ける。

#### SEC6. `auth_sessions.id` だけ DB に平文保存

Cookie 値がそのまま PK（`migrations/0001_baseline.up.sql:160-162, 178`、参照は `WHERE id = ?`
`crates/core/src/infrastructure/repositories/auth_session.rs:113-123`）。同じ表の `handle_hash` すら
SHA-256、他の bearer credential も全てハッシュ保存で非対称。DB 読取を得た者は TTL(600 秒)の間、同意待ち／
MFA 待ちの認可セッションを乗っ取れる。対策: `handle_hash` と揃えて SHA-256 保存へ（マイグレーション必要）。

#### SEC7. 認証成功時に `auth_session_id` を再生成しない

`set_password_verified` / `set_authenticated_user`（`crates/core/src/infrastructure/repositories/auth_session.rs:158-194`）
は認証前に発行した Cookie 値を使い回す。`sso_session_id` はログイン毎に再生成するのに非対称。
`password_verified_at` / `authenticated_user_id` を初めて立てる時点で id をローテートする。

#### SEC8. 再利用検知時に子孫トークンファミリを失効させない（code・refresh の両方）

- **authorization code**: `crates/core/src/application/token.rs:219-235` は再利用を監査記録するだけで、
  1 回目の交換で発行済みのアクセス／リフレッシュトークンは生かしたまま。監査 reason も
  「not found/expired/used」を 1 文字列に丸め、真の再利用を期限切れと区別できない。
- **refresh token**（当初の記述を訂正）: 再利用検知時（`token.rs:410-434`）に `revoke(&rt_hash, now)` で
  **提示された（親）トークンしか失効させない**（`crates/core/src/infrastructure/repositories/refresh_token.rs:94-105`
  は `token_hash` 完全一致の 1 行のみ更新）。そこから rotation 済みの**子トークン（子孫チェーン）は有効なまま**
  残る。当初「refresh 側はチェーン失効を実装済み」と書いたが誤り。`revoke_all_for_user_in_tenant`
  （`refresh_token.rs:117-`）は存在するが再利用検知経路では呼ばれない。
- 対策: 再利用検知時に当該トークンファミリ（`parent_hash` を辿る子孫、または発行元 auth_session/user
  単位）を一括失効させる。RFC 6819 / OAuth 2.1 の推奨に沿える。

#### SEC9. クエリ文字列がログに出うる（ADR-0018 の受け入れ条件が未達）

api / web とも `TraceLayer::new_for_http()`（`crates/api/src/presentation/router.rs:317`・
`crates/web/src/router.rs:317`）の既定スパンが `uri` をクエリ込みで持つ。現状 INFO 止まりで出力されないが、
`RUST_LOG=debug` で `/{tenant}/login?auth_session=…`・`/authorize?…code_challenge=…` が stdout に落ちる。
対策: `make_span_with` で `uri.path()` のみを記録する。

#### SEC10. `/token`・`/introspect`・`/revoke` にレート制限が無い

client_secret は Argon2 照合（`crates/core/src/application/token.rs:602-605`）で総当たりは非現実的だが、
メモリハード関数の CPU/メモリ増幅型 DoS が成立する。

#### SEC12. 低リスク改善のまとめ

- CSP に `script-src 'unsafe-inline'`（`crates/web/src/security_headers.rs`、コード内で自認済み）→ nonce 化。
- Swagger UI `/api/docs` が無認証・CSP 無しで常時公開（`crates/api/src/presentation/router.rs:315`）→ 公開可否確認。
- `Client::require_pkce` が死んだ設定（`crates/core/src/domain/client.rs:25`）。管理コンソールに「PKCE 必須」
  チェックボックスが出る（`crates/web/templates/console/client_form.html:45`）のに `/authorize`・`/token` から
  参照されず実際は常に S256 必須 → 削除か実装。
- 同意 POST がフォーム値の `auth_session_id` だけで動き Cookie と突き合わせない（`crates/web/src/handlers/consent.rs:89`）。
- argon2 が `Argon2::default()` でパラメータ非明示（依存更新で暗黙変化）→ 定数化。
- `auth_sessions` の期限切れ GC ジョブが無い（G2 に統合） / ci 照合（`utf8mb4_unicode_ci`）の秘密値 PK /
  `crates/core/src/application/authorize.rs:575,589` の `expect()` パニック経路 / CSRF 比較が非定数時間。

### 機能・運用のギャップ（G1〜G12）

セキュリティ（SEC）・認証仕様（AP）とは別軸で、**IdP としての機能欠落・運用性**を対象にした
レビューで検出した課題。良好な点（回帰させない）: DDD 4層と crate 境界の一致（web は sqlx に
依存できない）、i18n の en/ja キー完全一致（771 行同数）、設定の出所区分（`Builtin`/`EnvLocked`/
`DbManaged`）の単一定義、テナント分離の統合テスト、ADR による設計判断の追跡可能性。

#### G1. CORS 未実装 → public client（SPA）が実質使えない

api のルータに `CorsLayer` が無く（`crates/api/src/presentation/router.rs:327-340`）、
nginx にも `add_header Access-Control-*` が無い（`docker/nginx.conf`）。既定トポロジは
`domain-split`（api と web が別ホスト名）なので、SPA が `identity.example.com/{tenant}/token` を
呼ぶのは常にクロスオリジンになる。`application/x-www-form-urlencoded` は CORS-safelisted なので
リクエスト自体は飛ぶが、`Access-Control-Allow-Origin` が無いためブラウザが**レスポンスを読めない**。
`clients.client_type = 'public'`・`token_endpoint_auth_method = 'none'` を DDL でサポートし PKCE を
必須にしている以上、想定利用者は SPA だが現状は到達できない。

対策は経路ごとに分ける。**「クライアントの `redirect_uris` から許可オリジンを引く」を全経路へ一律
適用することはできない**（リクエストからクライアントを特定できない経路があるため）:

| 経路 | クライアント特定 | 方針 |
|---|---|---|
| `/.well-known/openid-configuration`・`/.well-known/jwks.json`・`/{tenant}/saml/metadata` | **不可**（client_id もトークンも載らない） | 無認証で誰でも取得できる公開メタデータなので `Access-Control-Allow-Origin: *`。`Allow-Credentials` は付けない |
| `/token`・`/revoke`・`/introspect` | 可（body の `client_id`） | `application/x-www-form-urlencoded` は CORS-safelisted でプリフライトが発生しないため、実リクエストの `client_id` から `redirect_uris` のオリジン集合を引いて `Access-Control-Allow-Origin` に反映する |
| `/userinfo` | **不可**（`Authorization: Bearer` が非 safelisted → 必ずプリフライトされるが、OPTIONS にトークンは載らない） | テナント内 public client の `redirect_uris` オリジンを合わせた allowlist、または配置レベルの設定キー（`CORS_ALLOWED_ORIGINS`）で照合する |

いずれの経路も **`Access-Control-Allow-Credentials` は付けない**（api はブラウザ Cookie を読まない。
ADR-0018）。したがって公開メタデータの `*` はセッションの持ち出しにつながらない。

#### G2. 期限切れレコードの GC が `log` テーブルにしか無い

`crates/api/src/lib.rs:79` の `spawn_application_log_purge` だけが定期削除を行い、他は誰も消さない。
`passkey_challenges` は `delete_expired` を実装済み（`crates/core/src/infrastructure/repositories/passkey_challenge.rs:97`）
だが**呼び出し元が無い**。無限に増える表: `auth_sessions`・`authorization_codes`・`refresh_tokens`・
`sso_sessions`・`revoked_access_tokens`・`passkey_challenges`・`password_reset_tokens`・
`email_verification_tokens`・`saml_sso_requests`。`revoked_access_tokens` は `/introspect` の
ブラックリスト照合に使うため、肥大はレイテンシに直結する。対策: 期限切れ削除を 1 本の
バックグラウンドタスク（`spawn_expired_record_purge`）に集約し、間隔と保持期間を設定キー化する。

#### G3. `client_secret_post` 未対応

`/token` のクライアント認証は `Authorization: Basic` のみ（`crates/api/src/presentation/handlers/token.rs:43`、
`TokenCommand` に `client_secret` フィールドが無い）。Discovery も
`token_endpoint_auth_methods_supported: ["client_secret_basic", "none"]`。RFC 6749 §2.3.1 は
`client_secret_basic` を推奨しつつ `client_secret_post` の受け入れも認めており、実際の RP
ライブラリ・SaaS 連携には `client_secret_post` を既定にするものが多い。相互運用の実害があるわりに
実装は body から 2 フィールドを読むだけ。対策: body での受け取りを追加し Discovery に広告する
（Basic と body の**併用は `invalid_request`** とする）。

#### G4. `client_credentials` grant 未対応

`TokenService::issue` の分岐は `authorization_code` / `refresh_token` のみ
（`crates/core/src/application/token.rs:164-170`）。サーバ間（M2M）でアクセストークンを取る手段が
無く、IdP を「アプリのユーザーログイン」にしか使えない。バッチ・内部サービス・API ゲートウェイ連携は
現状 `INTERNAL_SERVICE_TOKEN` の共有シークレット一本に頼るしかない。対策: `client_credentials` を
confidential client 限定で追加し、`sub` をクライアント自身とする（ID Token は発行しない・
`offline_access` は許可しない）。scope は `Clients.scopes` の部分集合に限る。

#### G5. Back-channel logout の信頼性と `sid` 欠落

`send_backchannel_logout_tokens`（`crates/api/src/presentation/handlers/logout.rs:100-172`）は
`tokio::spawn` で撃ちっぱなし。非 2xx は WARN を出すだけでリトライせず、プロセス再起動で
未送信分が消える。RP 側のログアウトが**黙って落ちる**ため、ログアウトしたつもりのセッションが
RP に残る。加えて `LogoutTokenClaims` に `sid` が無く、`exp` も無い。`sid` が無いと RP は
`sub` 単位でしか失効できず（同一ユーザーの別デバイスのセッションまで巻き添え）、Discovery で
`backchannel_logout_session_supported` を広告できない。対策: `sso_sessions` の識別子から導出した
`sid` を ID Token とログアウトトークンの双方へ載せ、送信を再試行付きの永続キュー（テーブル + ワーカー）
にする。登録時の URI 検証（旧 SEC2）は対応済みなので、残るのは送信の信頼性と `sid`・`exp` の付与。

#### G6. メトリクスが無い

`/metrics`（Prometheus）に相当する出口が無く、可観測性は JSON ログと `log`・`audit_log` テーブルだけ。
ログイン成功率・トークン発行レート・エンドポイント別レイテンシ・sqlx コネクションプールの枯渇・
鍵ローテーションの成否といった、IdP の SLO を見るのに要る値が取れない。対策: `metrics` +
`metrics-exporter-prometheus` を入れ、`/metrics` を内部面（`/internal/` と同じくプロキシで公開遮断）に置く。

#### G7. 一覧 API のページング欠落

`list_clients`（`crates/api/src/presentation/handlers/admin_clients.rs:93`）・`list_tenants`
（`admin_tenants.rs:44`）・権限一覧が `Vec` を全件返す。`admin_members`・`admin_audit` には
`limit`/`offset` があるので非対称。テナント内クライアントが数百になると管理コンソールが重くなる。

#### G8. `audit_log` の索引不足と保持期間の欠如

索引は `event_type`・`correlation_id`・`occurred_at`・`tenant_id` の**単一列 4 本**のみ
（`migrations/0001_baseline.up.sql:365-368`）。管理コンソールの絞り込みは
「テナント × 期間 × event_type × result × client_id」の組み合わせなので、複合索引
`(tenant_id, occurred_at)` が無いと期間検索が事実上の全表走査になり、`client_id`・`result`・
`user_id` には索引すら無い。また `log` には `APP_LOG_RETENTION_DAYS` があるのに `audit_log` には
保持期間の仕組みが無く、法定保存期間の設計も未定。対策: 複合索引の追加と
`AUDIT_LOG_RETENTION_DAYS`（既定は「削除しない」）の導入。

#### G9. api のシングルインスタンス前提が明文化されていない

`InMemoryLoginRateLimiter`（`crates/core/src/infrastructure/rate_limit.rs`）・`InMemoryTtlCache`
（`infrastructure/cache.rs`）はプロセス内メモリで、コード内コメントは「MVP は単一インスタンス前提」と
断っている。さらに署名鍵の自動ローテーション（`crates/api/src/lib.rs:84-98`）は排他制御なしの
バックグラウンドループ。api を 2 プロセス以上にすると、(a) ログインのレート制限が実質 N 倍に緩み、
(b) 権限・テナントのキャッシュ無効化がインスタンス間で伝わらず、(c) 鍵ローテーションが競合しうる。
CLAUDE.md は Redis を「セッションストアとして任意採用」と書くが実装は無い。対策: まず README /
OPERATIONS に**制約として明記**する（コストは低く、誤った水平スケールを防げる）。共有ストア
（Redis 実装 + ローテーションの DB アドバイザリロック）は別タスクとする。

#### G10. 利用者セルフサービスの欠落

`user_settings` にあるのはパスワード変更・氏名変更・言語のみ（`crates/web/src/handlers/user_settings.rs`）。
一般的な IdP が持つ次の 2 つが無い:

- **ログイン中セッションの一覧・失効**。`sso_sessions` を本人が見て個別に切れない（できるのは
  現在のセッションのログアウトだけ）。端末を紛失した利用者の自助手段が無い。
- **連携済みアプリ（consent）の確認・取り消し**。`ClientConsentRepository` には `revoke` と
  `list_for_user` が実装済み（`crates/core/src/infrastructure/repositories/consent.rs:93,106`）だが、
  application 層・エンドポイントからの**呼び出し元が無い**。一度同意すると利用者側から解除できず、
  scope 追加時の再同意（`authorize.rs` の同意判定）以外で consent 行が変わらない。

対策: ポータルに「セキュリティ」タブを設け、セッション一覧＋失効と連携アプリ一覧＋取り消しを載せる。
**必要な作業量は 2 つで異なる**:

- **consent 側**はリポジトリ層が揃っているので application + presentation + テンプレートで足りる。
- **セッション側はリポジトリ層から要る**。`SsoSessionRepository`（`crates/core/src/domain/repositories.rs:323-331`）は
  `create` / `find_by_hash` / `extend_idle` / `delete` / `delete_all_for_user` のみで、
  **ユーザー単位の一覧取得が trait にも sqlx 実装にも無い**。`list_for_user(user_id)` の追加が要る。
  表示に要る列（`auth_time`・`user_agent`・`ip_address`・`created_at`）は `sso_sessions` に既にあり
  索引 `sso_sessions_user_idx` も張ってあるので、マイグレーションは不要。
  失効は既存の `delete(session_hash)` で足りるが、PK が秘密値由来のハッシュなので、画面へ
  ハッシュをそのまま出すか非可逆の表示用 ID を別に持つかは実装時に決める（ハッシュ自体は
  Cookie 値ではなく、提示しても認証には使えない）。

#### G11. web crate に統合テストが無い

`crates/api/tests/` には 25 本の統合テスト（sqlx + axum）があるのに、`crates/web/tests/` は**存在しない**。
web は 14.9k LOC で、ログイン・同意・MFA・パスキー・管理コンソールという**ブラウザ経路の入口全部**を
持つ。ハンドラ内の `#[test]` は 89 個あるが、いずれも純関数・テンプレート描画の単体検証で、
ルータ経由（Cookie・CSRF・リダイレクト・api クライアントのエラー処理）は `scripts/e2e.sh` の
シェルスクリプト頼み。対策: `wiremock` で api をスタブし、`tower::ServiceExt::oneshot` で
web ルータを叩く統合テストを追加する（DB 不要で CI が速い）。

#### G12. `/authorize` の任意パラメータ未対応と Discovery の広告不足

`AuthorizeRequest`（`crates/core/src/application/authorize.rs:35-48`）が受けるのは
`response_type`・`client_id`・`redirect_uri`・`scope`・`state`・`nonce`・`code_challenge`・
`code_challenge_method`・`prompt`・`max_age` まで。未対応:

- `login_hint` — ログイン画面にユーザー名を事前入力できない（再ログイン時の UX 低下）。
- `ui_locales` — RP が表示言語を指定できない（web の言語決定順は URL/ユーザー設定/Cookie/
  `Accept-Language` のみ。CLAUDE.md「国際化」の表に `ui_locales` を足すか、対象外と明記する）。
- `id_token_hint` — `/logout`（RP-initiated logout）でも未使用。`post_logout_redirect_uri` の
  検証を id_token_hint に紐づけられない。
- `acr_values` — AP3（認証ポリシーの `requested_acr` 条件）の前提。
- `response_mode` — `query` 固定。`form_post` が要る RP に対応できない。
- `prompt=select_account` — 複数アカウント切替の入口が無い（`Prompt::parse` は none/login/consent のみ）。

Discovery も `response_modes_supported`・`request_parameter_supported`・`claims_parameter_supported`・
`acr_values_supported`・`ui_locales_supported` を出しておらず、RP のメタデータ検証が厳しい実装
（OIDC 認定テストを含む）で落ちうる。対策: `login_hint`・`ui_locales` を先に入れる（UX 直結・低コスト）。
`response_mode=form_post` と `acr_values` は AP3 と合わせて判断する。
