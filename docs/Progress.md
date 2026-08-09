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
| 8 | SEC6 | `auth_sessions.id` だけ DB に平文保存（他の bearer credential は全てハッシュ）（⬜未着手） | 中 | 小 | 大 | 中 |
| 8 | AP3 | 認証ポリシーの条件種別を拡張する（ネットワークゾーン・国・端末・時間帯・requested_acr 等。仕様 §8）と `require_specific_method` 効果（⬜未着手） | 大 | 中 | 中 | 大 |
| 8 | AP8 | ログイン識別子の複数化（仕様 §4。`user_login_identifiers`: 電話番号・社員番号等の種別、表示値と正規化値の分離、識別子単位の無効化）（⬜未着手） | 大 | 大 | 小 | 大 |
| 5 | SEC13 | ログイン失敗カウンタの更新が read-modify-write で原子的でない（並行試行でロック閾値に届かないことがある。3 つのログイン経路に共通）（⬜未着手） | 中 | 中 | 中 | 小 |
| 5 | SEC12 | 低リスク改善のまとめ（CSP `unsafe-inline`・Swagger 無認証・`require_pkce` 死に設定・同意 POST の Cookie 非束縛・argon2 パラメータ非明示・auth_sessions の GC/照合/`expect()`）（⬜未着手） | 中 | 中 | 小 | 中 |
| 5 | AP1 | 認証ポリシーの管理画面（web コンソール UI。現状は API のみ）（⬜未着手） | 中 | 中 | 小 | 中 |
| 5 | AP7 | パスワードポリシーの拡張（仕様 §11.2。漏えい済みパスワード検出・過去パスワード再利用禁止・有効期限。現状は最小文字数のみ）（⬜未着手） | 中 | 小 | 中 | 中 |
| 5 | AP11 | AP9 の contract フェーズ（TOTP/WebAuthn の秘密を `user_authenticators` へ集約し、`user_totp_secrets` / `user_webauthn_credentials` を撤去）（⬜未着手） | 中 | 中 | 小 | 中 |
| 5 | AP12 | SAML 外部 IdP（AP10 は OIDC のみ実装。`external_identity_providers` の protocol 拡張が要る）（⬜未着手） | 大 | 中 | 小 | 大 |
| 5 | G1 | CORS 未実装（api・nginx とも）。public client（SPA）がブラウザから `/token`・`/userinfo`・`/.well-known/*` を呼べない（⬜未着手） | 中 | 中 | 小 | 中 |
| 5 | G2 | 期限切れレコードの GC が `log` テーブルにしか無い（`auth_sessions`・`authorization_codes`・`refresh_tokens`・`sso_sessions`・`revoked_access_tokens`・`passkey_challenges`・各種トークン表が無限に増える）（⬜未着手） | 中 | 中 | 中 | 小 |
| 5 | G9 | api のシングルインスタンス前提が明文化されていない（レートリミッタ・キャッシュがプロセス内メモリ、鍵ローテーションが排他制御無し）（⬜未着手） | 小 | 大 | 小 | 小 |
| 5 | G11 | web crate に統合テストが無い（`crates/web/tests/` 不在。ルータ経由の検証は `scripts/e2e.sh` 頼み）（⬜未着手） | 中 | 中 | 小 | 中 |
| 5 | G12 | `/authorize` の任意パラメータ未対応（`login_hint`・`ui_locales`・`id_token_hint`・`acr_values`・`response_mode`・`prompt=select_account`）と Discovery の広告不足（⬜未着手） | 中 | 中 | 小 | 中 |
| 3 | SEC10 | `/token`・`/introspect`・`/revoke` にレート制限が無い（Argon2 増幅型 DoS）（⬜未着手） | 小 | 小 | 中 | 小 |
| 3 | AP6 | アカウントロックの管理者解除（仕様 §17.1・§24.6。`locked_until` を即時クリアする管理操作。現状は期限経過待ちのみ）と段階的ロック（⬜未着手） | 小 | 小 | 中 | 小 |
| 3 | G3 | `client_secret_post` 未対応（`client_secret_basic` / `none` のみ。RP ライブラリ既定との相互運用性）（⬜未着手） | 小 | 中 | 小 | 小 |
| 3 | G8 | `audit_log` に絞り込み用の索引（`client_id`・`user_id`・`result`・複合 `(tenant_id, occurred_at)`）と保持期間の仕組みが無い（`log` にはある）（⬜未着手） | 小 | 中 | 小 | 小 |
| 2 | AP13 | SMS OTP の送信経路が無い（認証方式・認証器種別としては定義済みだが、送信アダプタと登録画面が未実装）（⬜未着手） | 中 | 小 | 小 | 中 |
| 2 | G6 | メトリクスが無い（`/metrics` 非公開。ログイン成功率・トークン発行レート・レイテンシ・DB プール枯渇を監視できない）（⬜未着手） | 中 | 中 | 小 | 小 |
| 1 | G7 | 一覧 API のページング欠落（`list_clients`・`list_tenants`・権限一覧は全件返す。members・audit にはある）（⬜未着手） | 小 | 小 | 小 | 小 |

## 詳細

### ユーザー認証・認証ポリシー仕様書の残実装（AP1〜AP10）

ADR-0020 で `authentication_policies`（deny / require_mfa / allow、client_ids・user_ids 条件）・
管理 API・OIDC ログインフロー（パスワード・パスキー・強制パスワード変更）への適用・アカウント
ロックの設定化（`LOGIN_MAX_FAILED_ATTEMPTS` / `LOGIN_LOCK_DURATION_SECS`）を導入済み。
仕様書に対する残実装をタスク化する:

- **AP1** 管理画面（web コンソール UI）。現状は API のみ（手順は `docs/OPERATIONS.md`）。
  AP10 で追加した外部 IdP 設定（`/admin/external-idps`）も同じく API のみのため、本タスクの対象に含む。
- **AP3** 条件種別の拡張（仕様 §8: ネットワークゾーン・国・端末信頼・時間帯・requested_acr 等）と
  `require_specific_method` 効果。WebAuthn 必須・UV 必須等の要求（§12.2）を含む。
  AP4 で認証方式・強度を記録済みなので、`require_specific_method` の判定材料は揃っている。
- **AP6** アカウントロックの管理者即時解除（`locked_until` クリア）と段階的ロック（§17.1）。
- **AP7** パスワードポリシーの拡張（§11.2）。
- **AP8** ログイン識別子の複数化（§4 `user_login_identifiers`）。`users.email` /
  `preferred_username` 直付けからの移行（expand/contract）を伴う。

AP2・AP4・AP5・AP9・AP10 は実装済み（`CHANGELOG.md` 参照）。AP9 の残り（contract フェーズ）と
AP10 の残り（SAML 外部 IdP）は下記「積み残し」に切り出した。

### 積み残し（AP9・AP10 実装からの繰り越し。AP11〜AP13）

#### AP11. AP9 の contract フェーズ（秘密の集約）

AP9 は expand フェーズだけを入れた。`user_authenticators` は**認証器の種別・状態・ラベル・
最終使用時刻**を一元管理するが、**秘密そのものは既存表に残したまま**である（TOTP の共有鍵は
`user_totp_secrets`、パスキーの公開鍵・署名カウンタは `user_webauthn_credentials`）。
`user_authenticators.credential_ref` が元の行を指し、検証経路は従来どおり元の表を読む。

分けた理由は移行リスク。秘密の移送は暗号化のまま運び直す（あるいは復号→再暗号化する）操作で、
途中で失敗すると**利用者が MFA を通れなくなり自力で復旧できない**。状態管理だけを先に移して
運用で慣らし、参照経路を切り替えてから秘密を動かす。

contract フェーズでやること:

1. 検証経路（TOTP 照合・WebAuthn assertion）の読み出しを `user_authenticators` 側へ切り替える。
2. 秘密を `user_authenticators.secret_encrypted` へ移すマイグレーション（`credential_ref` で対応付け）。
3. `user_totp_secrets` / `user_webauthn_credentials` の削除と、`credential_ref` 列の撤去。

各段は独立したマイグレーションにし、1 と 2 の間に**両方を読める期間**を挟む（ローリングデプロイ中に
古いプロセスが残るため）。

#### AP12. SAML 外部 IdP

AP10 で入れたのは **OIDC の外部 IdP のみ**。`external_identity_providers` は
`issuer` / `authorization_endpoint` / `token_endpoint` / `jwks_uri` / `client_id` という
OIDC 前提の列構成で、SAML の IdP メタデータ（`SingleSignOnService` URL・署名証明書・
`NameID` 形式）を表現できない。対応するなら `protocol` 列（`oidc` / `saml`）を足し、
プロトコル固有の設定は JSON 列へ寄せるか別表に分ける設計判断が要る（ADR 対象）。

なお本 IdP を **SAML の IdP として**振る舞わせる側（`/{tenant}/saml/metadata`・`saml_sso_requests`）は
既に別途存在する。ここで言う SAML は**外部 IdP を利用者の認証元として使う（SP 側）**方向の話で、
向きが逆である。

#### AP13. SMS OTP の送信経路

`AuthenticationMethod::SmsOtp` と `AuthenticatorType::SmsOtp` は AP4 / AP9 で語彙としては定義済み
（認証強度の判定・認証器一覧の表示は SMS を受け入れる）だが、**送信アダプタ（SMS ゲートウェイの
ポートと実装）と電話番号の登録・確認画面が無い**ため、実際には登録も認証もできない。
メール OTP（`lettre`）と同じ形のポート＋インフラ実装を足すのが最小の作業。

送信事業者の選定と、電話番号を PII としてどう保持するか（ログ非出力は既定として、DB では
暗号化するか正規化値のみ持つか）は未決。

### セキュリティレビュー（SEC6・SEC10・SEC12・SEC13）

api / web の別サブドメイン構成を対象にした調査で検出した課題。**「api には対策があるのに web 側に無い」
非対称**が主軸。良好な点（回帰させない）: redirect_uri/post_logout の完全一致、code の 256bit・SHA-256・
60 秒・原子的ワンタイム、PKCE S256 の無条件強制、client_secret の Argon2 保存、sso_session_id の
256bit・ハッシュ保存・ログイン毎の再生成、ADR-0018 の Cookie 非依存ハンドオフ（単回・60 秒・テナント固定束縛）、
web の `X-Forwarded-For` ゲート（SEC1）・CSRF 種の `__Host-` 束縛（SEC5）・`auth_session_id` の
認証時再生成（SEC7）・再利用検知でのトークンファミリ失効（SEC8）・アクセスログのクエリ非記録（SEC9）。

#### SEC6. `auth_sessions.id` だけ DB に平文保存

Cookie 値がそのまま PK（`migrations/0001_baseline.up.sql` の `auth_sessions`、参照は `WHERE id = ?`
`crates/core/src/infrastructure/repositories/auth_session.rs`）。同じ表の `handle_hash` すら
SHA-256、他の bearer credential も全てハッシュ保存で非対称。DB 読取を得た者は TTL(600 秒)の間、同意待ち／
MFA 待ちの認可セッションを乗っ取れる。対策: `handle_hash` と揃えて SHA-256 保存へ（マイグレーション必要）。

SEC7 で認証成功時の id 再生成（`set_authenticated_user` / `set_password_verified` が同じ UPDATE で
id を差し替える）は入っているため、本タスクは「Cookie 値そのものを PK に置かない」ことに絞られる。
再生成の口が 1 箇所に閉じたぶん、ハッシュ化の際に触る場所も減っている。

#### SEC10. `/token`・`/introspect`・`/revoke` にレート制限が無い

client_secret は Argon2 照合（`crates/core/src/application/token.rs:602-605`）で総当たりは非現実的だが、
メモリハード関数の CPU/メモリ増幅型 DoS が成立する。

#### SEC13. 失敗カウンタの更新が原子的でない

`LoginService::handle_password_failure`・`MfaLoginService::handle_totp_failure`・
`PortalLoginService` の失敗処理はいずれも「`user.failed_login_count` を読む → +1 して
`update_login_state` で上書き」で、read-modify-write が原子的でない。並行して届いた N 件の試行が
同じ値を読むと、N 回失敗しても行は 1 しか進まず、ロック閾値に届かないことがある。IP 単位の
レート制限（既定 30 回/5 分）が総試行数を抑えるため実害は限定的だが、ロックは多層防御の
一枚なので取りこぼしたくない。

対策: `UPDATE users SET failed_login_count = failed_login_count + 1, locked_until = CASE ... END`
のように 1 文で加算とロック判定を行うリポジトリメソッドを追加し、3 経路をそれに寄せる。
`UserRepository` にメソッドが増えるため、各ユニットテストのフェイク実装（10 箇所前後）にも
追随が要る。

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
