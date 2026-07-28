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
| 45 | T1 | 入れ子ホスト名（`api.idp.nolumia.com` 等）の DNS・証明書・RP 再設定を実施する（⬜未着手。コード側は完了） | 小 | 中 | 大 | 小 |
| 23 | SEC2 | ログアウト系 URI（`backchannel_logout_uri` ほか）が無検証 → 認証済み blind SSRF（⬜未着手） | 中 | 中 | 大 | 中 |
| 15 | SEC11 | `INTERNAL_SERVICE_TOKEN` に長さ・形式検証が無く、http issuer では dev 既定へフォールバックする（⬜未着手） | 小 | 中 | 大 | 小 |
| 14 | SEC4 | single-origin 構成で admin JSON API にブラウザ Cookie が届き、api 側に Origin/CSRF 検証が無い（⬜未着手） | 中 | 中 | 中 | 中 |
| 9 | SEC5 | CSRF double-submit の種（`admin_csrf_id`/`portal_csrf_id`）がオリジン非分離 → `__Host-` 前置（⬜未着手） | 小 | 中 | 中 | 小 |
| 9 | SEC7 | 認証成功時に `auth_session_id` を再生成しない（`sso_session_id` は再生成済みで非対称）（⬜未着手） | 小 | 小 | 中 | 中 |
| 9 | SEC9 | クエリ文字列（`?auth_session=`・`?code_challenge=`）が `TraceLayer` 既定スパン経由でログに出うる（⬜未着手） | 小 | 中 | 中 | 小 |
| 8 | SEC1 | web が `X-Forwarded-For` を無条件信頼（api の `TRUST_FORWARDED_HEADERS` ゲートを迂回）→ レート制限回避・監査ログ汚染（⬜未着手） | 中 | 中 | 大 | 小 |
| 8 | SEC3 | OIDC フローの TOTP 検証にレート制限・ロックアウトが無い（ポータル側にはある）（⬜未着手） | 小 | 中 | 大 | 中 |
| 8 | SEC6 | `auth_sessions.id` だけ DB に平文保存（他の bearer credential は全てハッシュ）（⬜未着手） | 中 | 小 | 大 | 中 |
| 5 | SEC8 | authorization code 再利用検知時に発行済みトークンを失効させない（refresh 側は実装済みで非対称）（⬜未着手） | 中 | 小 | 中 | 中 |
| 5 | SEC12 | 低リスク改善のまとめ（CSP `unsafe-inline`・Swagger 無認証・`require_pkce` 死に設定・同意 POST の Cookie 非束縛・argon2 パラメータ非明示・auth_sessions の GC/照合/`expect()`）（⬜未着手） | 中 | 中 | 小 | 中 |
| 3 | SEC10 | `/token`・`/introspect`・`/revoke` にレート制限が無い（Argon2 増幅型 DoS）（⬜未着手） | 小 | 小 | 中 | 小 |

## 詳細

### T1. 入れ子ホスト名のデプロイ作業（ADR-0018 決定 1 の残作業）

ADR-0018 のコード実装（決定 2〜4: api の Cookie 非依存化・host-only 化・`COOKIE_DOMAIN` 既定
未設定）と `.env.*.example` の入れ子ホスト名への変更は完了した（`docs/CHANGELOG.md` 2026-07-27）。
残るのは stg / prod 環境への適用作業のみ。

| 環境 | web | api | ポート |
|---|---|---|---|
| prod | `idp.nolumia.com` | `api.idp.nolumia.com` | 10000 / 10001 |
| stg | `idpstg.nolumia.com` | `api.idpstg.nolumia.com` | 10010 / 10011 |

手順:

1. DNS に `api.idp.nolumia.com` / `api.idpstg.nolumia.com` を追加し、証明書を用意する。
   **証明書は web・api 両方のホスト名を SAN に含めること**（`*.idp.nolumia.com` のワイルドカードは
   `api.idp.nolumia.com` には一致するが **bare な `idp.nolumia.com` には一致しない**）。
   1 枚にまとめるなら SAN = `idp.nolumia.com` + `api.idp.nolumia.com`（または
   `*.idp.nolumia.com` + `idp.nolumia.com`）。stg も同様。
2. 前段プロキシの振り分け先は現行のまま（`WEB_PORT` / `API_PORT` は変えない）。
3. `.env` の `ISSUER` を上表の api ホストへ変更する（`PUBLIC_WEB_BASE_URL` は不変）。
   旧構成の `Domain=nolumia.com` Cookie がブラウザに残っている間は `COOKIE_DOMAIN=nolumia.com` を
   移行期間だけ残して掃除させ、期間が終わったら未設定へ戻す（ADR-0018 決定 4）。
4. **`ISSUER` 変更に伴い RP 側の再設定が必要**（discovery・ID Token の `iss` が変わる。
   `end_session_endpoint` も web の `/{tenant_id}/logout` へ変わった）。メンテナンス枠で実施する。

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

#### SEC2. ログアウト系 URI が無検証 → 認証済み blind SSRF

`redirect_uris` は `validate_redirect_uri`（スキーム・フラグメント・ワイルドカード検査）を通るのに、
`backchannel_logout_uri` / `frontchannel_logout_uri` / `post_logout_redirect_uris` はそのまま代入される
（`crates/core/src/application/client_management.rs:149-151, 219-227`）。特に `backchannel_logout_uri` は api が
サーバ側から POST する（`crates/api/src/presentation/handlers/logout.rs:152-160`、5 秒タイムアウトのみ）ため、
テナント管理者権限で `http://169.254.169.254/...`・内部サービスへ POST を打たせられる。対策: 3 種とも
`validate_redirect_uri` 相当を通し、backchannel はさらにプライベート IP 拒否／allowlist を検討する。

#### SEC3. OIDC フローの TOTP にレート制限・ロックアウトが無い

`crates/core/src/application/mfa_login.rs:101-177` は失敗時に監査するだけで、レート制限・失敗カウンタ・
ロックが無い。ポータル側 MFA にはレート制限がある（`crates/core/src/application/portal_login.rs:300`）ため非対称。
auth_session 生存 600 秒間、6 桁 TOTP を無制限に総当たり可能。パスワード窃取済み攻撃者の MFA 突破につながる。

#### SEC4. single-origin で admin JSON API に Cookie が届き、api 側に Origin/CSRF 検証が無い

既定の domain-split では `sso_session_id` が host-only で api ホストへ送られず安全。しかし
`PUBLISH_TOPOLOGY=single-origin` では nginx が `/{tenant}/admin/*` を `Accept` ヘッダで振り分け
（`docker/nginx.conf:51-54, 79-81`）、`Accept: application/json` で同一オリジンのブラウザ Cookie 付き
リクエストが api の管理 API に到達する。api の admin extractor は Cookie のみ検証し Origin/Referer/CSRF を
見ない（`crates/api/src/presentation/admin.rs:67-106`）。現状 CSRF が成立しないのは `axum::Json` extractor が
JSON content-type を要求する副次効果に依存するだけで、`Form` 受理や CORS 追加で即座に CSRF になる。
対策: api の admin 経路に Origin 検証を追加する。

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

#### SEC8. code 再利用検知時に発行済みトークンを失効させない

`crates/core/src/application/token.rs:219-235` は再利用を監査記録するだけで、1 回目の交換で発行済みの
アクセス／リフレッシュトークンは生かしたまま。refresh 側は再利用でチェーン失効を実装済み（`token.rs:411-434`）で
非対称。監査 reason も「not found/expired/used」を 1 文字列に丸め、真の再利用を区別できない。

#### SEC9. クエリ文字列がログに出うる（ADR-0018 の受け入れ条件が未達）

api / web とも `TraceLayer::new_for_http()`（`crates/api/src/presentation/router.rs:317`・
`crates/web/src/router.rs:317`）の既定スパンが `uri` をクエリ込みで持つ。現状 INFO 止まりで出力されないが、
`RUST_LOG=debug` で `/{tenant}/login?auth_session=…`・`/authorize?…code_challenge=…` が stdout に落ちる。
対策: `make_span_with` で `uri.path()` のみを記録する。

#### SEC10. `/token`・`/introspect`・`/revoke` にレート制限が無い

client_secret は Argon2 照合（`crates/core/src/application/token.rs:602-605`）で総当たりは非現実的だが、
メモリハード関数の CPU/メモリ増幅型 DoS が成立する。

#### SEC11. `INTERNAL_SERVICE_TOKEN` の検証欠如と http issuer フォールバック

`CSRF_SECRET` / `KEY_ENCRYPTION_KEY` は 32 バイト強制なのに、`INTERNAL_SERVICE_TOKEN` は無検証で
1 文字でも本番起動が通る（`crates/core/src/config.rs:179-183`）。加えて dev 既定シークレットの起動時
fail-fast（`config.rs:566-598`）は `ISSUER` が https のときだけ効くため、TLS を前段で終端し ISSUER を http に
した配置では既知トークンで `/internal/*` が開き、防御が nginx の `/internal/` 404 一枚になる。
対策: トークンの最小長・`CHANGE-ME` 検出を追加し、http issuer 運用の危険性を明示する。

#### SEC12. 低リスク改善のまとめ

- CSP に `script-src 'unsafe-inline'`（`crates/web/src/security_headers.rs`、コード内で自認済み）→ nonce 化。
- Swagger UI `/api/docs` が無認証・CSP 無しで常時公開（`crates/api/src/presentation/router.rs:315`）→ 公開可否確認。
- `Client::require_pkce` が死んだ設定（`crates/core/src/domain/client.rs:25`）。管理コンソールに「PKCE 必須」
  チェックボックスが出る（`crates/web/templates/console/client_form.html:45`）のに `/authorize`・`/token` から
  参照されず実際は常に S256 必須 → 削除か実装。
- 同意 POST がフォーム値の `auth_session_id` だけで動き Cookie と突き合わせない（`crates/web/src/handlers/consent.rs:89`）。
- argon2 が `Argon2::default()` でパラメータ非明示（依存更新で暗黙変化）→ 定数化。
- `auth_sessions` の期限切れ GC ジョブが無い / ci 照合（`utf8mb4_unicode_ci`）の秘密値 PK /
  `crates/core/src/application/authorize.rs:575,589` の `expect()` パニック経路 / CSRF 比較が非定数時間。
