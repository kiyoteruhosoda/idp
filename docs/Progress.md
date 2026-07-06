# Progress

進行中・未着手タスクのみを管理する（完了したら本ファイルから削除し、必要なら `CHANGELOG.md` / `history/` へ）。

OIDC IdP MVP（**Rust + MariaDB**）の実装計画。設計仕様は `docs/OIDC_INPUT.md`、
スタック採用理由は `docs/adr/0005-rust-mariadb-stack.md`。

## MVP 充足状況

設計仕様 `docs/OIDC_INPUT.md` の **MVP 完了条件 §10（1〜13）はすべて充足**し、`tests/oidc_flow.rs`
の E2E テストで検証済み（ロックアウト §4.3・IP レート制限・scope 部分集合検証・redirect_uri 完全一致・
code 再利用検知・SSO 復元時の auth_time 継承・監査ログ二重出力を含む）。API §4・トークン仕様 §5・
監査ログ §7 も実装済み。§8 の MVP 対象外項目は意図どおり未実装。

> 既知の軽微な差分（本番運用向け・下表 S1 で対応予定）: HSTS / セキュリティヘッダはアプリ層では未実装。
> `prompt` / `max_age` は §4.2 のとおり MVP では無視（下表 F3 と併せて対応）。

## MVP 以降のバックログ（未着手）

管理機能（RP 登録・管理画面）と鍵管理・プロキシ対応を優先し、その後 OIDC 拡張（§9）を進める。
着手時に本表の状態を更新し、完了したら削除して `CHANGELOG.md` へ移す。

| 優先 | # | 概要 | 状態 | 影響度 | 工数 |
|---|---|---|---|---|---|
| 1 | A2 | 管理コンソール基盤: 管理者認証・画面レイアウト・権限（scope ベース）・操作監査 | 🚧進行中 | 大 | 中 |
| 2 | A3 | 状況確認画面: ログイン/監査ログ一覧（エラー絞り込み）、クライアント状況一覧（最終利用時刻等） | 🚧進行中 | 中 | 中 |
| 3 | K1 | 署名鍵管理: 複数鍵での署名（世代重複）・JWKS 公開・管理画面（一覧/生成/退役）・EC(ES256) 対応 | ⬜未着手 | 大 | 中 |
| 4 | K2 | 署名鍵の自動ローテーション: `not_after` ベースのスケジュール実行・ACTIVE/RETIRED 自動管理 | ⬜未着手 | 中 | 中 |
| 5 | S1 | SSL アクセラレーター対応: `X-Forwarded-Proto`/`-For` 信頼設定・HSTS・セキュリティヘッダ（アプリは HTTP 直受け） | ⬜未着手 | 中 | 小〜中 |
| 6 | F2 | Refresh Token（rotation・reuse detection、`offline_access` scope） | ⬜未着手 | 大 | 大 |
| 7 | F3 | Consent（同意画面・同意済み scope 記録・取り消し、`prompt`/`max_age` 正式対応） | ⬜未着手 | 中 | 中 |
| 8 | F4 | Logout（RP-initiated / front-channel / back-channel、`sso_session.terminated` 有効化） | ⬜未着手 | 中 | 中 |
| 9 | F5 | Token 管理（revocation / introspection endpoint、ユーザー単位の全セッション無効化） | ⬜未着手 | 中 | 中 |

> **A1（クライアント登録 API・画面）は完了**（2026-07-06、`CHANGELOG.md`）。JSON 管理 API に加え、
> `/admin/console/clients*` のサーバレンダリング画面（一覧・登録・詳細・編集・secret 再発行・無効化導線）を実装。
> 動的クライアント登録（RFC 7591）・`private_key_jwt` は対象外（将来）。

## 詳細

### 管理機能（A2〜A3）

- **A2 — 管理コンソール基盤**（権限モデルは **`docs/adr/0006-admin-permission-model.md`** で確定）:
  - アクセスは **ロールではなく権限コード**（例 `idp.admin`）で制御（CLAUDE.md「権限管理」）。
    OIDC scope（openid/profile/email）とは別軸の「利用者権限」を新設する（ADR-0006）。
  - **権限モデル基盤は実装済み**（2026-07-06、`CHANGELOG.md`）: `permissions` / `user_permissions`
    マイグレーション（0003）+ seed（0004。`admin@example.com` へ `idp.admin` 付与）+ 値オブジェクト
    `PermissionCode` + `UserPermissionRepository`（DIP 境界。参照/付与/剥奪）+ Application の
    `AdminAccessService`（SSO→利用者→権限突合）+ `RequirePerms<IdpAdmin>` extractor +
    内部疎通用 `GET /admin/whoami`。監査種別 `user_permission.granted`/`.revoked` を §7 に追記済み。
  - **権限付与/剥奪 API は実装済み**（2026-07-06、`CHANGELOG.md`）: `/admin/users/{user_id}/permissions`
    の付与（`POST`）・剥奪（`DELETE`）・参照（`GET`）（`RequirePerms<IdpAdmin>`）。SRP に従い参照
    （保護判定）の `AdminAccessService` とは別に管理（変更）用の `PermissionManagementService` を新設し、
    付与/剥奪を `AuditEventType::UserPermission*`（`user_permission.granted`/`.revoked`）として
    `audit_log` へ記録する。付与は冪等・未知コードは 400・対象利用者不存在は 404。
  - **管理コンソール基盤 UI は実装済み**（2026-07-06、`CHANGELOG.md`）: `/admin/console` 配下に
    サーバレンダリングの管理ログイン（`GET/POST /admin/console/login`）・ホーム（`GET /admin/console`）・
    ログアウト（`POST /admin/console/logout`）を追加（既存ログイン画面と同じ axum + fluent i18n）。
    JSON 管理 API（`/admin/<resource>`）とは経路を分離。ログインはクライアント不要で SSO セッションを
    直接発行し（ADR-0006 §6。初回デプロイの鶏卵問題を回避）、資格情報検証・ロックアウト・IP レート制限は
    通常ログインと共有。CSRF は同期トークン（`admin_csrf_id` Cookie）。画面用の認可 extractor
    `AdminHtmlSession`（未認証→ログイン画面へ 302／権限不足→403 HTML）と共通レイアウト
    `render_layout`（A1 の画面が利用中。A3 の画面もこの上に差し込む）を用意。
  - **残作業**: 上記付与/剥奪 API を叩く**権限付与/剥奪 UI**（A2 の共通レイアウト上に実装）。

- **A3 — 状況確認画面**:
  - **ログイン/監査ログ一覧 API は実装済み**（2026-07-06、`CHANGELOG.md`）: `GET /admin/audit-logs`
    （`RequirePerms<IdpAdmin>`）。`event_type` / `result`（`failure` 等の**エラー絞り込み**が主眼）/
    期間（`from`/`to`、RFC3339）/ `client_id` / `correlation_id` で AND 絞り込みし、新しい順に返す
    （`limit`≤200・`offset`）。`correlation_id` でリクエスト〜監査イベントを追跡。読み取りは
    `AuditLogQuery`（DIP 境界。書き込みの `AuditLogSink` と分離）。
  - **残作業（クライアント状況一覧）**: 各 client の状態（ACTIVE/DISABLED）・scope・**最終利用時刻**の一覧。
    最終利用時刻は `audit_log`（`token.issued` 等の最新 `occurred_at`）から導出、または
    `clients.last_used_at` を発行時に更新（マイグレーション）。負荷を見て方式決定。
  - **残作業（画面）**: 上記 API を表示する状況確認**画面**（A2 の管理コンソール基盤の上に実装）。

### 鍵管理（K1・K2）

- **K1 — 署名鍵管理**:
  - **複数鍵での署名**: 現行の ACTIVE 単一運用から、有効期間が重複する複数鍵（現行＋次期）を許容する
    運用へ拡張。新規署名は「現行 ACTIVE」、検証は JWKS 掲載の全有効鍵で可能にする（無停止ローテの前提）。
  - **JWK 提供 API**: `GET /.well-known/jwks.json` は実装済み（ACTIVE+RETIRED を公開）。K1 では
    複数世代の掲載・`not_after` 経過鍵の非公開化を整備する。
  - **管理画面**: 鍵一覧（`kid`/status/有効期間）・手動生成・退役（ACTIVE→RETIRED）・削除。
  - **EC(ES256) 対応**: `signing_keys.algorithm` の許可値・CHECK 制約に `ES256` を追加し、
    jsonwebtoken の EC 署名/検証・JWKS（`kty=EC`,`crv`,`x`,`y`）を実装（設計仕様 §5 は現状 RS256）。

- **K2 — 自動ローテーション**: `signing_keys.not_after` に基づき、期限接近で次期鍵を自動生成して
  重複期間を設け、旧鍵を「最大トークン有効期限＋クロックスキュー」経過後に RETIRED→非公開化（§3.6）。
  スケジューラ（tokio タスク or 外部 cron ジョブ）方式は着手時に決定。MVP は起動時ブートストラップのみ。

### インフラ / プロキシ対応（S1）

- **S1 — SSL アクセラレーター/リバースプロキシ対応**（アプリは TLS 終端の**後ろで HTTP を直受け**）:
  - **信頼プロキシ設定**（例 `TRUSTED_PROXIES` / `TRUST_FORWARDED_HEADERS`）を追加し、有効時のみ
    `X-Forwarded-Proto`（https 判定）・`X-Forwarded-For`（client IP）を解釈する。未設定時は
    ヘッダを無視して直結スキーム/接続元 IP を用いる（ヘッダ偽装対策）。
  - **HSTS**: 外部が HTTPS（`X-Forwarded-Proto=https` もしくは issuer が https）のときに
    `Strict-Transport-Security` を付与（`HSTS_MAX_AGE` 設定可）。`tower-http` のヘッダ層で実装。
  - **セキュリティヘッダ**: `X-Content-Type-Options: nosniff`・`Referrer-Policy` 等をログイン/管理画面へ付与。
  - **client IP の一貫化**: 監査ログ（§7 `ip_address`）と IP レート制限（§4.3）が
    転送ヘッダ経由の実 IP を使うよう結線する（現状は接続元 IP）。
  - Cookie の `Secure` は issuer スキーム/`COOKIE_SECURE` で対応済み（HTTP 直受けでも https issuer なら有効）。

### OIDC 拡張（F2〜F5、設計仕様 §9）

- **F2（§9.1）**: `RefreshTokens` テーブル（ハッシュ保存）。rotation / reuse detection は
  authorization_code の原子的 one-time 消費（`code_issuance`）を参考に実装。`offline_access` 要求時のみ発行。
  Discovery の `grant_types_supported` に `refresh_token` を追加。
- **F3（§9.2）**: client ごとの同意済み scope を永続化し、`/authorize` で未同意 scope のみ同意画面へ。
  併せて `prompt=login`（再認証）・`max_age`（auth_time 超過時の再認証）を正式対応（§4.2 MVP 無視分）。
- **F4**: `sso_session.terminated`（§7 で予約済み）を有効化。SSO セッション・関連 code の失効を実装。
  back-channel logout は client 側 logout endpoint への通知が必要。
- **F5（§9.4）**: RFC 7009 revocation・RFC 7662 introspection。introspection は confidential client 認証必須。

> 依存関係:
> - A2（管理コンソール基盤＋権限モデル）は A1・A3・K1 の画面が前提とする。権限モデルは
>   `docs/adr/0006-admin-permission-model.md`（Accepted）で確定。**権限モデルと管理コンソール基盤 UI
>   （ログイン／ホーム／ログアウト＋画面用 extractor `AdminHtmlSession`＋共通レイアウト）は実装済み**。
>   A1・A3・K1 の管理画面は `AdminHtmlSession` で保護し、`render_layout` の上に実装する。
> - F2 は A1（client の grant_types 管理）と親和。F4・F5 はセッション/トークン失効基盤を共有。
> - S1 は他タスクと独立に着手可能（早期着手も可）。
> 各タスクは着手時に `docs/history/` への記録要否（規模が大きく背景まで追う場合のみ）を判断する。
