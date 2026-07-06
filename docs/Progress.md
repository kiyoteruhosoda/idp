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
| 1 | K1 | 署名鍵管理: 複数鍵での署名（世代重複）・JWKS 公開・管理画面（一覧/生成/退役）・EC(ES256) 対応 | ⬜未着手 | 大 | 中 |
| 2 | K2 | 署名鍵の自動ローテーション: `not_after` ベースのスケジュール実行・ACTIVE/RETIRED 自動管理 | ⬜未着手 | 中 | 中 |
| 3 | S1 | SSL アクセラレーター対応: `X-Forwarded-Proto`/`-For` 信頼設定・HSTS・セキュリティヘッダ（アプリは HTTP 直受け） | ⬜未着手 | 中 | 小〜中 |
| 4 | F2 | Refresh Token（rotation・reuse detection、`offline_access` scope） | ⬜未着手 | 大 | 大 |
| 5 | F3 | Consent（同意画面・同意済み scope 記録・取り消し、`prompt`/`max_age` 正式対応） | ⬜未着手 | 中 | 中 |
| 6 | F4 | Logout（RP-initiated / front-channel / back-channel、`sso_session.terminated` 有効化） | ⬜未着手 | 中 | 中 |
| 7 | F5 | Token 管理（revocation / introspection endpoint、ユーザー単位の全セッション無効化） | ⬜未着手 | 中 | 中 |

> **A1（クライアント登録 API・画面）は完了**（2026-07-06、`CHANGELOG.md`）。JSON 管理 API に加え、
> `/admin/console/clients*` のサーバレンダリング画面（一覧・登録・詳細・編集・secret 再発行・無効化導線）を実装。
> 動的クライアント登録（RFC 7591）・`private_key_jwt` は対象外（将来）。

> **A2（管理コンソール基盤）は完了**（2026-07-06、`CHANGELOG.md`）。権限モデル基盤・付与/剥奪 API・
> 管理コンソール基盤 UI（ログイン／ホーム／ログアウト＋画面用 extractor `AdminHtmlSession`＋共通レイアウト
> `render_layout`）に加え、**権限付与/剥奪 UI**（`/admin/console/users*` の利用者検索・保有権限一覧・
> 付与フォーム・剥奪ボタン）を実装。K1 の管理画面は `AdminHtmlSession` で保護し、`render_layout`
> の上に実装する。

> **A3（状況確認画面）は完了**（2026-07-06、`CHANGELOG.md`）。監査/ログインログ一覧 API に加え、
> 状況確認画面（`/admin/console/audit-logs` の絞り込み＋一覧・前後ページ、`/admin/console/status` の
> クライアント状態・scope・**最終利用時刻**一覧）を実装。最終利用時刻は `audit_log`（成功した
> `token.issued`／`authorization_code.issued` の最新 `occurred_at`）から導出する（マイグレーション不要）。

## 詳細

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
> - A1・A2・A3（管理コンソール基盤＋権限モデル＋各管理/状況画面）は**完了済み**（`CHANGELOG.md`）。
>   権限モデルは `docs/adr/0006-admin-permission-model.md`（Accepted）で確定。残る K1 の管理画面は
>   画面用 extractor `AdminHtmlSession` で保護し、共通レイアウト `render_layout` の上に実装する。
> - F2 は A1（client の grant_types 管理）と親和。F4・F5 はセッション/トークン失効基盤を共有。
> - S1 は他タスクと独立に着手可能（早期着手も可）。
> 各タスクは着手時に `docs/history/` への記録要否（規模が大きく背景まで追う場合のみ）を判断する。
