# Progress

進行中・未着手タスクのみを管理する（完了したら本ファイルから削除し、必要なら `CHANGELOG.md` / `history/` へ）。

OIDC IdP MVP（**Rust + MariaDB**）の実装計画。設計仕様は `docs/OIDC_INPUT.md`、
スタック採用理由は `docs/adr/0005-rust-mariadb-stack.md`。MVP 完了条件（§10）は充足済み（詳細は `CHANGELOG.md`）。

## バックログ

| 優先 | # | 概要 | 状態 | 影響度 | 工数 |
|---|---|---|---|---|---|
| 1 | K1 | 署名鍵管理: 複数鍵での署名（世代重複）・JWKS 公開・管理画面（一覧/生成/退役）・EC(ES256) 対応 | ⬜未着手 | 大 | 中 |
| 2 | K2 | 署名鍵の自動ローテーション: `not_after` ベースのスケジュール実行・ACTIVE/RETIRED 自動管理 | ⬜未着手 | 中 | 中 |
| 3 | S1 | SSL アクセラレーター対応: `X-Forwarded-Proto`/`-For` 信頼設定・HSTS・セキュリティヘッダ（アプリは HTTP 直受け） | ⬜未着手 | 中 | 小〜中 |
| 4 | C1 | コンテナ分離（API/Web を別サービスに分割・理想形）: workspace 分割・Web→API HTTP 化・内部認証 API・Compose 分離 | 🚧進行中（残 P3-4・P4・P5） | 大 | 大 |
| 5 | F2 | Refresh Token（rotation・reuse detection、`offline_access` scope） | ⬜未着手 | 大 | 大 |
| 6 | F3 | Consent（同意画面・同意済み scope 記録・取り消し、`prompt`/`max_age` 正式対応） | ⬜未着手 | 中 | 中 |
| 7 | F4 | Logout（RP-initiated / front-channel / back-channel、`sso_session.terminated` 有効化） | ⬜未着手 | 中 | 中 |
| 8 | F5 | Token 管理（revocation / introspection endpoint、ユーザー単位の全セッション無効化） | ⬜未着手 | 中 | 中 |

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

### インフラ / コンテナ分離（C1）

設計は `docs/adr/0007-api-web-service-split.md`（Accepted）で確定。P0（ADR）・P1（workspace 化）・
P2（内部認証 API）・P3-1（`contracts`＋`web` crate 土台）・P3-2（ログイン画面移設）・
P3-3（管理コンソール全画面 `/admin/console/*` を web へ移設。login/home/clients/users/status/audit-logs。
不足 JSON エンドポイント〔whoami/内部ログアウト/利用者検索・取得/付与可能権限/クライアント状況〕を api に追加）
は完了（`CHANGELOG.md`）。残りの作業:

- **P3-4 api の HTML 撤去**（進行中）: api から presentation の HTML（login・admin console）・i18n・html を
  削除し、api を JSON/protocol のみにする。`RequirePerms<IdpAdmin>` は残す（画面誘導は web）。撤去で成立
  しなくなる api 統合テスト（`/login`・`/admin/console/*` 依存）は P5 で api 単体向けに組み替える。
- **P4 コンテナ/Compose**: `api`・`web` を別イメージ・別サービスに（Dockerfile を crate 別ビルドへ）。
  リバースプロキシのパスルーティング（`/login`・`/admin/console/*`→web、それ以外→api、`/internal/*` は遮断）と
  ネットワーク公開範囲を確定し `OPERATIONS.md` に明記。`migrate` ジョブは現状維持。
- **P5 テスト/運用**: 現在の全部入り統合テスト（`tests/*` は api の `router::build` を利用）を、api 単体の
  統合テストと `web`→`api` の E2E 疎通へ再編する（P3-4 で HTML を api から外すと全部入り E2E が成立しないため）。

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
> - K1 の管理画面は管理コンソール（C1 で web へ移設）の上に実装する。権限モデルは
>   `docs/adr/0006-admin-permission-model.md`（Accepted）で確定済み。
> - F2 は client の grant_types 管理と親和。F4・F5 はセッション/トークン失効基盤を共有。
> - S1 は他タスクと独立に着手可能。C1 のプロキシ（P4）とヘッダ層を共有できる。
> - 各タスクは着手時に `docs/history/` への記録要否（規模が大きく背景まで追う場合のみ）を判断する。
