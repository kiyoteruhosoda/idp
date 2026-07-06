# ADR-0007: API と Web を別サービスへ分割する（コンテナ分離）

- Status: Accepted
- Date: 2026-07-06
- 関連: `CLAUDE.md`（ディレクトリ構成・設計方針）、`docs/OIDC_INPUT.md` §4.2（authorize/login フロー）、
  `docs/Progress.md`（C1）、`docs/adr/0005-rust-mariadb-stack.md`、`docs/adr/0006-admin-permission-model.md`、
  `docs/Progress.md` S1（リバースプロキシ対応）

本 ADR は Progress C1 の **P0（設計）** に相当する。ここで責務境界とサービス間の相互作用を確定し、
実装（P1〜P5）はこの決定に従う。**本 ADR ではコード移設を行わない**（設計のみ）。

## Context

現状は単一ライブラリクレート `idp` ＋単一バイナリ ＋単一 `web` コンテナが全経路を提供している。

| 分類 | 経路（現状） | 種別 |
|---|---|---|
| OIDC protocol | `/authorize`・`/token`・`/userinfo`・`/.well-known/*` | JSON/リダイレクト |
| ログイン画面 | `/login`（GET/POST） | サーバレンダリング HTML |
| JSON 管理 API | `/admin/clients*`・`/admin/users/*/permissions`・`/admin/audit-logs`・`/admin/whoami` | JSON |
| 管理コンソール | `/admin/console/*`（login/home/clients/users/status/audit-logs） | サーバレンダリング HTML |
| 運用 | `/healthz`・`/readyz`・`/api/docs`・`/api/openapi.json` | - |

これらが 1 プロセスに同居しているため、次が達成できない。

- **独立スケール**: 対 RP のトークン発行（API）と、人間が使う管理/ログイン画面（Web）は負荷特性が異なる。
- **独立デプロイ / 変更の影響範囲（blast radius）の分離**: 画面変更で protocol を巻き込みたくない。
- **ネットワーク公開範囲の分離**: 管理コンソールは内部/制限公開にし、protocol だけ外部公開したい。

Progress C1 のスコープ分割相談の結果、**理想形（真のサービス分割）** を採ることを決定した
（工数が大きくとも将来の分離度を優先）。本 ADR はその設計を固定する。

## Decision

### 1. 責務境界（どの経路をどちらに置くか）

| サービス | 担当経路 | DB | 役割 |
|---|---|---|---|
| **api** | OIDC protocol（`/authorize`・`/token`・`/userinfo`・`/.well-known/*`）、JSON 管理 API（`/admin/*`）、**内部 API（`/internal/*`）**、`/healthz`・`/readyz`・OpenAPI | **直結** | 認可サーバ本体・唯一の DB 所有者・署名鍵ブートストラップ |
| **web** | サーバレンダリング HTML（ログイン画面 `/login`、管理コンソール `/admin/console/*`）、`/healthz` | **持たない** | 画面描画（HTML＋i18n＋CSRF）と、API への HTTP クライアント |

- **Web=全 HTML 画面**（ログイン画面と管理コンソール）、**API=JSON/protocol のみ**。
- **DB へ直結するのは api のみ**。web は sqlx／infrastructure に依存しない。データ操作はすべて
  api の HTTP エンドポイント越しに行う。
- **外部から見た OIDC の契約（`docs/OIDC_INPUT.md` §4.2）は不変**。RP は従来どおり `/authorize` に来て、
  ログイン画面へ誘導され、資格情報を送信し、code 付きで redirect される。分割は内部実装の再編であり、
  RP からは観測されない。

### 2. デプロイ位置づけ（単一オリジン・パスルーティングを既定とする）

ブラウザは 1 回の認可フロー中に api（`/authorize`）と web（`/login`）の両方へアクセスし、**同じ SSO
Cookie** を送る必要がある。これを単純化するため、既定は**リバースプロキシによる単一オリジン・パスルーティング**とする。

- 外部は 1 オリジン（例 `https://idp.example.com`）。プロキシが**パスで振り分け**る:
  - `/login`・`/admin/console/*` → **web**
  - それ以外（`/authorize`・`/token`・`/userinfo`・`/.well-known/*`・`/admin/*`・`/healthz` 等）→ **api**
- 同一オリジンのため Cookie ドメイン・CSRF・CORS が単純（Cookie は 1 ドメインで両サービスに届く）。
- これは Progress **S1（リバースプロキシ対応）** と親和する（`X-Forwarded-*` 信頼・HSTS を同じ層で扱う）。
- **代替**: サブドメイン分割（`web.example.com` / `api.example.com`）＋共有親ドメイン Cookie（`.example.com`）。
  CORS/CSRF の考慮が増えるため既定にはしない（将来必要になれば選択可能）。

### 3. authorize ↔ login の分割フロー（最重要）

ログイン画面（web）と認可サーバ（api）が別プロセスになるため、資格情報検証・SSO 発行・code 発行を
api 側の**内部 API**へ集約し、web は画面描画とリダイレクトのみを担う（「認証 UI と認可サーバの分離」パターン）。

```
RP ── GET /authorize ──▶ api
                         ├─ client/redirect_uri/scope 検証・auth_session 作成
                         ├─ 有効な SSO Cookie があれば即 code 発行 → RP へ 302（従来どおり）
                         └─ 無ければ web の /login へ 302（auth_session 参照を伴う）
ブラウザ ── GET /login ─▶ web ─ フォーム描画（HTML＋i18n＋CSRF。auth_session 参照を保持）
ブラウザ ── POST /login ▶ web
                         └─ 資格情報＋auth_session 参照＋接続元情報(ip/UA) を
                            api の POST /internal/authenticate へ送信
                                          ▼
                                         api ─ LoginService（資格情報検証・ロックアウト §4.3・
                                               レート制限・SSO 作成・code 発行）
                                          └─ web へ返す: { redirect_to(code 付き RP URL),
                                                          sso_session_id, sso_ttl } または
                                                          エラー種別（invalid/locked/rate_limited/…）
                            web ─ 成功: SSO Cookie をブラウザへ Set-Cookie ＋ redirect_to へ 302
                                  失敗: エラー文言をローカライズしてフォーム再描画
```

- **SSO セッションは api が作成**（DB 所有者）。api は平文 `sso_session_id` と TTL を web へ返し、
  **Cookie の組み立て（属性 Secure/HttpOnly/SameSite/有効期限）は web が担う**（ブラウザに応答するのは web）。
- **管理コンソールのログイン**（`/admin/console/login`、クライアント不要・ADR-0006 §6）も同じ構造。web が
  フォームを描画し、資格情報を api の内部エンドポイント（管理ログイン用のバリアント）へ送って SSO を発行する。
- ロックアウト（§4.3）・IP レート制限・監査記録は**すべて api 側**で行う（唯一の DB 所有者）。web は
  接続元情報（`X-Forwarded-For` 由来 IP・User-Agent）を内部呼び出しに転送する。

### 4. 管理コンソール（web）→ JSON 管理 API（api）の認可

- 管理コンソールの各画面は、データ取得/操作を api の `/admin/*` JSON エンドポイント越しに行う。
- 認可は**管理者の SSO Cookie を web が api へ転送**し、api 側の既存 extractor `RequirePerms<IdpAdmin>`
  （SSO→利用者→権限突合、ADR-0006）を**そのまま再利用**する。サービス間で権限判定を二重化しない。
- CSRF は従来どおり **web 側**で維持（SSO セッション id 由来の同期トークン `console_csrf_token`）。web は
  フォーム CSRF を検証したうえで api を呼ぶ。
- 単一オリジン（決定 2）のため Cookie 転送は素直（同一ドメイン）。

### 5. 内部 API（`/internal/*`）の保護

- `/internal/*`（認証・その他サービス間 I/F）は**外部公開しない**。リバースプロキシは `/internal/*` を
  ルーティング対象から除外し、api の内部ネットワーク経由でのみ web から到達可能にする。
- 多層防御として、web→api の内部呼び出しに**サービス認証トークン**（共有シークレットのヘッダ。将来 mTLS）を
  必須とする。トークンは設定（`config` 経由）で注入する。

### 6. DTO 契約の共有（`contracts` crate）

- api が返す JSON DTO と、web の API クライアントが用いる型を**同一の serde 構造体**で共有するため、
  **`contracts` crate** を新設する（リクエスト/レスポンス DTO・内部認証 DTO・エラー種別）。
- コンパイル時に api（サーバ）と web（クライアント）の契約整合を保証する。OpenAPI からのコード生成は
  ツール依存が増えるため採らない（型は Rust で単一定義する）。utoipa による OpenAPI は api 側で継続。

### 7. cargo workspace 構成（目標形）

```
Cargo.toml                 # [workspace]
crates/
  core/        # domain + application + infrastructure（sqlx 依存）。api のみが使う
  contracts/   # serde DTO（api サーバ ↔ web クライアントで共有）。DB 非依存
  api/         # axum: protocol + JSON 管理 + /internal/*。core・contracts に依存
  web/         # axum: HTML 描画（login・admin console）+ i18n + API クライアント。contracts に依存し、
               #       core/infrastructure（sqlx）には依存しない
```

- **web は sqlx／infrastructure に依存しない**ことを crate 境界で強制する（これが分離の肝）。
- 設定（`config`）・ログ（`telemetry`）・`correlation` のような両サービス共通の基盤は、web が sqlx を
  間接依存しないよう、**DB 非依存の共通部分**を切り出す（`core` を細分するか小さな共通 crate を設ける）。
  厳密な切り出し境界は P1 で確定する。
- i18n（`i18n/*.ftl` と `presentation::i18n`）は描画側＝**web** へ移す。
- CLAUDE.md「単一バイナリクレート（将来 workspace 分割可）」の "将来" を本 ADR で実施する。移行完了時に
  CLAUDE.md のディレクトリ構成節を workspace 構成へ更新する（P1）。

### 8. DB・署名鍵・ヘルスチェック

- **DB 直結・スキーマ version 照合（fail-fast、ADR-0004）・署名鍵ブートストラップ（`ensure_active_key`）は
  api のみ**が行う。web は起動時に DB を見ない。
- `migrate` ワンショットジョブ（`sqlx migrate run`）は現状維持（DDL 適用はアプリ起動と分離、CLAUDE.md）。
- ヘルスチェック: 各サービスに `/healthz`（liveness、依存を見ない）。api の `/readyz` は DB＋schema version、
  web の `/readyz` は api への到達性を確認する。

## Consequences

**Positive**

- api（対 RP protocol）と web（人間向け画面）を独立にスケール・デプロイ・公開制御できる。
- 管理コンソールの障害・変更が protocol へ波及しない（blast radius 分離）。
- DB 所有者が api のみになり、データアクセス面が縮小（web は DB 資格情報を持たない）。
- crate 境界で「web は DB を触らない」を**コンパイル時に強制**でき、分離が退行しない。
- 認可判定（`RequirePerms<IdpAdmin>`・SSO 検証）を api に一元化し、二重実装を避けられる。

**Negative / コスト**

- **api に OIDC 標準外の内部認証エンドポイント**（`/internal/authenticate` 等）を新設する必要がある。
- 現在 presentation が application 層を**直接呼ぶ全箇所**（管理コンソール各画面・状況確認・権限付与/剥奪の
  POST・ログイン）を **API クライアント越し**に置き換える（工数の大半）。
- サービス間のネットワークホップによる遅延・障害点の増加。内部トークン/mTLS の運用が増える。
- SSO Cookie を「api が発行値を作り web が Set-Cookie する」責務分割にするため、Cookie 属性の一貫性
  （Secure/SameSite/TTL）を web 側で正しく維持する必要がある。
- 既存の全部入り統合テスト（`tests/*` は `router::build` を利用）を **api 単体＋web→api E2E** へ再編する。

**Alternatives considered**

- **共有 lib・2 バイナリ・各自 DB 直結**（当初の低リスク案）: 変更は最小だが web も DB に直結し続け、
  「Web は DB を持たない」理想に届かない → 却下（本 ADR は理想形を採る）。
- **ログイン画面を api 側に残す**（Web=管理コンソールのみ）: authorize↔login が 1 プロセスに収まり単純だが、
  「全 HTML 画面を web に集約」という決定に反する → 却下。
- **サブドメイン分割＋共有親ドメイン Cookie**: 単一オリジン・パスルーティングに比べ CORS/CSRF の考慮が増える
  → 既定にはしない（必要時の代替として残す）。
- **OpenAPI からの型生成で契約共有**: ツール依存が増える。Rust 単一定義（`contracts` crate）で十分 → 却下。

## Follow-ups

- 本 ADR に基づき Progress C1 の **P1〜P5** を実施する（workspace 化 → 内部認証 API → web crate 化 →
  Compose 分離 → テスト再編）。着手順・粒度は P1 で詳細化する。
- `docs/OIDC_INPUT.md` §4.2 に「login 画面と authorize は別サービスだが外部契約は不変。資格情報検証は
  api の内部エンドポイントで行う」旨を注記する（実装時）。
- `docs/OPERATIONS.md` に api/web の起動・ネットワーク公開範囲・内部トークン・リバースプロキシのパス
  ルーティング設定を追記する（P4）。
- 移行完了時に `CLAUDE.md` のディレクトリ構成節を workspace 構成へ更新する（P1）。
