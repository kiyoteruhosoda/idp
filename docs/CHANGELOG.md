# CHANGELOG

完了した重要な変更の要約（詳しい経緯は `history/`、設計判断は `adr/`）。

## 2026-07-07（web 画面をテンプレート化 + ビルド/デプロイのホスト分離）

- **web の HTML をコード生成から Askama テンプレートへ移行**。web crate の全画面（利用者ログイン・
  管理コンソール: ホーム/ログイン/クライアント一覧・登録/編集・詳細・secret 表示/利用者検索・権限/
  監査ログ/クライアント状況/共通レイアウト・告知）で `format!` による HTML 組み立てを廃し、
  `crates/web/templates/` 配下の `.html`（`console/layout.html` を継承）へ集約した。テンプレートは
  `.html` 拡張子により `{{ }}` 出力が自動 HTML エスケープされるため、手動エスケープの `html.rs`
  （`escape`）を削除。Askama のコンパイル時型検証で描画の型安全を担保（sqlx のコンパイル時クエリ検証と
  同じ思想）。外形（フォーム項目・CSRF 埋め込み・エスケープ）は不変で、web の全テスト・E2E 経路は維持。
  （エスケープは名前付き実体参照 `&lt;` から数値文字参照 `&#60;` へ変わるが XSS 安全性は同等。）
- **ビルド／デプロイのホスト分離**。ソースがある「ビルド側」と稼働する「デプロイ先」を別ホストとして扱う
  構成に整理した。`scripts/build.sh`（ビルド側）はネイティブ binary／Docker イメージのビルドと
  検証（`--check` = fmt/clippy/test）を行い、**コンテナは起動しない**。イメージ受け渡しはレジストリ
  （`--push`）と tar（`--save`）の両対応。デプロイ先用に `docker-compose.deploy.yml`（`build:` を持たず
  `image:` 参照のみ）を追加し、`init.sh`（初回・DB コンテナ新規作成）／`deploy.sh`（更新）は
  **ソースを持たずビルドせず**、`pull`／`docker load` 済みイメージで起動する。イメージ名は
  `${IMAGE_PREFIX:-idp}/{api,web,migrate}:${IMAGE_TAG:-latest}`（`.env` で設定）。`scripts/README.md`・
  `docs/OPERATIONS.md` を分離構成へ更新。

## 2026-07-06（C1 完了: API/Web サービス分割 — P5 テスト再編・E2E）

- **C1（コンテナ分離）完了**。ADR-0007 の理想形（真のサービス分割）を P0〜P5 まで実装。api（OIDC
  protocol・JSON 管理 API・内部 API・DB 唯一の所有者）と web（全 HTML 画面・API クライアント・DB 非依存）
  を cargo workspace（`core`/`contracts`/`api`/`web`）＋別コンテナ＋単一オリジンのリバースプロキシで分離。
- **P5 テスト再編**。api 単体統合テスト（`oidc_flow` は `/internal/authenticate` 駆動）＋web→api の自動
  E2E ハーネス `scripts/e2e.sh` を新設。e2e はapi・webを別プロセスで起動し、`/authorize`→web `/login`→
  `/token` の OIDC フローと管理コンソール（ログイン・クライアント作成・権限付与・状況/監査）を
  ブラウザ相当の HTTP で通す（実 MariaDB で全項目パスを確認）。
- 外部から見た OIDC 契約（`docs/OIDC_INPUT.md`）は分割の前後で不変。

## 2026-07-06（C1 P3-4・P4 完了: api の HTML 撤去とサービス分離 Compose）

- **api から HTML を撤去**（P3-4）。ログイン画面・管理コンソール 4 画面・i18n・html・`AdminHtmlSession`
  を削除し、api は OIDC protocol・JSON 管理 API・内部 API のみに。JSON 401/403 を返す
  `RequirePerms<IdpAdmin>` は残す。`/login`・`/admin/console/*` ルートを削除。core の未使用
  `admin_csrf_token` を削除。api 統合テストを再編（`oidc_flow` は `/internal/authenticate` 駆動へ、
  HTML 画面テストは web へ移動）。全テスト緑（fresh MariaDB）。
- **api / web / proxy の Compose 分離**（P4、ADR-0007 §2）。Dockerfile を 1 ワークスペース→2 バイナリ
  （`idp`＝api、`idp-web`＝web）＋2 実行ステージ（`runtime-api`・`runtime-web`）に。`docker-compose.yml`
  を `api`（DB 直結・非公開）／`web`（DB 非依存・非公開）／`proxy`（nginx。単一オリジンでパスルーティング）
  へ再構成。`docker/nginx.conf`: `/login`・`/admin/console/*`→web、`/internal/*` 遮断、他→api。
  `INTERNAL_SERVICE_TOKEN` を api・web で共有（`init.sh` が乱数生成、Compose が必須化）。`init.sh`・
  `deploy.sh`・`OPERATIONS.md`・`.env.example` を分離構成へ更新。
  （注: Docker イメージのビルドはサンドボックスの egress 制限〔apt ミラー 405〕で本環境では検証不可。
  ワークスペースはホスト cargo で両バイナリともビルド・実機起動を確認済み、compose config は妥当。）

## 2026-07-06（C1 P3-2 完了: ログイン画面を web crate へ移設）

- **ログイン画面（`/login` GET/POST）と i18n を `web` crate へ移設**（ADR-0007 P3-2）。web はフォーム描画と
  リダイレクトのみを担い、資格情報検証・SSO/code 発行は api の `POST /internal/authenticate` に委ねる。
  web は接続元情報（`X-Forwarded-For` 由来 IP・User-Agent）を転送し、成功時に api が返す `sso_session_id` を
  Cookie 化して `redirect_to` へ 302、`auth_session_id` Cookie を失効させる。エラーはローカライズして再描画。
- **ログイン CSRF 導出を `contracts` に一元化**（`idp_contracts::csrf::login_csrf_token`）。web（フォーム描画）と
  api（`LoginService` 検証）で同一導出を共有し、固定ベクタのユニットテストで齟齬を防ぐ。core は本関数へ委譲。
- web に i18n・cookies・correlation・login ハンドラを実装（api の presentation から移植）。api 側の `/login` は
  当面併存（全部入り E2E 維持のため。撤去は P3-4）。
- 検証: `cargo build`／`clippy` 警告なし／lib テスト（api 31・core 45・contracts 2・web 7）。**api＋web＋MariaDB を
  同時起動した実機 E2E**で、api `/authorize` →（別プロセスの）web `/login` GET/POST → api `/internal/authenticate`
  → SSO Cookie 発行＋`code` 付き RP リダイレクト → api `/token` で `id_token` 発行、まで疎通を確認。web が転送した
  IP が `sso_sessions.ip_address` に記録されることも確認。

## 2026-07-06（C1 P3-1 完了: contracts crate ＋ web crate 土台）

- **`contracts` crate（`idp-contracts`）を新設**（ADR-0007 §6）。内部認証 API（`/internal/authenticate*`）の
  DTO を api の presentation から移設し、**api サーバと web クライアントで同一の serde 型を共有**する
  （コンパイル時に契約整合を保証）。DB/axum/sqlx へは依存しない。
- **`web` crate（`idp-web` / bin=`idp-web`）を新設**。web 固有設定（`API_BASE_URL`・共有サービストークン・
  `WEB_BIND_ADDR` 等）、JSON ログ初期化、**reqwest ベースの API クライアント**（api への唯一の出入口。
  内部認証呼び出しにサービストークンと correlation_id を付与）、ヘルスチェック（`/healthz` liveness、
  `/readyz` は api への到達性で判断）を実装。
- **web は sqlx / idp-core に依存しない**ことを `cargo tree` で確認（crate 境界で分離を強制。ADR の肝）。
  api は無変更で全テスト緑。web バイナリの起動と `/healthz`=200・`/readyz`=503（api 停止時）を実機確認。
- P3 は規模が大きいためステージ分割で進める（本コミットは土台）。ログイン画面・管理コンソール・i18n の
  web 移設と、api からの HTML 撤去は後続ステージ。テスト再編は P5。

## 2026-07-06（C1 P2 完了: 内部認証 API）

- **内部認証エンドポイントを api に新設**（ADR-0007 §3・§5、C1 の P2）。OIDC 標準外の
  `POST /internal/authenticate`（OIDC ログイン）と `POST /internal/authenticate/admin`（管理コンソール）。
  将来の `web` crate が資格情報・`auth_session_id` 参照・接続元情報（IP/User-Agent）を JSON で転送し、api が
  既存の `LoginService`／`AdminLoginService`（資格情報検証・ロックアウト §4.3・IP レート制限・SSO/code 発行・
  監査）を実行して `result` タグ付き JSON を返す。Cookie 組み立て（Secure/HttpOnly/SameSite/TTL）とエラー
  文言のローカライズは呼び出し側（web）の責務。
- **サービス認証トークンで `/internal/*` を保護**（§5）。`X-Internal-Auth-Token` ヘッダを設定
  `INTERNAL_SERVICE_TOKEN`（未設定時は開発用の既定値＋起動時警告）と定数時間比較し、不一致は 401。
  `route_layer` で内部サブルータのみに適用（外部公開しない前提。リバースプロキシ遮断は P4）。
- 内部 DTO は presentation（`dto.rs`）に定義し `result` で判別（`contracts` crate 化は P3）。既存 HTML
  `/login`・`/admin/console/login` は同一プロセスのため引き続きユースケースを直接呼ぶ（API クライアント化は
  P3）。外部から見た OIDC 契約（§4.2）は不変。`docs/OIDC_INPUT.md` §4.3 に実装メモを追記。
- 検証: `cargo build`／`cargo clippy`（警告なし）／ユニットテスト（内部認証 3 件を追加）／MariaDB 実 DB での
  統合テスト `tests/internal_auth.rs`（トークン 401・CSRF 不一致・認証成功で SSO/code 発行・管理認証失敗）と
  既存 E2E（`oidc_flow` 等）を確認。

## 2026-07-06（ADR-0007 Accepted・C1 P1 完了: cargo workspace 化）

- **ADR-0007（API/Web サービス分割）を Accepted** とし、C1 の **P1（workspace 化）** を実施。単一クレート
  `idp` を **cargo workspace** に分割した。`crates/core`（lib=`idp_core`）に domain/application/
  infrastructure と config/telemetry（sqlx・DB 依存）を集約し、`crates/api`（lib=`idp_api` / bin=`idp`）に
  presentation と `run()` を置く。api は core を再エクスポートするため presentation 内の `crate::domain` 等の
  参照は不変。共通依存は `[workspace.dependencies]` で一元管理。
- **all-in-one を保ったままの crate 境界作成**（P1 の方針どおり。web/contracts crate と Web→API HTTP 化は
  後続 P2〜P5）。統合テストは `crates/api/tests/` へ移設（参照は `idp_api::*`）。`migrations/`・`i18n/` は
  リポジトリルート据え置きで、`sqlx::migrate!("../../migrations")`／`include_str!(CARGO_MANIFEST_DIR/../../i18n)`
  により crate から相対参照する。Dockerfile の builder を workspace ビルドへ更新（bin=`idp` は不変）。
- 検証: `cargo build --workspace`／`cargo clippy --workspace --all-targets`（警告なし）／lib ユニットテスト
  45 件パス。外部契約（OIDC・API 経路・バイナリ名）に変更なし。

## 2026-07-06（A3 完了: 状況確認画面）

- **状況確認画面をサーバレンダリングで実装**（A3 完了、設計仕様 §7）。監査／ログインログ一覧
  （`/admin/console/audit-logs`）とクライアント状況一覧（`/admin/console/status`）を追加。画面用
  extractor `AdminHtmlSession` で保護し、共通レイアウト `render_layout`（A2）の上に描画。JSON 管理 API
  （`GET /admin/audit-logs`、OpenAPI の正典）とは経路を分離。ホームから両画面へリンク。
- **監査ログ一覧画面**: `event_type`／`result`（`failure` 等のエラー絞り込みが主眼）／`client_id`／
  `correlation_id`／期間（`from`/`to`、RFC3339）で AND 絞り込みし、新しい順に表示。`offset` による前後
  ページ移動（フィルタ条件は URL エンコードで引き継ぐ）。日時形式が不正なら検索せずエラー表示。データ取得は
  API と同じ `AuditQueryService` を通す（読み取り専用のため CSRF は無い）。
- **クライアント状況一覧画面**: 各クライアントの状態（ACTIVE/DISABLED）・scope・**最終利用時刻**を表示。
  最終利用時刻は `audit_log`（成功した `token.issued`／`authorization_code.issued` の最新 `occurred_at`）
  から導出する（マイグレーション不要・書き込み経路への影響なし）。Application に読み取り専用の
  `ClientStatusService`（`ClientRepository` × `AuditLogQuery`、変更を担う `ClientManagementService` とは
  SRP で分離）を新設し、`AuditLogQuery::last_used_per_client`（client_id 別の最新利用時刻を 1 回の集計で取得）
  を追加。
- 単体テスト（監査行のエスケープ・失敗行の強調・空/日時エラー表示・ページャ・クエリ文字列のエンコード・
  状況一覧の最終利用時刻／未利用の `-`、サービスの突き合わせ）と統合テスト `tests/admin_status_console.rs`
  （未認証→ログイン画面へ 302、非管理者→403、状況一覧で最終利用時刻表示、監査一覧の絞り込み・不正日時→
  エラー）を追加。

## 2026-07-06（A2 完了: 利用者権限の付与・剥奪画面）

- **利用者権限の付与・剥奪のサーバレンダリング画面を実装**（A2 完了、ADR-0006）。`/admin/console/users*` に
  利用者検索（メール／ユーザー名）・保有権限の一覧・付与フォーム（付与可能コードの datalist 付き）・
  剥奪ボタンを提供。画面用 extractor `AdminHtmlSession` で保護し、共通レイアウト `render_layout`（A2）の
  上に描画する。データ操作は JSON API と同じ `PermissionManagementService` を通し、検証・監査記録を二重化しない。
- **経路分離**: ブラウザ向けコンソールは `/admin/console/users*`、JSON 管理 API（OpenAPI の正典）は
  `/admin/users/{user_id}/permissions` のまま。付与・剥奪の POST は Post/Redirect/Get で権限画面へ 302 し、
  失敗（CSRF 不一致・未知コード等）は `error` クエリで伝える（二重送信の回避）。CSRF は SSO セッション id
  由来の同期トークン `console_csrf_token`。利用者入力は `presentation::html::escape` を通し格納型 XSS を防止。
- Application の `PermissionManagementService` に画面用の読み取り（識別子→利用者解決 `find_user_by_identifier`・
  表示用 `get_user`・付与可能コード一覧 `available_codes`）を追加。付与可能コードは `permissions` マスタを
  単一の出所とし、`UserPermissionRepository::list_available_codes` で取得する（許可値の直書き重複なし）。
- 単体テスト（検索結果／権限画面のレンダリングと HTML エスケープ・エラークエリ→i18n キー写像・
  リダイレクト先の検証、サービスの識別子解決／付与可能コード）と統合テスト `tests/admin_users_console.rs`
  （未認証→ログイン画面へ 302、非管理者→403、メール／ユーザー名検索、CSRF 不一致・未知コード→302 error、
  付与／剥奪の 302 と `audit_log` 記録、不存在・非 UUID→404）を追加。

## 2026-07-06（A1: クライアント（RP）管理画面、A2 コンソール基盤の上に実装）

- **クライアント（RP）管理のサーバレンダリング画面を実装**（A1 完了、設計仕様 §9.3）。一覧・新規登録・
  詳細・編集・secret 再発行・無効化（状態 DISABLED）を `/admin/console/clients*` で提供。画面用 extractor
  `AdminHtmlSession` で保護し、共通レイアウト `render_layout`（A2）の上に描画する。データ操作は JSON API と
  同じ `ClientManagementService` を通し、検証・監査記録・secret 発行のロジックを二重化しない。
- **経路分離**: ブラウザ向けコンソールは `/admin/console/*`、JSON 管理 API（OpenAPI の正典）は
  `/admin/*` に整理。これに伴い前コミットの A2 コンソール（ログイン/ホーム/ログアウト）も `/admin/console/*`
  へ移設（`/admin/console/login`・`/admin/console`・`/admin/console/logout`）。
- **セキュリティ**: 利用者入力を HTML へ差し込む箇所は新設の `presentation::html::escape` を通し格納型 XSS を防止。
  ログイン後の状態変更フォームは SSO セッション id 由来の同期トークン `console_csrf_token` で CSRF 対策。
  `client_secret` は confidential の作成・再発行時に**その画面でのみ**平文表示（DB はハッシュのみ）。
- 単体テスト（入力パース・HTML エスケープ・一覧のエスケープ・CSRF 導出）と統合テスト
  `tests/admin_clients_console.rs`（未認証→ログイン画面へ 302、CSRF 不一致・不正 scope→400、
  confidential 作成で secret 一度表示、詳細・編集で DISABLED 反映、secret 再発行、不存在→404、非管理者→403）を追加。

## 2026-07-06（A2: 管理コンソール基盤 UI・管理ログイン、ADR-0006 §6）

- **管理コンソールのサーバレンダリング基盤 UI を実装**（A2、ADR-0006 §6）。管理ログイン
  （`GET/POST /admin/console/login`）・ホーム（`GET /admin/console`）・ログアウト（`POST /admin/console/logout`）を追加。
  文言は既存ログイン画面と同じ `fluent`（en/ja）。
- 管理ログインは OIDC クライアント不要で **SSO セッションを直接発行**する（`/authorize` 由来の
  `auth_session_id`・code 発行・redirect を伴わない）。初回デプロイ時にクライアントが存在しなくても
  コンソールへ入れる（鶏卵問題の回避）。資格情報検証・ロックアウト（§4.3）・IP レート制限は通常ログインと
  同方針で、レート制限器は共有。`idp.admin` 非保有の正当利用者は Forbidden（SSO 非発行）。CSRF は同期
  トークン方式（GET で `admin_csrf_id` Cookie を発行し一方向ハッシュをフォームへ埋め込む）。
- Application に `AdminLoginService`（ログイン／ログアウト。ログアウトは `sso_session.terminated` を監査）、
  Presentation に画面用の認可 extractor `AdminHtmlSession`（未認証→ログイン画面へ 302／権限不足→403 HTML。
  API 用 `RequirePerms<IdpAdmin>` の JSON 401/403 と使い分け）と共通レイアウト `render_layout`
  （A1/A3 の画面はこの上に差し込む）を追加。監査は既存種別のみ使用（§7 の追加なし）。
- 単体テスト（CSRF 導出の決定性・名前空間分離、フォーム／レイアウトのレンダリングと i18n）と統合テスト
  `tests/admin_console.rs`（ログイン画面→CSRF 発行、未認証ホーム→302、CSRF 不一致→400、正当ログイン→
  SSO 発行→ホーム 200→ログアウトで失効、非管理者→403）を追加。

## 2026-07-06（A2: 利用者権限の付与・剥奪 API）

- **利用者権限の付与・剥奪 API を実装**（管理コンソール基盤 A2、ADR-0006、設計仕様 §7）。
  `/admin/users/{user_id}/permissions` の付与（`POST`）・剥奪（`DELETE {permission_code}`）・参照（`GET`）
  （`RequirePerms<IdpAdmin>`）。付与は冪等、未知の権限コードは 400、対象利用者不存在は 404、
  `user_id` が UUID でなければ 400。応答は操作後の保有権限コード一覧。
- 参照（保護判定）の `AdminAccessService` と責務を分離（SRP）し、管理（変更）用の
  `PermissionManagementService`（Application）を新設。付与・剥奪を `AuditEventType::UserPermission*`
  （`user_permission.granted` / `.revoked`、actor を `user_id`・対象と権限コードを `reason` に記録）
  として `audit_log` へ出力する結線を追加。DTO（`GrantPermissionRequest` / `UserPermissionsResponse`）と
  `admin_permissions` ハンドラを追加し OpenAPI（tag `admin`）へ掲載。単体テスト（付与/剥奪の監査記録・
  空/未知コード・対象不存在）と統合テスト `tests/admin_permissions.rs`（401/403/400/404・付与/剥奪・
  冪等・監査記録）を追加。

## 2026-07-06（A3: 監査/ログイン ログ参照 API）

- **監査ログ参照 API を実装**（状況確認画面 A3、設計仕様 §7）。`GET /admin/audit-logs`
  （`RequirePerms<IdpAdmin>`）で `audit_log` を `event_type` / `result`（`failure` 等のエラー絞り込み）/
  期間（`from`/`to`、RFC3339）/ `client_id` / `correlation_id` で AND 絞り込みし、新しい順
  （`occurred_at` 降順・同時刻は `id` 降順）に返す。`limit`（既定 50・上限 200）・`offset` でページング。
- 読み取り境界 `AuditLogQuery`（書き込みの `AuditLogSink` と分離）と読み取りモデル `AuditLogEntry` /
  `AuditLogFilter` をドメインに追加。sqlx 実装は `QueryBuilder` で条件を安全にバインド。Application に
  `AuditQueryService`（limit クランプ・空文字正規化）、Presentation に `admin_audit` ハンドラと DTO を追加。
  OpenAPI に tag `admin` で掲載。単体テスト（limit クランプ・正規化）と統合テスト `tests/admin_audit.rs`
  （絞り込み・新しい順・401/403/400）を追加。

## 2026-07-06（A1: クライアント（RP）登録・管理 API）

- **クライアント管理 API を実装**（設計仕様 §9.3、Progress A1）。`/admin/clients` の CRUD＋シークレット
  再発行（`RequirePerms<IdpAdmin>` で保護）。`client_id` 自動採番、`client_secret` は confidential の
  登録・再発行時に**その応答でのみ**平文表示し DB は argon2 ハッシュのみ。`client_type` に応じ
  `token_endpoint_auth_method`（public=`none`／confidential=`client_secret_basic`）と PKCE を設定。
  redirect_uri は完全一致・複数登録・フラグメント／ワイルドカード禁止をアプリ層で検証。scope は
  `openid` を含む OIDC scope に限定。
- ドメインに `ClientRepository::{create,list,update}` を追加し sqlx 実装、Application に
  `ClientManagementService`（検証・secret 発行・監査記録）、Presentation に `admin_clients` ハンドラ群と
  DTO を追加。`ApiError::NotFound`（404）を追加。監査種別 `client.registered`/`.updated`/
  `.secret_rotated` を追加（§7）。OpenAPI に tag `admin` で自動掲載。
- 単体テスト（redirect_uri／scope／app_name 検証）と統合テスト `tests/admin_clients.rs`
  （401/403/400/CRUD/secret 再発行、権限の無い利用者の 403）を追加。

## 2026-07-06（管理機能の権限モデル基盤・A2 の前提、ADR-0006）

- **利用者権限モデルを実装**（ADR-0006）。OIDC scope（claim 制御）とは別軸の「利用者権限
  （permission code）」を新設。マイグレーション `0003_permissions_and_user_permissions`
  （`permissions` マスタ＋`user_permissions` 多対多）と seed `0004_seed_admin_permission`
  （`idp.admin` の登録と初期管理者への冪等付与）を追加。
- ドメインに値オブジェクト `PermissionCode` と `UserPermissionRepository`（DIP 境界。参照/付与/剥奪）、
  Infrastructure に sqlx 実装、Application に `AdminAccessService`（SSO セッション→利用者解決→権限突合。
  検証は Application 層で完結し Presentation には可否のみ返す）、Presentation に `RequirePerms<IdpAdmin>`
  extractor を追加。保護の疎通確認用に内部エンドポイント `GET /admin/whoami`（`idp.admin` 必須）を追加。
- 監査イベント種別 `user_permission.granted` / `.revoked` を追加（設計仕様 §7）。

## 2026-07-05（インフラ整備 T9〜T13・D2）

- **T9: IdP アプリのコンテナ化と Compose 統合**。マルチステージ `Dockerfile`（`rust:slim` ビルド →
  `debian:bookworm-slim` 実行、非 root、i18n は include_str! で埋め込み、TLS は rustls）を追加。
  `docker-compose.yml` に `web` サービス（`/healthz` の HEALTHCHECK、`mariadb` の service_healthy を
  `depends_on`、`DATABASE_URL` はサービス名 `mariadb` で解決）と、DDL/マスタデータ適用専用の
  ワンショット `migrate` サービス（sqlx-cli。`profiles: [tools]`）を追加。`.dockerignore` も追加。
- **T10: 秘密情報・設定の .env 一元管理**。`.env.example` を全設定（MariaDB パスワード・
  `KEY_ENCRYPTION_KEY`・`TEST_DATABASE_URL` を含む）の単一テンプレートへ拡充。Compose の秘密値を
  `.env` から注入するようパラメータ化。`config.rs` は空文字の環境変数を「未設定」として扱うよう
  堅牢化（Compose の `${VAR:-}` 由来の空値でパースが失敗しないように。単体テスト追加）。
- **T11: 初期設定スクリプト**。`scripts/init.sh`（冪等）でパスワード・鍵を乱数生成して `.env` を作成
  （既存は上書きしない）→ MariaDB 起動 → マイグレーション適用 → web ビルド・起動 → healthz 待機。
  共通処理は `scripts/lib.sh` に集約。
- **T12: 初期管理ユーザーのマスタデータ**。seed マイグレーション
  `migrations/0002_seed_initial_admin`（冪等 upsert。固定 id/sub、既定パスワードは変更前提）を追加。
  password_hash は argon2id（アプリと同一形式）。
- **T13: デプロイスクリプト**。`scripts/deploy.sh`（イメージビルド → DDL/マスタデータ適用の専用ジョブ →
  `up -d web` → `/readyz` 確認、ロールバック方針をコメント記載）。
- **D2: 運用手順を OPERATIONS.md に統合**。初期化・デプロイ・ロールバック・初期管理ユーザーの
  パスワード変更・`KEY_ENCRYPTION_KEY` ローテーション・バックアップ/リストアの手順を追記。

## 2026-07-05

- **T8: テスト & MVP 完了条件の E2E 検証**。`tests/oidc_flow.rs` で設計仕様 §10 の条件 1〜13 を
  通しで検証（登録 → /authorize → /login → code → /token → /userinfo → SSO 復元、code 再利用拒否、
  ロックアウト、client 認証失敗、監査ログの記録）。PKCE は RFC 7636 Appendix B のテストベクタを使用。
  純粋ロジック（PKCE / CSRF / Cookie / redirect URL 構築 / i18n / レート制限 / 認可検証）の
  単体テストを各モジュールへ追加。
- **D1: 付随ドキュメント整備**。`docs/ARCHITECTURE.md`（レイヤー構成・実装パターン）と
  `docs/OPERATIONS.md`（起動・マイグレーション・テスト・環境変数などの手順）を新設。
  utoipa による OpenAPI 自動生成（`/api/openapi.json`）と Swagger UI（`/api/docs`）を追加し、
  API 仕様の唯一の出所とした。
- **T7: 監査ログを横断結線**。`AuditService` が全イベント（login.succeeded/failed/locked、
  authorization_code.issued/used/reuse_detected、token.issued、client.authentication_failed、
  sso_session.created/resumed/expired）を tracing（JSON）と `audit_log` テーブルへ二重出力。
  correlation_id ミドルウェア（`x-request-id`）でリクエストと監査イベントを一気通貫で追跡可能に。
- **T6: Discovery / JWKS / UserInfo を実装**。`GET /.well-known/openid-configuration`（issuer は
  末尾スラッシュ無しで `iss` と完全一致）、`GET /.well-known/jwks.json`（ACTIVE+RETIRED 公開）、
  `GET /userinfo`（Bearer の `typ=at+jwt` JWT を署名・iss・aud・exp（±60s スキュー）で検証し、
  scope（openid/email/profile）に応じたクレームのみ返却）。
- **T5: トークン発行 `POST /token` を実装**。client 認証（confidential=`client_secret_basic`
  （argon2 検証・Basic ヘッダの percent-decode 対応）/ public=なし、header と body の client_id
  不一致は `invalid_request`）、code の原子的 one-time 消費（`UPDATE ... WHERE used_at IS NULL AND
  expires_at > ?` の affected rows 判定。0 行 = `invalid_grant` + `authorization_code.reuse_detected`）、
  PKCE S256 検証（verifier 43〜128 文字・文字種検証）、ID Token（`typ=JWT`、scope に応じた
  email/profile クレーム付与）と Access Token（`typ=at+jwt`、`aud=<issuer>/userinfo`）の RS256 発行、
  `Cache-Control: no-store` / `Pragma: no-cache`。
- **T4: 認可フロー中核を実装**。`GET /authorize`（検証: client 存在/ACTIVE・redirect_uri 完全一致・
  `response_type=code`・scope が openid を含み client 登録 scope の部分集合・state/nonce 必須・
  `code_challenge_method=S256`。client_id/redirect_uri 不正はリダイレクトせず 400、他は redirect_uri
  へエラー返却）、`GET/POST /login`（fluent による en/ja の i18n 画面、CSRF は auth_session_id 由来の
  同期トークン、username 単位 連続 10 回失敗 → 15 分ロック、IP 単位レート制限、成功時リセット）、
  SSO セッション（Cookie は平文 session_id・DB は SHA-256。復元時 idle +8h 延長・absolute 不変・
  `auth_time` は初回値維持）、code 発行共通モジュール（`code_issuance.rs`、256bit 乱数・ハッシュ保存・
  TTL 60s）。Cookie は `HttpOnly`/`Secure`(設定可)/`SameSite=Lax`/`Path=/`。302 Found でリダイレクト。
- **T3: ユーザー登録を実装**。`POST /auth/register`（設計仕様 §4.1）。argon2id でパスワードハッシュ、
  `id`/`sub`(UUID v4) 採番、`status=ACTIVE` / `email_verified=false`。email・preferred_username の
  一意性（DB UNIQUE ＋ 事前チェック、競合は 409）、簡易バリデーション（メール形式・パスワード最小長 8）。
  `PasswordHasher` トレイト（domain）＋ argon2 実装、`UserRepository` の sqlx 実装、`RegisterService`、
  presentation の DTO / `ApiError` / `AppState`（`FromRef`）を追加。統合テスト `tests/register.rs`
  （201 / 409 / 400 と DB 永続化）。
- **T2: 署名鍵と JWT 基盤を実装**。RSA-2048 鍵生成、秘密鍵の AES-256-GCM 暗号化保存、`kid` 採番、
  RS256 署名（ID Token=`typ=JWT` / Access Token=`typ=at+jwt`）、JWKS 構築（公開鍵 PEM→`n`/`e`）、
  検証用 `DecodingKey` を実装（`infrastructure/jwt.rs`・`crypto.rs`）。`SigningKeyRepository` の sqlx 実装、
  `KeyService`（ACTIVE 鍵ブートストラップ＝冪等 / 署名材料取得 / JWKS）、`Clock` トレイトと `SystemClock`、
  `KEY_ENCRYPTION_KEY` 設定を追加。クレートを lib+bin 構成へ変更（`src/lib.rs::run()`）。起動時に署名鍵を
  ブートストラップする。sqlx 互換のためベースラインの照合を `utf8mb4_unicode_ci` に統一（`_bin` は
  VARBINARY 扱いで String デコード不可のため。完全一致比較はアプリ層で担保）。統合テスト `tests/keys.rs`
  で「鍵ブートストラップ→署名→JWKS 検証」を確認。
- **T1: データモデルとマイグレーションを実装**。ベースラインマイグレーション
  `migrations/0001_baseline`（up/down）で 6 テーブル（users / clients / auth_sessions /
  sso_sessions / authorization_codes / signing_keys）＋ `audit_log` を作成（MariaDB 向け型読み替え:
  UUID→`CHAR(36)`、enum→`VARCHAR`+`CHECK`、時刻→UTC `DATETIME(6)`、配列→`JSON`、CITEXT 相当のみ
  大小無視照合、既定は `utf8mb4_bin`）。ドメイン層にエンティティ・列挙・監査イベント型・リポジトリ
  トレイト（DIP 境界、`#[async_trait]`）を追加。DB 接続のセッションタイムゾーンを UTC に固定。
  マイグレーション整合の統合テスト（`tests/schema.rs`）を追加。

- **ドキュメントを実装スタック（Rust + MariaDB）に整合**。CLAUDE.md・db-migration スキルを
  Rust/axum/sqlx 前提へ改訂し、ADR-0005（スタック採用）を追加、ADR-0004 と OIDC_INPUT.md に
  MariaDB 読み替え注記を追加（ADR-0005）。
- **T0: プロジェクト基盤を構築**。単一バイナリクレート（`idp`）を作成し、DDD 4層のモジュール骨格
  （domain / application / infrastructure / presentation）を配置。axum によるサーバ起動、`config`
  モジュール（環境変数 > 既定値、issuer 正規化・各種 TTL）、`tracing` の JSON 構造化ログ、sqlx の
  MariaDB 接続プール、起動時のスキーマ version 照合（`_sqlx_migrations` を SSOT とした fail-fast）、
  `/healthz`・`/readyz` ヘルスチェック、開発用 `docker-compose.yml`（MariaDB 10.11 / 任意 Redis）を実装。
