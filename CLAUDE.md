# CLAUDE.md

このプロジェクト固有の設計ルール・制約事項をまとめる。

本プロジェクトは **Rust 製の OpenID Connect Identity Provider（IdP）** である。
設計仕様は `docs/OIDC_INPUT.md`、採用スタックの判断根拠は `docs/adr/0005-rust-mariadb-stack.md` を参照。

## ドキュメント運用

進捗・変更・設計判断は `docs/` 配下で管理する。

```
docs/
├── ARCHITECTURE.md   # 設計・レイヤー構成・命名規則（DDDの実装パターン解説）
├── OPERATIONS.md     # 手順書（下記「ドキュメントの役割分担」参照）
├── Progress.md       # 進行中・未着手タスクのみ
├── CHANGELOG.md      # 完了した重要な変更の要約
├── adr/              # 設計判断（ADR。NNNN-*.md 形式）
└── history/          # 要約だけでは経緯が追えない規模の変更の詳細記録
```

運用ルール:

1. **開発開始時** → `docs/Progress.md` に TODO を追加する。
2. **作業中** → `docs/Progress.md` を更新する（状態・メモ）。
3. **完了時** → `docs/Progress.md` から削除し、重要なら `docs/CHANGELOG.md`（要約）／
   `docs/history/`（経緯）へ移す。Progress には完了項目を残さない。
4. **規模が大きく、背景まで追いたい変更のみ** `docs/history/` に記録する（`CHANGELOG.md` の要約だけで足りるものは history に書かない）。
5. **設計判断は ADR** として `docs/adr/NNNN-*.md` に残す。

### ドキュメントの役割分担（何をどこに書くか）

| ドキュメント | 役割 | 書くこと | 書かないこと |
|---|---|---|---|
| `docs/OPERATIONS.md` | 手順書 | 「〇〇したいとき、〇〇する」という操作手順・コマンドのみ | なぜそうなっているか、過去に何が起きたか、内部の仕組み、API仕様 |
| `docs/ARCHITECTURE.md` | 設計ガイド | レイヤー構成・命名規則・DDDパターンの解説 | 個別機能の操作手順、環境変数の一覧（OPERATIONS.md へ） |
| 各クレート／モジュールの README | 仕様書 | コード・設定が**現在どう動くか**（現状の挙動・制約・注意点） | 「以前は〜だったが」「原因は〜だった」という過去の不具合の経緯 |
| `docs/CHANGELOG.md` | 変更履歴 | 完了した重要な変更の要約（バグ修正・機能追加・破壊的変更を問わない。1〜数行） | 詳しい経緯・調査過程（history へ） |
| `docs/history/` | 経緯の詳細記録 | 要約だけでは伝わらない、規模の大きい変更の背景・原因・調査過程 | 軽微な進捗（Progress で管理） |

迷ったら「これは手順か（OPERATIONS）」「設計の解説か（ARCHITECTURE）」
「現在の仕様か（README）」「短い要約か（CHANGELOG）」「経緯まで残すべき規模か（history）」で判断する。
同じ内容を複数箇所に重複して書かない。

**APIエンドポイント仕様は手書きしない。** axum + `utoipa` から自動生成する
OpenAPI（`/api/openapi.json`）・Swagger UI が唯一の出所。ドキュメントにはそこへのリンクだけを書く。

`docs/Progress.md` は**優先順・番号・概要・状態・影響度・重要度・難易度・工数の表**で書く。
補足が必要なものだけ表の下に「詳細」として番号付きで記載する。

```
| 優先 | # | 概要 | 状態 | 影響度 | 重要度 | 難易度 | 工数 |
|---|---|---|---|---|---|---|---|
| 1 | T1 | 〇〇を実装 | 🚧進行中 | 中 | 小 | 大 | 大 |
```

- 状態: ⬜未着手 / 🚧進行中 / 🟡要判断
- 影響度・重要度・難易度・工数: 大 / 中 / 小

---

## 設計方針

- **DDD（ドメイン駆動設計）** を採用する。Presentation / Application / Domain / Infrastructure の4層構造。依存方向は Presentation → Application → Domain、Infrastructure は Domain のトレイト（インターフェース）を実装する。
- **SOLID 原則**を遵守する。特に SRP（単一責務）と DIP（依存性逆転）を重視。
- **依存注入**を使う。具象への直接依存より、`domain` 層に定義したトレイトへのコンストラクタ注入を優先。axum ではハンドラへの依存を `State` / `Extension` で注入する。
- `util` / `helper` といった曖昧な名前のモジュール・型を作らない。
- 命名はドメイン語彙（ユビキタス言語）を使う。技術用語・略語で上書きしない。

---

## 環境要件

| 項目 | バージョン／方針 |
|---|---|
| Rust | stable（edition 2021 以上）。`rust:slim` ベースでビルド |
| axum | 最新安定版（HTTP・ルーティング） |
| tokio | 非同期ランタイム |
| serde / serde_json | DTO のシリアライズ／デシリアライズ |
| sqlx | MariaDB ドライバ（`mysql` feature、async、コンパイル時クエリ検証） |
| sqlx マイグレーション | `migrations/` 配下で管理（`sqlx migrate`） |
| MariaDB | 10.11.x |
| Redis | 7.x（パスワード保護必須。セッションストアとして任意採用） |
| jsonwebtoken / rsa / argon2 | JWT(RS256) 署名・RSA 鍵生成・パスワードハッシュ |
| tracing / tracing-subscriber | JSON 構造化ログ |
| ホスト | Linux / Synology DSM 7.x（Docker 上） |

---

## ディレクトリ構成

DDD 4層を Rust モジュールへ写像した cargo workspace。ADR-0007（API/Web サービス分割）で単一クレートを
分割した。P1 で `core`（DB 直結：domain/application/infrastructure＋設定・ログ基盤）と `api`（axum
presentation＋バイナリ）へ、P3 で `contracts`（serde DTO 契約）と `web`（HTML 描画＋API クライアント）を
追加した。**web は sqlx/infrastructure に依存しない**（crate 境界で強制。データ操作は api へ HTTP 越し）。

```
Cargo.toml            # [workspace]（共通依存は [workspace.dependencies]）
crates/
  core/               # idp-core（lib=idp_core）。sqlx/DB へ依存する層を集約。api のみが使う
    src/
      config.rs       # 設定（環境変数 > DB system_settings > 既定値）
      telemetry.rs    # tracing による JSON 構造化ログ初期化
      domain/         # ビジネスロジック（フレームワーク・DB非依存）
        repositories.rs # 各リポジトリ trait 定義（DIP 境界）
        error.rs      # ドメインエラー・OAuth/OIDC エラーコード
        ...           # user, client, auth_session, sso_session, authorization_code, signing_key, values
      application/    # ユースケース・トランザクション境界
        ...           # register, authorize, login, token, userinfo, code_issuance(共通), key_service, audit
      infrastructure/ # domain トレイトの実装
        repositories/ # sqlx による MariaDB 実装
        jwt.rs password.rs crypto.rs clock.rs db.rs

  contracts/          # idp-contracts（lib=idp_contracts）。api ↔ web 共有の serde DTO。DB/axum 非依存
    src/auth.rs       # 内部認証 API（/internal/authenticate*）の DTO 契約

  api/                # idp-api（lib=idp_api / bin=idp）。core を再エクスポートし presentation を提供
    src/
      main.rs         # ブートストラップ（idp_api::run）
      lib.rs          # run()・core 再エクスポート
      presentation/   # axum ハンドラ・ルータ・DTO
        router.rs handlers/ dto.rs cookies.rs error.rs i18n.rs
    tests/            # 統合テスト（sqlx + axum）

  web/                # idp-web（lib=idp_web / bin=idp-web）。HTML 描画＋API クライアント。sqlx 非依存
    src/
      main.rs         # ブートストラップ（idp_web::run）
      config.rs       # web 固有設定（API_BASE_URL・共有サービストークン等）
      api_client.rs   # api への reqwest クライアント（データ操作の唯一の出入口）
      templates.rs    # Askama テンプレート構造体（描画のコンパイル時型検証。詳細は下記「画面描画」）
      router.rs handlers/ state.rs telemetry.rs
      # ログイン画面・管理コンソール・i18n は後続ステージで移設（P3）
    templates/        # Askama の HTML テンプレート（console/layout.html を継承）。自動 HTML エスケープ

migrations/           # sqlx マイグレーション（.sql）。crate からは ../../migrations で参照
i18n/                 # fluent 翻訳（.ftl）。api から ../../i18n で埋め込み（移設完了で web へ移す）
```

---

## 権限管理

- 認可は **ロールではなく scope（権限コード値）** で行う。ロール名での分岐禁止。
- OIDC の `scope`（`openid` / `profile` / `email`）は、発行トークンと `/userinfo` の返却クレームを制御する。要求 scope は必ず `Clients.scopes` の部分集合であること。
- 保護エンドポイントには scope 検証を行う axum extractor（例：`RequirePerms("scope_name")`）を付与する。
- 権限の検証は Application 層で行い、Presentation 層には結果のみ渡す。
- JWT 発行時の scope は保有権限の範囲内で指定。未指定・空 = 権限なし。

---

## DDL 管理

- テーブル変更は必ず **sqlx マイグレーション** で行う。手書きの `ALTER TABLE` / `CREATE TABLE` を本番に直接実行しない。
- マイグレーションファイルは `migrations/<version>_<description>.sql`（reversible 運用時は `.up.sql` / `.down.sql` を対で用意）。
- ベースラインは初期マイグレーション（現行モデル全テーブルを生成）。詳細は `migrations/README.md`。
- マスタデータ（clients seed・初期管理ユーザー等）は単一の出所（`domain` 層の定数、または `migrations/masterdata/*.sql`）を seed マイグレーションが参照する。値をどちらかに直書き重複させない。

---

## DB モデリング（sqlx / MariaDB）

- **DB ネイティブ ENUM カラムを使わない。** MariaDB の `ENUM` は値追加に `ALTER TABLE` が必要で DDL 運用と噛み合わず、序数変更でデータが壊れる。**`VARCHAR` + `CHECK` 制約**とし、許可値は Rust 側の enum（`#[derive]` + 文字列変換、または `sqlx::Type`）で集中管理する。
- 型安全のための Rust 側の許可値集中管理（`enum`）は推奨。禁止しているのは「DB 側のネイティブ ENUM 型」であって、Rust の列挙そのものではない。
- **UUID** は MariaDB では `CHAR(36)`（正準文字列）を基本とする（最適化が必要な箇所のみ `BINARY(16)`）。設計書(PostgreSQL)の `UUID` 型はこれに読み替える。
- **時刻は常に UTC の `DATETIME(6)`** で保持する（`chrono::DateTime<Utc>`）。`TIMESTAMP` 型は範囲・自動更新の副作用があるため使わない。設計書(PostgreSQL)の `timestamptz` はこれに読み替える。
- 設計書の PostgreSQL 固有型は次のように読み替える：`CITEXT` → `VARCHAR` + 大小無視照合（`utf8mb4_0900_ai_ci` 等）、`inet` → `VARCHAR(45)`、`text[]`（配列）→ `JSON`、部分UNIQUE索引 → MariaDB の UNIQUE 索引は複数 NULL を許容するため通常の UNIQUE 索引で代替。
- モデル（Rust struct）とスキーマの乖離はマイグレーション整合テストで検出する。

---

## schema-version

- DBスキーマ・マスタデータのバージョン整合性は、**sqlx マイグレーションの version（`_sqlx_migrations` テーブル）を SSOT** とした fail-fast 方式で管理する。
  - 起動時／readiness で「DB が期待 version 以上」を確認し、未満なら起動を失敗させる（厳密一致にしない＝ローリングデプロイ対応）。
  - 設計根拠: `docs/adr/0004-schema-version-sync.md`（Alembic 前提で書かれているが、revision→sqlx version と読み替える。スタック採用理由は `docs/adr/0005-rust-mariadb-stack.md`）。
  - マイグレーション作成時のルール: `.claude/skills/db-migration/` を参照（自動適用）。

---

## 設定管理（Settings）

設定値の取得は **必ず `config` モジュール経由**。生の環境変数・DSN 直接参照は禁止。

```rust
// OK
let issuer = config.issuer();

// NG
std::env::var("ISSUER")?;
```

優先順位: **組み込みデフォルト値 < 環境変数（ENV）< DB（system_settings テーブル）**。
「あとから DB で上書きできる」という思想で、より運用に近い層（DB）を優先する。

- ただし DB 上書きを受け付けるのは `DbManaged` のキーだけ。DB を読む前や DB 内 secret の復号に必要な
  bootstrap 系（`DATABASE_URL`・`KEY_ENCRYPTION_KEY`・`INTERNAL_SERVICE_TOKEN`・`CSRF_SECRET` 等）や、
  api/web で値を一致させる必要があるキーは `EnvLocked` とし、DB を参照せず ENV > 既定値 で解決する（ADR-0010）。
- 各キーの出所区分（`Builtin` / `EnvLocked` / `DbManaged`）と説明は `domain/system_setting.rs` の
  `RUNTIME_SETTING_DEFINITIONS` を単一の出所として集中管理する。

新しい設定キーを追加する場合：

1. `domain/system_setting.rs` — `RUNTIME_SETTING_DEFINITIONS` に定義（出所区分・既定値・型・**用途の説明**）を追加
2. `src/config.rs` — 設定項目（getter）と読み込みロジックを追加
3. DB 上書き対応が必要なら `owner: DbManaged` とする（`EnvLocked` は DB を無視して ENV > 既定値）

---

## API 設計（axum）

- serde DTO から直接 Domain モデルを生成しない（Application 層で変換）。
- ルーティングは axum の **`Router`** を使い、`presentation/router.rs` で `.merge()` / `.nest()` により集約する。

**スキーマ命名規則**: `〇〇Request`（`serde::Deserialize`） / `〇〇Response`（`serde::Serialize`）

**配置先**:
- `presentation` 全体で使う共通 DTO → `src/presentation/dto.rs`
- 特定コンテキスト固有の DTO → 該当モジュール内

**ハンドラ定義**: リクエストボディ・パスパラメータは extractor（`Json` / `Path` / `Form` / `Query`）で受け取り、依存は `State` / `Extension` で注入する。OpenAPI は `utoipa` の属性から自動生成する。

```rust
async fn create_example(
    State(service): State<ExampleService>,
    Json(body): Json<ExampleRequest>,
) -> Result<Json<ExampleResponse>, ApiError> {
    ...
}
```

---

## 画面描画（web）

- **HTML はコード生成（`format!`）ではなく Askama テンプレートで描画する。** テンプレートは
  `crates/web/templates/` 配下の `.html`（共通レイアウトは `console/layout.html`）に置き、対応する
  テンプレート構造体を `crates/web/src/templates.rs` に `#[derive(Template)]` で定義する。ハンドラは
  構造体を組み立てて `templates::render(&t)` で文字列化する。
- **エスケープはテンプレート任せにする。** `.html` テンプレートの `{{ }}` 出力は自動 HTML エスケープ
  されるため、手動エスケープ関数を新設しない。生 HTML を差し込む `|safe` は原則使わず、共通レイアウトは
  `{% extends %}` / `{% block %}` の継承で組む。
- 翻訳文言はテンプレート内で `messages.get("キー")` を直接呼ぶ（i18n は下記）。
- 画面固有のパス・ラベル分岐はテンプレート側の `{% if %}` で表現し、ハンドラは値の受け渡しに徹する。

## 国際化（i18n）

- ログイン画面等のユーザー向け文言は翻訳リソースファイル（`fluent` の `.ftl`）で管理する。
- 新規メッセージは英語で定義し翻訳キーとして扱う。日本語訳は `ja` 用リソースに手動追記する。
- 対応言語は **日本語（`ja`）／英語（`en`）**。将来の言語追加（`zh`・`ko`・`fr` 等）を考慮した設計にする。

```
i18n/
  en/main.ftl
  ja/main.ftl
```

### 責務分離（Web が言語を決定し、API は `Accept-Language` のみ参照）

**表示言語の決定責任は web が持つ。** web は決定した言語を `Accept-Language` ヘッダで API へ引き継ぐ。
API は `Accept-Language` のみからレスポンス言語を決め、**Cookie・Session・URL クエリ・DB のユーザー設定を
見ない**（クライアント種別＝Web/モバイル/CLI に依存しない）。web と API は常に同一言語で動作する。

**web の言語決定順（先勝ち。不正・非対応値は無視して次順位へ）**:

| 優先 | 判定 | 用途 |
|---|---|---|
| 1 | URL クエリ `?lang=`（`ja`/`en`） | 一時切替 |
| 2 | ユーザー設定（ログインユーザーの `language`） | ログイン時は Cookie より優先 |
| 3 | Cookie（`lang`） | 未ログイン時の前回選択 |
| 4 | ブラウザ `Accept-Language` | 初回アクセスのみ |
| 5 | システム既定 `ja` | 終端フォールバック |

- 言語変更時・初回（ブラウザ言語採用時）に Cookie `lang` を保存する。ログイン済みユーザーが変更したら
  ユーザー設定（`users.language`、`ja`/`en`）にも保存する。
- web → API 呼び出しでは決定言語を `Accept-Language` に載せる。**Cookie・`lang` クエリは API へ送らない。**

**API の言語判定**:

- `Accept-Language` のみを参照し、終端フォールバックは既定 `ja`。
- 地域コードは無視して言語コードのみで判定する（`ja-JP`→`ja`、`en-US`/`en-GB`→`en`）。
- 非対応言語（例 `fr`）・未指定は既定 `ja` にフォールバックする。

### 多言語化の対象範囲

- **対象**: ユーザー向けメッセージすべて — エラー・バリデーション・業務メッセージを含む。API が返す
  エラーは `Accept-Language` に従い多言語化する。**エラーコードは言語不変**（固定値。`message` のみ翻訳）。
- **対象外**: 内部ログ・監査ログ・例外スタックトレース等の運用情報は多言語化せず**運用言語（英語）で統一**する
  （ログに PII を含めない方針は「## ログ」参照）。
- 文言はキー（例 `user.notFound`・`validation.required`）で管理し、言語ごとに翻訳リソースを用意する。
  将来的に翻訳管理システムや DB 管理へ移行できる構成にする。多言語**データ**（製品情報等）が必要になった場合は
  言語別の翻訳テーブルで対応する。

> 現状は i18n が web crate のみ（`fluent`、既定 `en`、画面文言限定）で API 側は未導入。上記の責務分離・
> 優先順位・API 多言語化・既定 `ja` への統一は目標設計であり、実装は `docs/Progress.md`（MT19・MT20）で追う。

---

## ログ

- すべてのログは **JSON 形式**で出力し（`tracing` + JSON subscriber）、同時に DB へ非同期書き込みする。
- ログには **PII を含めない**。ユーザー識別子は `id_hash`（およびハッシュ化した `sub`）のみ使用する。監査ログの詳細は `docs/OIDC_INPUT.md` §7 に従う。

| 出力先 | 追跡キー | 用途 |
|---|---|---|
| `log` テーブル | `correlation_id`（= requestId） | HTTP リクエスト単位 |
| `audit_log` テーブル | `correlation_id` | 監査イベント（login/code/token/client認証 等） |

`correlation_id` により「リクエスト → 処理 → 監査イベント」を一気通貫で追跡できる。
（Celery 等のワーカーは MVP 対象外。将来バックグラウンドジョブを導入する際は `worker_log` + `task_id` を追加する。）

時刻は常に UTC（`UTC_TIMESTAMP(6)`）。traceback フィールドは NULLABLE（例外時のみ記録）。

---

## テスト

```
tests/
  unit/         # 外部依存なし（Domain 中心。PKCE/JWT/ロック判定など）
  integration/  # DB・ネットワークを使う（sqlx + axum）
```

- `cargo test` で実行する。API の統合テストは `tower::ServiceExt::oneshot`（`TestClient` 相当）または `reqwest` を用いる。
- 外部リソース（SMTP 等）を要するテストは feature フラグまたは `#[ignore]` で既定除外する。
- 時刻・乱数・UUID はテスト内で固定する。実環境の時刻取得はトレイト（`Clock`）越しにし、テストで固定実装に差し替える。

---

## 動的呼び出しの制限

- 文字列でメソッド名・型名を渡して実行時に解決する動的ディスパッチは避け、**明示的なトレイト／enum によるインターフェース**を使う。
- 必要以上に `Box<dyn Any>` / ダウンキャスト（`Any::downcast`）に頼らない。多態が必要な箇所は用途を限定したトレイトオブジェクト、または enum で表現する。
