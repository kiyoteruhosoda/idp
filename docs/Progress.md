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
| **41.7** | CFG1 | 設定値の出所・優先順位・DB 反映を一元化する | 大 (3) | 大 (5) | 大 (5) | 大 (5) |
| **37.5** | TEST1 | DB 統合・E2E・構成検証をスキップ不能な CI にする | 中 (2) | 大 (5) | 大 (5) | 中 (3) |
| **25.0** | OPS1 | `deploy.sh app/migration/reset` とゼロタッチ初期配置を実装する | 大 (3) | 大 (5) | 中 (3) | 大 (5) |
| **22.5** | UI1 | 設定画面に危険な初期値と現在の設定元を表示する | 中 (2) | 中 (3) | 大 (5) | 中 (3) |
| **15.0** | SEC1 | Compose の DB 公開とコンテナ権限を本番向けに制限する | 小 (1) | 中 (3) | 大 (5) | 小 (1) |
| **13.5** | REL1 | デプロイ時の stale イメージ再利用を防ぎ成果物を検証する | 中 (2) | 中 (3) | 中 (3) | 中 (3) |
| **9.0** | LOG1 | 起動・デプロイ失敗時に原因ログを自動表示する | 小 (1) | 中 (3) | 中 (3) | 小 (1) |
| **8.3** | DDD1 | Application 層から Infrastructure 具象依存を除去する | 大 (3) | 大 (5) | 小 (1) | 大 (5) |

### CFG1: 設定値の出所・優先順位・DB 反映を一元化する

**問題**: `Config` のコメントは「環境変数 > DB > 既定値」だが、DB 上書きは未実装で、DB が扱うのは
SMTP 設定だけである。また Compose は `CSRF_SECRET`、各種 TTL、`TRUST_FORWARDED_HEADERS`、
`HSTS_MAX_AGE`、`PUBLIC_WEB_BASE_URL` など `Config` が対応する値をコンテナへ渡していない。
`.env` に記載しても反映されない設定があり、設定画面から値の出所を説明できない。

**実装詳細**（ADR-0010）:

- 設定キーごとに `BUILTIN` / `ENV_LOCKED` / `DB_MANAGED` の出所と、秘密値・再起動要否・既定値の
  危険度をメタデータとして一元管理する。api/web/Compose/設定画面で別々の一覧を持たない。
- `.env` のオペレーター固定領域は通常の deploy と DB 反映で上書きしない。DB 管理を明示したキーだけを
  `.env` の自動生成領域へ materialize し、次回のコンテナ再作成へ反映する。
- `reset` は DB と自動生成領域を破棄するが、オペレーター固定領域は保持する。DB が扱えない bootstrap
  secret（DB 認証・鍵暗号化キー等）は DB 管理対象にしない。
- Compose の api/web へ、実装済み `Config` が受け付ける全キーを適切なサービスに注入する。
- DB 書込、`.env` materialize、再起動の途中失敗で半端な状態を残さない。秘密値は API 応答・ログへ
  平文出力せず、変更操作を監査ログへ記録する。
- 解決順序、DB 反映、reset 後の復元、api/web 間で共有する値の一致を自動テストする。

### TEST1: DB 統合・E2E・構成検証をスキップ不能な CI にする

**問題**: GitHub Actions がなく、`cargo test` は `TEST_DATABASE_URL` 未設定時に DB 統合テストを
成功扱いで早期 return する。`build.sh --check` だけではスキーマ、テナント分離、OIDC フローが一件も
実行されなくても成功する。運用スクリプトと Compose の自動テストもない。

**実装詳細**:

- CI で MariaDB を起動し、`cargo fmt --check`、`clippy -D warnings`、unit、DB integration、
  `scripts/e2e.sh`、Docker build、`docker compose config` を必須チェックとして実行する。
- CI/`--check` モードでは `TEST_DATABASE_URL` が無ければ skip ではなく失敗させる。開発者が意図して
  DB テストだけを省略するコマンドは別名にする。
- `init`、`deploy app`、`deploy migration`、`deploy reset`、既存 `.env` 非上書き、失敗時ログ表示を、
  Docker コマンドを stub 化したシェルテストまたは隔離 Compose E2E で検証する。
- 依存関係監査（Rust advisory DB）と、秘密情報がリポジトリ／イメージへ混入していない検査を追加する。

### OPS1: `deploy.sh app/migration/reset` とゼロタッチ初期配置を実装する

**問題**: 現在の `deploy.sh` は引数を受け取らず毎回 migration と app 再起動を行う。`reset` がなく、
初回は別途 `init.sh` を知って実行しなければならないため、要求された 3 モードと「初期配置から何も設定せず
ログイン画面表示」を満たさない。

**実装詳細**:

- `deploy.sh app` は DB を保持して api/web/proxy のみ更新、`deploy.sh migration` は DB 起動と migration
  のみ、`deploy.sh reset` は明示確認付きで DB volume・DB 管理設定を破棄して再初期化する。
- `.env` が無ければ deploy がテンプレートから作成し、DB password、root password、
  `KEY_ENCRYPTION_KEY`、`INTERNAL_SERVICE_TOKEN`、`CSRF_SECRET` を連動する安全な乱数で生成する。
  既存 `.env` のオペレーター固定領域は上書きしない。
- 引数なし・未知引数は usage と終了コード 2 を返す。`reset` は対話不可の自動実行向けに明示的な
  `--yes` を要求し、対象 Compose project/volume を表示してから削除する。
- 初回 `app` 実行時は必要なら migration まで行い、root tenant UUID を含む実在するログイン URL を表示する。
  `init.sh` は互換ラッパーにするか廃止し、入口を `deploy.sh` に一本化する。

### UI1: 設定画面に危険な初期値と現在の設定元を表示する

**問題**: api は一部の開発用 secret 使用をログ警告するだけで、設定画面は SMTP とテナント設定しか
表示しない。固定初期管理者、既知の CSRF secret、HTTP/Cookie/HSTS、未変更の Redis password など、
危険な初期状態であることと、値が built-in/.env/DB のどれに由来するかを画面で確認できない。

**実装詳細**:

- root の設定画面に、設定名、現在の出所、状態（安全／要対応）、理由、再起動要否を表示する。
- secret は値を返さず「自動生成済み／既定値／未設定／不一致」のみ返す。api と web の共有 secret は
  fingerprint の定数時間比較等で一致だけを判定し、平文・fingerprint 自体を画面やログへ出さない。
- 少なくとも初期管理者のパスワード変更未完了、開発用 key/token/CSRF、`COOKIE_SECURE=false`、
  `HSTS_MAX_AGE=0`、SMTP 未設定を判定する。環境用途により許容できる項目は、根拠を表示して抑制可能にする。
- 判定 API の root 限定認可、HTML escape、secret 非露出、表示条件を統合テストする。

### SEC1: Compose の DB 公開とコンテナ権限を本番向けに制限する

**問題**: `docker-compose.deploy.yml` の MariaDB は既定で `0.0.0.0:3306` に publish される。DB は
個人情報・認証情報を保持するため、アプリだけを公開する通常構成では不要な攻撃面になる。

**実装詳細**:

- deploy 用 Compose では MariaDB をホストへ publish しない。保守用接続は `docker compose exec` を標準にし、
  必要時だけ loopback bind の override profile を使う。開発用 Compose も既定は `127.0.0.1` bind とする。
- api/web/proxy/mariadb に適切な `restart` policy を設定し、可能なサービスへ `read_only`、`tmpfs`、
  `no-new-privileges`、capability drop、resource limit を適用する。互換性を Compose E2E で確認する。

### REL1: デプロイ時の stale イメージ再利用を防ぎ成果物を検証する

**問題**: `ensure_images` は同名タグがローカルに存在すると pull しない。`IMAGE_TAG=latest` の通常設定では、
新しいイメージを push 済みでも古いローカルイメージを再起動して deploy 成功となり得る。tar 成果物にも
checksum／commit の対応表がない。

**実装詳細**:

- レジストリ方式は immutable tag または digest を要求し、deploy 時に明示 pull して期待 digest と一致確認する。
- `build.sh --save` は api/web/migrate の tar、SHA-256、Git commit、バージョンを manifest に出力する。
  deploy は Pick 済み成果物の manifest とローカル image ID を照合してから更新する。
- ビルド済み 3 イメージが同一ソース commit 由来であることをラベルで検証し、実際に配置した digest をログへ残す。

### LOG1: 起動・デプロイ失敗時に原因ログを自動表示する

**問題**: `wait_healthy` は失敗時に `docker compose ... logs` という確認コマンドを文字列で案内するだけで、
ログ自体を表示しない。`docker pull` の stderr も捨てるため、起動前・イメージ取得・healthcheck 失敗の原因を
その場で特定できない。

**実装詳細**:

- ERR trap と共通診断関数を追加し、失敗した phase、終了コード、Compose `ps`、対象サービスの末尾ログ、
  health status、実行中 image digest を stderr へ自動表示する。
- pull/migration の標準エラーを保持しつつ secret をマスクする。ログ取得自体の失敗で元の終了コードを失わない。
- 正常時は phase 単位の開始／完了と所要時間を出し、`--verbose` 以外では過剰なログを抑える。

### DDD1: Application 層から Infrastructure 具象依存を除去する

**問題**: `domain/repositories.rs` は「Application 層は trait のみに依存」と定義している一方、Application の
多数のユースケースが `infrastructure::crypto`、`infrastructure::jwt`、`WebAuthnService` を直接 import している。
暗号・トークン・乱数・WebAuthn の実装差替えが難しく、DDD/DIP の記載と実装が一致しない。

**実装詳細**:

- Domain/Application 側に `TokenGenerator`、`TokenCodec`、`SecretCipher`、`WebAuthnPort` 等の必要最小限の port を置き、
  Infrastructure が実装する。composition root (`AppState::build`) だけが具象型を選ぶ。
- 文字列や巨大な万能 trait ではなく、ユースケース単位の小さな interface と value object を使う。
- 既存の暗号テストベクタ・OIDC 統合テストを維持し、Application の unit test は Infrastructure なしで実行可能にする。
