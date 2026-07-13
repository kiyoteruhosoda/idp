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
| **22.5** | UI1 | 設定画面に危険な初期値と現在の設定元を表示する | 中 (2) | 中 (3) | 大 (5) | 中 (3) |
| **13.5** | REL1 | デプロイ時の stale イメージ再利用を防ぎ成果物を検証する | 中 (2) | 中 (3) | 中 (3) | 中 (3) |
| **8.3** | DDD1 | Application 層から Infrastructure 具象依存を除去する | 大 (3) | 大 (5) | 小 (1) | 大 (5) |

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

### REL1: デプロイ時の stale イメージ再利用を防ぎ成果物を検証する

**問題**: `ensure_images` は同名タグがローカルに存在すると pull しない。`IMAGE_TAG=latest` の通常設定では、
新しいイメージを push 済みでも古いローカルイメージを再起動して deploy 成功となり得る。tar 成果物にも
checksum／commit の対応表がない。

**実装詳細**:

- レジストリ方式は immutable tag または digest を要求し、deploy 時に明示 pull して期待 digest と一致確認する。
- `build.sh --save` は api/web/migrate の tar、SHA-256、Git commit、バージョンを manifest に出力する。
  deploy は Pick 済み成果物の manifest とローカル image ID を照合してから更新する。
- ビルド済み 3 イメージが同一ソース commit 由来であることをラベルで検証し、実際に配置した digest をログへ残す。

### DDD1: Application 層から Infrastructure 具象依存を除去する

**問題**: `domain/repositories.rs` は「Application 層は trait のみに依存」と定義している一方、Application の
多数のユースケースが `infrastructure::crypto`、`infrastructure::jwt`、`WebAuthnService` を直接 import している。
暗号・トークン・乱数・WebAuthn の実装差替えが難しく、DDD/DIP の記載と実装が一致しない。

**実装詳細**:

- Domain/Application 側に `TokenGenerator`、`TokenCodec`、`SecretCipher`、`WebAuthnPort` 等の必要最小限の port を置き、
  Infrastructure が実装する。composition root (`AppState::build`) だけが具象型を選ぶ。
- 文字列や巨大な万能 trait ではなく、ユースケース単位の小さな interface と value object を使う。
- 既存の暗号テストベクタ・OIDC 統合テストを維持し、Application の unit test は Infrastructure なしで実行可能にする。
