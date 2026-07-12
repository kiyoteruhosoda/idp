# Progress

進行中・未着手タスクのみを管理する（完了したら本ファイルから削除し、必要なら `CHANGELOG.md` / `history/` へ）。

タスクは改訂後 ADR-0009（テナント独立・Entra ID 型 / UUIDv7 / 完全一致 scope / 初期 DDL 刷新）の
Phase 計画に沿う。

## 推奨モデルの基準

各タスクの **難易度（工数）× リスク（影響度）** で Claude モデルを割り当てる。リスクは
「テナント分離・認可境界・トークン検証・自動生成シークレット・データ基盤の整合」を重く見る。

| モデル | 割り当て基準 |
|---|---|
| **Opus 4.8** | 高リスク（セキュリティ境界・分離防御線・保証の要）または高難度（広範囲波及・設計判断を伴う） |
| **Sonnet 5** | 仕様が明確な機能実装・中程度の面。標準的な難度で判断も限定的 |
| **Haiku 4.5** | 定型・低リスク（確立パターンの反復、限定的な UI・文言・設定） |

## バックログ

SEC = MT16 完了時のセキュリティレビュー指摘、REF = 同リファクタ候補（いずれも 2026-07-12）。
認可境界に実害があるもの・本番事故を防ぐもの・後続タスク全部に効くもの（テスト基盤・トランザクション境界）を
機能追加（MT17 以降）より先に置く。

| 優先 | # | 概要 | 状態 | 影響度 | 工数 | 推奨モデル |
|---|---|---|---|---|---|---|
| 14 | REF3 | 認可ホットパスの整理 — SSO セッション解決（hash→取得→有効性→ユーザー有効）が `AdminAccessService::authorize`／`authenticated_user`／`try_resume_sso` に三重実装。共通のセッション解決サービスへ抽出し、`has_permission` 2 回問い合わせも `IN (?, ?)` の `has_any_permission` 1 回に統合。権限コード定数（`idp.system.admin` 等）の散在も `domain::permission` へ集約 | ⬜未着手 | 中 | 中 | Sonnet 5 |
| 15 | SEC7 | ログイン/同意 CSRF トークンの HMAC 化 — 現状 `sha256("csrf:" + auth_session_id)` でサーバシークレット不使用（保護対象と同じ秘密からの導出）。サーバ側キーの HMAC へ（web/api 共有のため `idp-contracts` の導出を差し替え） | ⬜未着手 | 小 | 小 | Sonnet 5 |
| 16 | REF4 | 小粒の重複解消 — ①`InvitationError`/`PermissionManagementError`→`ApiError` マッピングのハンドラ間コピー（`impl From` へ集約）②`validate_email` の三重定義（`EmailAddress` 値オブジェクトへ）③`list_members` の N+1（JOIN 一括取得）④`ensure_user_in_tenant` と `get_user` の同文重複 | ⬜未着手 | 小 | 小 | Haiku 4.5 |

> MT14・MT15・MT19・MT20 は完了（`docs/CHANGELOG.md` 参照）。

### 詳細

**推奨モデルの根拠（高リスク＝Opus 4.8）**: 認可境界（ADR-0009 §3・§4 の「権限保有はメンバーシップを
含意する」という保証）の要に触れるタスクは Opus を割り当てる（SEC1・REF2・GAP1 は完了。
`docs/CHANGELOG.md` 参照）。

**SEC/REF の出所**: MT16 完了時（2026-07-12）の全体セキュリティレビュー・リファクタ棚卸し。
検証済みの前提（良い点）は `docs/CHANGELOG.md` の MT16 項を参照。SEC 系の再検証には
`crates/api/tests/tenant_isolation.rs` の negative test 群と `/security-review` を使う。

**中リスク／定型（Sonnet 5）**: REF3 等。仕様が ADR・既存基盤で明確で、
Askama テンプレート・`api_client` 等の確立パターンに沿う機能実装。MT15（セルフサービスの
パスワード変更）はセキュリティ機微を含むため、実装後に §テスト・`/security-review` を併用する
（今回は SSO 解決 → 現行パスワード再検証 → 強度検証の経路を追加。他セッション失効は行っていない）。

**依存関係**: Phase 2（MT6〜MT8）・MT9〜MT20・SEC6・SEC6b（Phase 3）は完了（`docs/CHANGELOG.md` 参照）。
メール配送基盤（`Mailer`・`SystemSettingsService::smtp_server`）は MT17/MT18/SEC6b で確立済み。
