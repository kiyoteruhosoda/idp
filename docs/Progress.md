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
| 7 | REF2 | ユースケースのトランザクション境界導入 — `create_tenant` は tenant INSERT → 管理者作成 → 権限付与を個別実行し、途中失敗で管理者のいないテナントが残り得る。unit of work を導入し、SEC1 の後始末とあわせて整合を保証する | ⬜未着手 | 中 | 中 | Opus 4.8 |
| 8 | MT17 | 招待のメール配送（MT14 の SMTP 設定完了済み。手動トークン伝達 → メールリンク） | ⬜未着手 | 中 | 中 | Sonnet 5 |
| 9 | MT18 | セルフサービス・パスワードリセット（忘失時。外部 SMTP 連携。MT14 完了済み） | ⬜未着手 | 中 | 中 | Sonnet 5 |
| 10 | SEC6 | 自己登録（`/{tenant_id}/auth/register`）の制御 — 全テナントで無条件開放・レート制限なし・メール検証なしで ACTIVE アカウントを作成でき、409 応答でテナント内のメール存在が列挙可能。テナント設定で有効/無効を切替（既定 OFF 推奨）＋レート制限。メール検証は MT17 の SMTP 基盤に乗せる | ⬜未着手 | 中 | 中 | Sonnet 5 |
| 11 | MT19 | API の `Accept-Language` ベース多言語化（i18n 仕様書 §5・§6）— API は `Accept-Language` のみ参照（Cookie/Session/クエリ/DB を見ない）。地域コード無視（`en-US`→`en`）、非対応言語・未指定はシステム既定 `ja`。エラー／バリデーション／業務メッセージをキー管理で多言語化（コードは言語不変）。運用ログ・監査ログ・スタックトレースは対象外（英語統一） | ⬜未着手 | 中 | 大 | Sonnet 5 |
| 12 | MT20 | Web の表示言語決定チェーン（i18n 仕様書 §3・§4・§9）— 優先順位 `?lang=` → ユーザー設定 → Cookie（`lang`）→ ブラウザ `Accept-Language` → 既定 `ja`。不正値は次順位へフォールバック。言語変更時／初回に Cookie 保存、ログイン時はユーザー設定優先。決定言語を API へ `Accept-Language` で伝搬（Cookie・`lang` クエリは送らない）。ユーザー設定 `language` 列（ja/en）を追加。将来言語追加（zh/ko/fr 等）を考慮 | ⬜未着手 | 中 | 大 | Sonnet 5 |
| 13 | GAP1 | ゲストへの権限付与の ADR 乖離解消 — ADR-0009 §4 は「付与対象は当該テナントのメンバー（HOME/GUEST）」だが、`ensure_user_in_tenant` が所属元限定のため GUEST へ付与できない。付与対象を「HOME または ACTIVE な GUEST」に広げるか、ADR を現状に合わせるかの設計判断 | 🟡要判断 | 中 | 小 | Opus 4.8 |
| 14 | REF3 | 認可ホットパスの整理 — SSO セッション解決（hash→取得→有効性→ユーザー有効）が `AdminAccessService::authorize`／`authenticated_user`／`try_resume_sso` に三重実装。共通のセッション解決サービスへ抽出し、`has_permission` 2 回問い合わせも `IN (?, ?)` の `has_any_permission` 1 回に統合。権限コード定数（`idp.system.admin` 等）の散在も `domain::permission` へ集約 | ⬜未着手 | 中 | 中 | Sonnet 5 |
| 15 | SEC7 | ログイン/同意 CSRF トークンの HMAC 化 — 現状 `sha256("csrf:" + auth_session_id)` でサーバシークレット不使用（保護対象と同じ秘密からの導出）。サーバ側キーの HMAC へ（web/api 共有のため `idp-contracts` の導出を差し替え） | ⬜未着手 | 小 | 小 | Sonnet 5 |
| 16 | REF4 | 小粒の重複解消 — ①`InvitationError`/`PermissionManagementError`→`ApiError` マッピングのハンドラ間コピー（`impl From` へ集約）②`validate_email` の三重定義（`EmailAddress` 値オブジェクトへ）③`list_members` の N+1（JOIN 一括取得）④`ensure_user_in_tenant` と `get_user` の同文重複 | ⬜未着手 | 小 | 小 | Haiku 4.5 |

> MT14・MT15 は完了（`docs/CHANGELOG.md` 参照）。MT15 の言語設定は現状 **`lang` Cookie 保存 + `/settings`
> 画面での `?lang=`／Cookie 反映**まで（決定チェーンの優先度1・3）。全画面への決定チェーン統一・
> ユーザー設定 `language` 列（優先度2）・システム既定 `ja` への統一は MT20 の範囲として残る。

### 詳細

**推奨モデルの根拠（高リスク＝Opus 4.8）**: SEC1・REF2・GAP1 は認可境界（ADR-0009 §3・§4 の
「権限保有はメンバーシップを含意する」という保証）とデータ整合の要に触れるため Opus を割り当てる。
SEC1 と REF2 は同じトランザクション境界の話であり、まとめて 1 ブランチで実装してよい
（先に SEC1 の一括 revoke + 順序修正、その足場で REF2 の unit of work を導入）。

**SEC/REF の出所**: MT16 完了時（2026-07-12）の全体セキュリティレビュー・リファクタ棚卸し。
検証済みの前提（良い点）は `docs/CHANGELOG.md` の MT16 項を参照。SEC 系の再検証には
`crates/api/tests/tenant_isolation.rs` の negative test 群と `/security-review` を使う。

**中リスク／定型（Sonnet 5）**: MT17・MT18。仕様が ADR で明確で、
Askama テンプレート・`api_client` 等の確立パターンに沿う機能実装。MT15（セルフサービスの
パスワード変更）はセキュリティ機微を含むため、実装後に §テスト・`/security-review` を併用する
（今回は SSO 解決 → 現行パスワード再検証 → 強度検証の経路を追加。他セッション失効は行っていない）。

**依存関係**: Phase 2（MT6〜MT8）・MT9〜MT16（Phase 3）は完了（`docs/CHANGELOG.md` 参照）。
MT17・MT18 の前提だった MT14 のシステム設定（SMTP）は完了済み（`SystemSettingsService::get_smtp`
が消費側の入口）。

**i18n 仕様書（MT19・MT20）の現状ギャップと注意点**:
- **現状**: i18n は **web crate のみ**（`fluent`、`crates/web/src/i18n.rs`、`i18n/<lang>/main.ftl`）。言語決定は
  **`Accept-Language` のみ**・**既定 `En`**・対象は**ログイン画面等の画面文言のみ**。API 側は i18n 未導入で、
  エラーメッセージは多言語化されていない。
- **既定言語の変更**: 仕様書はシステム既定を **`ja`** と定める（現状の実装既定 `En` から変更）。MT19・MT20 で
  フォールバック終端を `ja` に統一する。
- **責務分離**: Web（MT20）が優先順位チェーンで表示言語を**決定**し、決定結果のみを `Accept-Language` で
  API へ渡す。API（MT19）は `Accept-Language` だけを見てレスポンスを生成し、クライアント種別
  （Web/モバイル/CLI）に依存しない。両者は常に同一言語で動作する。
- **関連**: MT15（ユーザー設定画面の言語設定 UI）は完了。現状は `lang` Cookie 保存 + `/settings` 画面での
  `?lang=`／Cookie 反映まで（`Locale::resolve`）。MT20 で**ユーザー設定 `language` 列**（優先度2）を追加し、
  全画面へ決定チェーンを適用する。`language` 列追加は sqlx マイグレーション（`.claude/skills/db-migration/`）で行う。
- 製品情報のような多言語**データ**が必要になった場合は翻訳テーブル（例: `ProductTranslation`）で対応する
  想定だが、現行スコープ（ユーザー向けメッセージの多言語化）には含めない。
