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

| 優先 | # | 概要 | 状態 | 影響度 | 工数 | 推奨モデル |
|---|---|---|---|---|---|---|
| 1 | MT9 | `/{tenant_id}/...` ルーティング（静的パス優先 + UUID 検証、静的アセットはテナント外）+ MT6 の `TenantResolver` middleware を mount し `RequirePerms`・OIDC 各ハンドラの要求テナントをパス由来へ | ⬜未着手 | 中 | 中 | Sonnet 5 |
| 2 | MT10 | `crates/contracts` DTO へ `tenant_id` 追加 + web `api_client.rs` のテナント対応 | ⬜未着手 | 中 | 中 | Sonnet 5 |
| 3 | MT11 | 管理 API（`tenants`/`users`/`clients`/`members`/`invitations`）+ テナント作成時の管理者自動生成・パスワード自動生成・`must_change_password` 付与 | ⬜未着手 | 大 | 大 | Opus 4.8 |
| 4 | MT12 | パスワード変更（リセット）画面 + 初回ログイン時の強制変更誘導 | ⬜未着手 | 中 | 中 | Sonnet 5 |
| 5 | MT13 | テナント管理コンソール（`/{tenant_id}/admin/`）— ユーザー・クライアント・メンバー・招待管理 | ⬜未着手 | 中 | 大 | Sonnet 5 |
| 6 | MT14 | 設定画面（`/{tenant_id}/admin/settings`）— テナント設定 + root のみシステム設定区画（SMTP 等） | ⬜未着手 | 中 | 中 | Sonnet 5 |
| 7 | MT15 | ユーザー設定画面（`/{tenant_id}/settings`）— パスワード変更・MFA・言語設定 | ⬜未着手 | 小 | 中 | Sonnet 5 |
| 8 | MT16 | 統合テスト（テナント間分離・権限境界の完全一致・ゲスト保護・「root は作成できるが内部を操作できない」の検証） | ⬜未着手 | 大 | 中 | Opus 4.8 |
| 9 | MT17 | 招待のメール配送（MT14 の SMTP 設定完了後。手動トークン伝達 → メールリンク） | ⬜未着手 | 中 | 中 | Sonnet 5 |
| 10 | MT18 | セルフサービス・パスワードリセット（忘失時。外部 SMTP 連携。MT14 完了後） | ⬜未着手 | 中 | 中 | Sonnet 5 |

### 詳細

**推奨モデルの根拠（高リスク＝Opus 4.8）**:
- **MT11**: 権限操作 API と自動生成パスワード/招待トークンの一度限り返却（ログ・監査へ出さない）。
  ADR-0009 §4・§5。（Phase 2 の MT6〜MT8＝キャッシュ／解決基盤・per-tenant issuer・招待
  ユースケース／メンバーシップ判定は完了。）
- **MT16**: これらの保証を検証するテスト自体が保証の一部（negative test 必須）。ADR-0009 §8。

**中リスク／定型（Sonnet 5）**: MT9・MT10・MT12〜MT15・MT17・MT18。仕様が ADR で明確で、
Askama テンプレート・`api_client` 等の確立パターンに沿う機能実装。ただし MT15（MFA）・MT12
（パスワード）はセキュリティ機微を含むため、実装後に §テスト・`/security-review` を併用する。

**依存関係**: Phase 2（MT6〜MT8）完了 → MT9〜MT16（Phase 3）。MT17・MT18 は
MT14 のシステム設定（SMTP）完了が前提。

**過渡期の既知の状態（Phase 2 完了 → MT9 まで）**: Repository trait・ユースケースは `tenant_id`／
`TenantContext` を必須で受け取る。MT6（汎用 TTL キャッシュ・`TenantResolver` middleware・権限解決の
キャッシュ化）・MT7（per-tenant issuer 合成・WebAuthn RP ID の基底ホスト分離）・MT8（招待
ユースケース・OIDC フローのメンバーシップ判定）を実装済みで、いずれも `AppState`（`tenant_resolution`／
`invitations`）へ配線済み。ただし `/{tenant_id}/...` ルーティング（MT9）が未導入のため、
`TenantResolver` middleware はまだルーターへ mount しておらず、招待の HTTP エンドポイントも未追加
（MT11）。api は引き続き起動時に解決した **root テナントを既定テナント**（`AppState::default_tenant`）
として全リクエストへ適用し、issuer もそのテナントで合成する（`iss` = `<基底>/<root_uuid>`）。
MT9 で middleware をテナントルート群へ付与し、`RequirePerms`・OIDC 各ハンドラの要求テナントを
リクエストパス由来の `Extension<ResolvedTenant>` に置き換える。
