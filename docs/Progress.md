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
| 1 | MT1 | 初期 DDL 刷新: `tenants`（`is_root` 番兵列）・`tenant_memberships` 新設 + `users`/`clients`/`user_permissions`/`auth_sessions`/`audit_log` に `tenant_id`・`must_change_password`（既存データ破棄） | ⬜未着手 | 大 | 中 | Opus 4.8 |
| 2 | MT2 | root テナントを UUIDv7 で動的採番 seed + `idp.system.admin` scope=root の CHECK を投入時付与（`PREPARE`/`EXECUTE`）+ 権限コード・初期管理者 seed | ⬜未着手 | 大 | 小 | Opus 4.8 |
| 3 | MT3 | UUIDv7 導入（`uuid` crate に `v7`、生成を `IdGenerator` 相当へ集約。揮発トークンは v4 維持） | ⬜未着手 | 中 | 小 | Sonnet 5 |
| 4 | MT4 | `Tenant`/`TenantMembership` ドメインモデル + Repository trait + `TenantContext`/`TenantScope` 値オブジェクト | ⬜未着手 | 中 | 中 | Sonnet 5 |
| 5 | MT5 | 全 Repository trait／ユースケースへ `tenant_id` 引数追加（テナント分離強制・広範囲波及） | ⬜未着手 | 大 | 大 | Opus 4.8 |
| 6 | MT6 | 汎用 TTL キャッシュ抽象（テナント解決／scope→権限解決で共用）+ `TenantResolver` middleware + `RequirePerms` 完全一致 scope 判定 | ⬜未着手 | 大 | 中 | Opus 4.8 |
| 7 | MT7 | per-tenant issuer 合成（基底 issuer + tenant_id）+ WebAuthn RP ID の基底ホスト分離 | ⬜未着手 | 大 | 中 | Opus 4.8 |
| 8 | MT8 | 招待ユースケース（招待作成・トークン一度限り返却・承諾・解除）+ OIDC フローのメンバーシップ判定（認証は所属元テナント限定） | ⬜未着手 | 大 | 中 | Opus 4.8 |
| 9 | MT9 | `/{tenant_id}/...` ルーティング（静的パス優先 + UUID 検証、静的アセットはテナント外） | ⬜未着手 | 中 | 中 | Sonnet 5 |
| 10 | MT10 | `crates/contracts` DTO へ `tenant_id` 追加 + web `api_client.rs` のテナント対応 | ⬜未着手 | 中 | 中 | Sonnet 5 |
| 11 | MT11 | 管理 API（`tenants`/`users`/`clients`/`members`/`invitations`）+ テナント作成時の管理者自動生成・パスワード自動生成・`must_change_password` 付与 | ⬜未着手 | 大 | 大 | Opus 4.8 |
| 12 | MT12 | パスワード変更（リセット）画面 + 初回ログイン時の強制変更誘導 | ⬜未着手 | 中 | 中 | Sonnet 5 |
| 13 | MT13 | テナント管理コンソール（`/{tenant_id}/admin/`）— ユーザー・クライアント・メンバー・招待管理 | ⬜未着手 | 中 | 大 | Sonnet 5 |
| 14 | MT14 | 設定画面（`/{tenant_id}/admin/settings`）— テナント設定 + root のみシステム設定区画（SMTP 等） | ⬜未着手 | 中 | 中 | Sonnet 5 |
| 15 | MT15 | ユーザー設定画面（`/{tenant_id}/settings`）— パスワード変更・MFA・言語設定 | ⬜未着手 | 小 | 中 | Sonnet 5 |
| 16 | MT16 | 統合テスト（テナント間分離・権限境界の完全一致・ゲスト保護・「root は作成できるが内部を操作できない」の検証） | ⬜未着手 | 大 | 中 | Opus 4.8 |
| 17 | MT17 | 招待のメール配送（MT14 の SMTP 設定完了後。手動トークン伝達 → メールリンク） | ⬜未着手 | 中 | 中 | Sonnet 5 |
| 18 | MT18 | セルフサービス・パスワードリセット（忘失時。外部 SMTP 連携。MT14 完了後） | ⬜未着手 | 中 | 中 | Sonnet 5 |

### 詳細

**推奨モデルの根拠（高リスク＝Opus 4.8）**:
- **MT1・MT2**: データ基盤と権限保証の要。`tenant_id` 設計・単一 root 担保・`idp.system.admin` の
  scope=root 縛りを誤ると分離・権限の前提が崩れる。ADR-0009 §1・§4・§11。
- **MT5**: 分離防御線（MariaDB に RLS がないためアプリ層が唯一）。全リポジトリ・ユースケースへ波及し、
  漏れがそのままテナント越境になる。ADR-0009 §8。
- **MT6・MT7**: 認可境界（完全一致判定）とトークン検証（per-tenant `iss`・WebAuthn RP ID）。
  判定・issuer 合成の誤りは越権・トークン流用に直結。ADR-0009 §4・§6・§7。
- **MT8**: クロステナント参加の境界。ゲストのユーザー状態保護・認証を所属元に限定する要。ADR-0009 §3・§8。
- **MT11**: 権限操作 API と自動生成パスワード/招待トークンの一度限り返却（ログ・監査へ出さない）。
  ADR-0009 §4・§5。
- **MT16**: これらの保証を検証するテスト自体が保証の一部（negative test 必須）。ADR-0009 §8。

**中リスク／定型（Sonnet 5）**: MT3・MT4・MT9・MT10・MT12〜MT15・MT17・MT18。仕様が ADR で明確で、
Askama テンプレート・`api_client` 等の確立パターンに沿う機能実装。ただし MT15（MFA）・MT12
（パスワード）はセキュリティ機微を含むため、実装後に §テスト・`/security-review` を併用する。

**依存関係**: MT1〜MT3（Phase 1）→ MT4〜MT8（Phase 2）→ MT9〜MT16（Phase 3）。MT17・MT18 は
MT14 のシステム設定（SMTP）完了が前提。
