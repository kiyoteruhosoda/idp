# migrations

sqlx マイグレーション（MariaDB）を管理する。

- ファイル名: `<version>_<description>.sql`（reversible 運用時は `.up.sql` / `.down.sql` を対で用意）。
- `version` は sqlx が採番する連番（タイムスタンプ）。この version が
  スキーマ・マスタデータのバージョン整合性の SSOT（`_sqlx_migrations` テーブル）。
- 適用: `sqlx migrate run`（アプリ起動時には**適用しない**。起動時は「DB が期待 version 以上か」を
  照合するのみ ＝ fail-fast。詳細は `docs/adr/0004-schema-version-sync.md`）。
- 規約: DB ネイティブ ENUM 禁止（`VARCHAR` + `CHECK`）、UUID は `CHAR(36)`（エンティティ主キーは
  UUIDv7・揮発トークンは v4。ADR-0009 §12）、時刻は UTC の `DATETIME(6)`。
  詳細は `.claude/skills/db-migration/` と `CLAUDE.md`「DB モデリング」を参照。
- マスタデータ（root テナント・権限コード・初期管理ユーザー等）も冪等 upsert のマイグレーション
  として書く。単一の出所は当該 seed マイグレーション自身とし、値を他所へ重複させない。

> **注意（ADR-0009 §11 の一度限りの刷新）**: マルチテナント対応で初期 DDL・マスタデータを全面的に
> 作り直した（既存データは破棄・全環境 DB 再作成。手順は `docs/OPERATIONS.md`「DB を作り直したいとき」）。
> 刷新後は従来どおり追記型マイグレーション（expand/contract・up/down 対・冪等 seed）に戻る。
> ベースラインの書き換えは以後行わない。

現行のマイグレーション:

- `0001_baseline`: マルチテナント対応の全テーブル（ADR-0009）。`tenants`（`is_root` 番兵列 +
  単一 root UNIQUE）・`tenant_memberships`・`users`（`tenant_id`・`must_change_password`）・
  `clients`（テナント内一意の `client_id`）・`permissions`・`user_permissions`（scope = `tenant_id`）・
  `auth_sessions` / `authorization_codes` / `refresh_tokens` / `client_consents`
  （`(tenant_id, client_id)` 複合外部キー）・`sso_sessions`（ホスト共有のため tenant なし）・
  `signing_keys`・`revoked_access_tokens`・`user_totp_secrets`・`user_webauthn_credentials`・
  `passkey_challenges`・`audit_log`（`tenant_id` 追跡列）。
- `0002_seed_master_data`: マスタデータ seed（冪等）。root テナント（UUIDv7 を**投入時に動的採番**。
  固定リテラルなし）、`idp.system.admin` の scope = root を縛る CHECK 制約（解決済み root UUID を
  リテラル化して `PREPARE`/`EXECUTE` で付与。ファイル自体は静的でチェックサムは全環境一致）、
  権限コード（`idp.system.admin` / `idp.tenant.admin`）、初期管理者 `admin@example.com`
  （root 所属・HOME メンバーシップ・`must_change_password = 1`・`idp.system.admin` を DB 直接付与）。
- `0009_default_admin_password`: 初期管理者 `admin@example.com` の既定パスワードを、メールアドレスと
  同じ `admin@example.com` へ更新する（0002 の旧既定 `ChangeMe!123` のままの行に限定。変更済み
  パスワードは上書きしない）。追記型のため 0002 は書き換えず、本マイグレーションで更新する。
- `0012_rename_root_tenant`: root テナントの既定表示名を `Root` から `ROOT` へ更新する（0002 の seed
  既定 `Root` のままの行に限定。運用者が別名へ変更した行は上書きしない）。追記型のため 0002 は
  書き換えず、本マイグレーションで更新する。

root テナントの UUID は環境ごとに異なる。確認手順は `docs/OPERATIONS.md`
「root テナントの UUID を確認したいとき」を参照。
