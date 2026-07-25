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
- `0002_seed_master_data`: マスタデータ seed（冪等）。root テナント（**固定 UUID**
  `00000000-0000-7000-8000-000000000001`。全環境共通で git 管理する。ADR-0011）、
  `idp.system.admin` の scope = root を縛る CHECK 制約（固定 root UUID を
  リテラル化して `PREPARE`/`EXECUTE` で付与）、
  権限コード（`idp.system.admin` / `idp.tenant.admin`）、初期管理者 `admin@example.com`
  （root 所属・HOME メンバーシップ・`must_change_password = 1`・`idp.system.admin` を DB 直接付与）。
- `0009_default_admin_password`: 初期管理者 `admin@example.com` の既定パスワードを、メールアドレスと
  同じ `admin@example.com` へ更新する（0002 の旧既定 `ChangeMe!123` のままの行に限定。変更済み
  パスワードは上書きしない）。追記型のため 0002 は書き換えず、本マイグレーションで更新する。
- `0012_rename_root_tenant`: root テナントの既定表示名を `Root` から `ROOT` へ更新する（0002 の seed
  既定 `Root` のままの行に限定。運用者が別名へ変更した行は上書きしない）。追記型のため 0002 は
  書き換えず、本マイグレーションで更新する。
- `0013_admin_username_email`: 初期管理者 `admin@example.com` のログイン識別子（`preferred_username`）を、
  メールアドレスと同じ `admin@example.com` へ更新する（0002 の seed 既定 `admin` のままの行に限定。
  運用者が別名へ変更した行は上書きしない）。ログインは email ではなく `preferred_username` で照合する
  （ADR-0009 §8）ため、初期案内どおり `admin@example.com` でログインできるようにする。追記型のため
  0002 は書き換えず、本マイグレーションで更新する。
- `0014_membership_suspended`: `tenant_memberships.status` の許可値へ `SUSPENDED` を追加する（MT24）。
  ゲストの一時停止用。CHECK 制約の張り替えのみで既存行は変更しない（expand）。`down` は残存する
  `SUSPENDED` 行を `INVITED` へ倒してから旧 CHECK へ戻す（`ACTIVE` へ戻すと、止めたはずのゲストの
  アクセスがロールバックで復活してしまうため）。
- `0015_drop_saml_identity_providers`: 0008 で追加した外部 IdP 設定表 `saml_identity_providers` を削除する
  （参照コードは既に存在しない。ADR-0004 §6 の expand/contract の contract 側。MT28）。`down` は 0008 と
  同一定義で再作成する（ENGINE・CHARSET・COLLATE を含めて一致させないと外部キーが errno 150 で失敗する）。
  行データは復元しない。

root テナントの UUID は固定値 `00000000-0000-7000-8000-000000000001`（全環境共通・git 管理。ADR-0011）。
管理者ログイン URL は `/00000000-0000-7000-8000-000000000001/...`。
