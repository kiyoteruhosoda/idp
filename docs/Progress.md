# Progress

進行中・未着手タスクのみを管理する（完了したら本ファイルから削除し、必要なら `CHANGELOG.md` / `history/` へ）。

OIDC IdP MVP（**Rust + MariaDB**）の実装計画。設計仕様は `docs/OIDC_INPUT.md`、
スタック採用理由は `docs/adr/0005-rust-mariadb-stack.md`。MVP 完了条件（§10）は充足済み（詳細は `CHANGELOG.md`）。

## バックログ

現在の未着手タスクはありません。


---

### 詳細

#### T4: Passkey（WebAuthn）登録・認証

**Application**: `passkey_registration.rs`（登録開始・完了）/ `passkey_authentication.rs`（認証開始・完了）

**Infrastructure**: `webauthn_credential.rs`（sqlx）/ `webauthn.rs`（`webauthn-rs` ラッパー）

**API**:
- `POST /account/mfa/passkey/register/begin` / `complete`
- `DELETE /account/mfa/passkey/:id`
- `POST /login/passkey/begin` / `complete`

**Web**: Passkey登録画面（WebAuthn JS API 呼び出し）・ログイン画面に Passkey ボタン追加


---

### 詳細

#### T1: MFA基盤 — DBマイグレーション＋ドメイン設計

**マイグレーション**

- `0010_user_totp_secrets.up/down.sql`
  `(user_id, encrypted_secret, backup_codes_hash JSON, confirmed_at, created_at)` — `confirmed_at IS NULL` なら仮登録中
- `0011_user_webauthn_credentials.up/down.sql`
  `(id, user_id, credential_id, public_key, sign_count, transports, name, created_at, last_used_at)`
- `0012_auth_session_mfa_pending.up/down.sql`
  `auth_sessions` に `password_verified_at DATETIME(6) NULL` を追加（MFA pending 状態管理用）

**ドメイン**

- `domain/totp_secret.rs` — `TotpSecret` エンティティ
- `domain/webauthn_credential.rs` — `WebAuthnCredential` エンティティ
- `domain/repositories.rs` に `TotpSecretRepository` / `WebAuthnCredentialRepository` トレイト追加

---

#### T2: TOTP登録・管理

MFA は任意（強制なし）。ユーザーが自分でセルフ登録・削除する。

**Application**: `application/totp_registration.rs`
- `setup(user_id)` → TOTP secret 生成・仮保存・QR URI 返却
- `confirm(user_id, code)` → コード検証後 `confirmed_at` 設定で確定
- `remove(user_id)` → TOTP削除

**Infrastructure**: `infrastructure/repositories/totp_secret.rs`（sqlx 実装）

**API**（`/account/mfa/totp` 配下）
- `GET  /account/mfa/totp/setup` → TOTP URI + QRコード返却
- `POST /account/mfa/totp/confirm` → 6桁コードで確定
- `DELETE /account/mfa/totp` → TOTP削除

**Web**: TOTP設定画面（QRコード表示・確認コード入力フォーム）・アカウント設定にMFAセクション追加

---

#### T3: ログインフローへの TOTPステップ追加

`LoginService` でパスワード検証成功後、ユーザーに TOTP が有効なら `auth_sessions.password_verified_at` を更新して `LoginOutcome::MfaRequired` を返す（SSO発行は MFA完了後）。

**Application**: `application/mfa_login.rs` — `MfaLoginService::verify_totp(auth_session_id, code, ctx)`
- セッションの `password_verified_at` を確認 → TOTP検証 → SSO発行 → consent → code 発行

**API**: `POST /login/mfa/totp` ハンドラ追加

**Web**: TOTP入力画面（ログインフロー内）

---

#### T4: Passkey（WebAuthn）登録・認証

**Application**: `passkey_registration.rs`（登録開始・完了）/ `passkey_authentication.rs`（認証開始・完了）

**Infrastructure**: `webauthn_credential.rs`（sqlx）/ `webauthn.rs`（`webauthn-rs` ラッパー）

**API**:
- `POST /account/mfa/passkey/register/begin` / `complete`
- `DELETE /account/mfa/passkey/:id`
- `POST /login/passkey/begin` / `complete`

**Web**: Passkey登録画面（WebAuthn JS API 呼び出し）・ログイン画面に Passkey ボタン追加
