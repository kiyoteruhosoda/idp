-- 認証セッションへの認証方式・強度・MFA 完了状態の記録（AP4。ユーザー認証・認証ポリシー仕様書
-- §14.3・§18.1）。
--
-- 「どの認証器で本人確認したか」を SSO セッションに残す。MFA 経過時間による再認証（§18.2
-- `max_authentication_age`）と Step-up 認証（§15）は、この 3 列だけを判定材料にする。
-- 許可値の単一の出所は Rust 側 enum（`domain::values::AuthenticationMethod` /
-- `AuthenticationStrength`）で、DB は VARCHAR + CHECK で受ける（DB ネイティブ ENUM は使わない）。
--
-- expand 方式: 既存行（本マイグレーション以前に確立した SSO セッション）は認証方式を記録して
-- いないため `authentication_methods` を NULL 許容とし、アプリ側は NULL を「記録なし」として扱う。
-- 強度は既定 `single_factor`（記録が無いセッションを多要素とみなさない fail-closed）。
ALTER TABLE sso_sessions
    ADD COLUMN authentication_methods  JSON        NULL
        COMMENT '検証された認証方式の配列（password / totp / webauthn / recovery_code / email_otp / sms_otp / external_idp）。NULL = 記録なし（本列の導入前に確立したセッション）',
    ADD COLUMN authentication_strength VARCHAR(32) NOT NULL DEFAULT 'single_factor'
        COMMENT '認証強度（single_factor / multi_factor）。authentication_methods からの導出値',
    ADD COLUMN mfa_completed_at        DATETIME(6) NULL
        COMMENT '第二要素の検証が完了した時刻。NULL = MFA 未完了',
    ADD CONSTRAINT sso_sessions_auth_strength_chk
        CHECK (authentication_strength IN ('single_factor', 'multi_factor'));
