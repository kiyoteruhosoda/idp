-- 認証器の統合管理（AP9。ユーザー認証・認証ポリシー仕様書 §5）。
--
-- これまで認証器は種別ごとに別テーブル（`user_totp_secrets` / `user_webauthn_credentials`）で、
-- どちらも「登録済みか否か」しか持っていなかった。そのため次ができない:
--
--   * 利用者・管理者が「この人が使える認証器」を 1 箇所で見る。
--   * 認証器を**一時停止**する（紛失した端末を、消さずに使えなくする）。復旧後に戻せるのが
--     削除との違いで、削除しかないと「戻すには登録し直し」になる。
--   * 認証器の種類を増やす（リカバリーコード・email OTP）。種別ごとに表を足す設計は、
--     ログイン側の分岐も認証ポリシーの参照先も種別数だけ増える。
--
-- 本テーブルは種別によらない**登録簿**として、種別・状態・ラベル・利用時刻を一元的に持つ。
--
-- # 秘密の置き場所（expand フェーズ）
--
-- TOTP のシークレットと WebAuthn の passkey_json は既存テーブルに置いたままにし、本テーブルは
-- `credential_ref` でそれを指す（TOTP は 1 ユーザー 1 行なので `NULL`、WebAuthn は
-- `user_webauthn_credentials.id`）。秘密の移送は本マイグレーションでは行わない — 移送は
-- 「復号して読み直して書き戻す」操作で、失敗すると MFA を通せない利用者が出る。登録簿の導入と
-- 秘密の移送を同じ変更に載せない（ADR-0004 の expand/contract）。
--
-- リカバリーコードと email OTP は既存テーブルを持たないため、本テーブルの `secret_encrypted` に
-- 直接置く（リカバリーコードは SHA-256、email OTP は送信済みコードの SHA-256）。
CREATE TABLE user_authenticators (
    id                 CHAR(36)     NOT NULL
        COMMENT '内部識別子（UUIDv7）',
    user_id            CHAR(36)     NOT NULL,
    authenticator_type VARCHAR(32)  NOT NULL
        COMMENT '認証器の種別（totp / webauthn / recovery_code / email_otp / sms_otp）',
    status             VARCHAR(16)  NOT NULL DEFAULT 'pending'
        COMMENT '状態（pending / active / suspended / revoked）',
    label              VARCHAR(255) NOT NULL DEFAULT ''
        COMMENT '利用者が付ける表示名（例: "iPhone の認証アプリ"）',
    secret_encrypted   TEXT         NULL
        COMMENT '種別固有の秘密。リカバリーコードは SHA-256、email OTP は送信コードの SHA-256。TOTP / WebAuthn は既存テーブル側にあるため NULL',
    credential_ref     CHAR(36)     NULL
        COMMENT 'WebAuthn は user_webauthn_credentials.id。TOTP は 1 ユーザー 1 行のため NULL',
    -- 認証先（email OTP の送信先）。PII を持つ列だが、送信に必要で `users.email` とは別の
    -- アドレスを使える必要がある（仕事用と復旧用を分ける運用）。
    target             VARCHAR(320) NULL
        COMMENT 'email OTP の送信先アドレス。他の種別では NULL',
    confirmed_at       DATETIME(6)  NULL
        COMMENT '登録確認が完了した時刻。NULL = pending',
    last_used_at       DATETIME(6)  NULL
        COMMENT '直近にこの認証器で認証が通った時刻',
    -- 期限。email OTP のコードのように寿命があるものにだけ入る。
    expires_at         DATETIME(6)  NULL
        COMMENT 'この認証器（コード）の有効期限。無期限なら NULL',
    revoked_at         DATETIME(6)  NULL
        COMMENT '失効させた時刻。非 NULL = status も revoked',
    created_at         DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at         DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    -- ログイン時のホットパス（「この人の使える認証器」）が使う索引。
    KEY user_authenticators_user_idx (user_id, status, authenticator_type),
    -- WebAuthn の登録簿行は 1 クレデンシャルにつき 1 行（重複登録を DB で防ぐ）。
    UNIQUE KEY user_authenticators_credential_uk (credential_ref),
    CONSTRAINT user_authenticators_type_chk
        CHECK (authenticator_type IN ('totp', 'webauthn', 'recovery_code', 'email_otp', 'sms_otp')),
    CONSTRAINT user_authenticators_status_chk
        CHECK (status IN ('pending', 'active', 'suspended', 'revoked')),
    CONSTRAINT user_authenticators_user_fk FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- 既存の認証器を登録簿へ取り込む（冪等。再実行しても二重登録しない）。
-- UUIDv7 は SQL では作れないため、version/variant ニブルを埋めた v4 相当の値を生成する
-- （登録簿の id は時系列ソートに使わないため、ここは v4 で差し支えない。ADR-0009 §12 の
-- 「揮発トークンは v4」に準じる）。
INSERT INTO user_authenticators
    (id, user_id, authenticator_type, status, label, credential_ref, confirmed_at, created_at)
SELECT
    LOWER(CONCAT(
        SUBSTR(HEX(RANDOM_BYTES(4)), 1, 8), '-',
        SUBSTR(HEX(RANDOM_BYTES(2)), 1, 4), '-4',
        SUBSTR(HEX(RANDOM_BYTES(2)), 2, 3), '-a',
        SUBSTR(HEX(RANDOM_BYTES(2)), 2, 3), '-',
        SUBSTR(HEX(RANDOM_BYTES(6)), 1, 12)
    )),
    t.user_id,
    'totp',
    -- 確認前（QR を出しただけ）の行は pending のまま取り込む。
    CASE WHEN t.confirmed_at IS NULL THEN 'pending' ELSE 'active' END,
    '',
    NULL,
    t.confirmed_at,
    t.created_at
FROM user_totp_secrets t
WHERE NOT EXISTS (
    SELECT 1 FROM user_authenticators a
    WHERE a.user_id = t.user_id AND a.authenticator_type = 'totp'
);

INSERT INTO user_authenticators
    (id, user_id, authenticator_type, status, label, credential_ref, confirmed_at,
     last_used_at, created_at)
SELECT
    LOWER(CONCAT(
        SUBSTR(HEX(RANDOM_BYTES(4)), 1, 8), '-',
        SUBSTR(HEX(RANDOM_BYTES(2)), 1, 4), '-4',
        SUBSTR(HEX(RANDOM_BYTES(2)), 2, 3), '-a',
        SUBSTR(HEX(RANDOM_BYTES(2)), 2, 3), '-',
        SUBSTR(HEX(RANDOM_BYTES(6)), 1, 12)
    )),
    c.user_id,
    'webauthn',
    -- 登録済みのパスキーは確認済み（登録の完了＝チャレンジ検証の成功）。
    'active',
    c.name,
    c.id,
    c.created_at,
    c.last_used_at,
    c.created_at
FROM user_webauthn_credentials c
WHERE NOT EXISTS (
    SELECT 1 FROM user_authenticators a WHERE a.credential_ref = c.id
);
