-- Migration 0010: ユーザーの TOTP（Time-based One-Time Password）シークレット。
-- MFA は任意でユーザーが自身で登録・削除する。
-- secret_encrypted: AES-256-GCM で暗号化したシークレット（signing_keys の private_key_encrypted と同方式）。
-- confirmed_at: NULL = 仮登録中（QR確認未完了）、非 NULL = 有効な TOTP 設定あり。
CREATE TABLE user_totp_secrets (
    user_id          CHAR(36)     NOT NULL,
    secret_encrypted TEXT         NOT NULL,
    confirmed_at     DATETIME(6)  NULL,
    created_at       DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at       DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (user_id),
    CONSTRAINT user_totp_user_fk FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
