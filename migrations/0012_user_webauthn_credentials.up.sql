-- Migration 0012: WebAuthn（Passkey）クレデンシャル登録テーブルとチャレンジ一時テーブル。
--
-- user_webauthn_credentials:
--   WebAuthn クレデンシャル1件を1行で管理する。webauthn-rs の Passkey 構造体（公開鍵・
--   sign_count・transports など）を JSON シリアライズして passkey_json カラムへ保存する。
--   credential_id は認証レスポンスからのクレデンシャル特定用（base64url 文字列）。
--
-- passkey_challenges:
--   登録（register）・認証（authenticate）のチャレンジ中間状態を一時保存する。
--   webauthn-rs の PasskeyRegistration / DiscoverableAuthentication を JSON で保存し、
--   complete ステップで消費する。expires_at を過ぎたレコードはアプリケーションが削除する。

-- Passkey クレデンシャル本体。
CREATE TABLE user_webauthn_credentials (
    id            CHAR(36)     NOT NULL,
    user_id       CHAR(36)     NOT NULL,
    -- WebAuthn credential ID（base64url エンコード）。認証レスポンスからの逆引き用。
    credential_id VARCHAR(512) NOT NULL,
    -- webauthn-rs Passkey 構造体全体（公開鍵・sign_count・back_eligible など）の JSON。
    passkey_json  MEDIUMTEXT   NOT NULL,
    -- ユーザーが付けた任意のラベル（例: "MacBook Touch ID"）。
    name          VARCHAR(255) NOT NULL DEFAULT '',
    created_at    DATETIME(6)  NOT NULL,
    last_used_at  DATETIME(6)  NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_wc_credential_id (credential_id(255)),
    INDEX idx_wc_user_id (user_id),
    CONSTRAINT wc_user_fk FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- チャレンジ一時テーブル（登録 / 認証の begin → complete 間で保持）。
CREATE TABLE passkey_challenges (
    id               CHAR(36)     NOT NULL,
    -- register: SSO 済みユーザーの UUID。authenticate: discoverable のため NULL 可。
    user_id          CHAR(36)     NULL,
    -- 'register' | 'authenticate'
    challenge_type   VARCHAR(20)  NOT NULL,
    -- webauthn-rs の PasskeyRegistration / DiscoverableAuthentication を JSON シリアライズした値。
    state_json       MEDIUMTEXT   NOT NULL,
    -- 認証チャレンジと OIDC フロー（AuthSession）を紐づける。register では NULL。
    auth_session_id  VARCHAR(64)  NULL,
    expires_at       DATETIME(6)  NOT NULL,
    created_at       DATETIME(6)  NOT NULL,
    PRIMARY KEY (id),
    INDEX idx_pc_expires (expires_at),
    CONSTRAINT pc_challenge_type_chk CHECK (challenge_type IN ('register', 'authenticate'))
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
