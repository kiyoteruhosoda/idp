-- 0038 の巻き戻し。元の表と `credential_ref` 列を作り直し、登録簿の秘密を書き戻す。
--
-- 秘密は登録簿にそのまま在るので、**値としては完全に戻せる**（0038 は取り込んでから落として
-- いるため、登録簿の側が最新である）。戻らないのは元の表の行 id で、ここでは登録簿の行 id を
-- そのまま使う。`credential_ref` は同じ値を指し直すので、前半のコードから見た対応付けは保たれる。

CREATE TABLE user_totp_secrets (
    user_id          CHAR(36)     NOT NULL,
    secret_encrypted TEXT         NOT NULL,
    confirmed_at     DATETIME(6)  NULL,
    created_at       DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at       DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (user_id),
    CONSTRAINT user_totp_user_fk FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

CREATE TABLE user_webauthn_credentials (
    id            CHAR(36)     NOT NULL COMMENT 'UUIDv7',
    user_id       CHAR(36)     NOT NULL,
    credential_id VARCHAR(512) NOT NULL,
    passkey_json  MEDIUMTEXT   NOT NULL,
    name          VARCHAR(255) NOT NULL DEFAULT '',
    created_at    DATETIME(6)  NOT NULL,
    last_used_at  DATETIME(6)  NULL,
    PRIMARY KEY (id),
    UNIQUE KEY user_webauthn_credential_id_uk (credential_id(255)),
    KEY user_webauthn_user_idx (user_id),
    CONSTRAINT user_webauthn_user_fk FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

ALTER TABLE user_authenticators
    ADD COLUMN credential_ref CHAR(36) NULL
        COMMENT 'WebAuthn は user_webauthn_credentials.id。TOTP は 1 ユーザー 1 行のため NULL'
        AFTER secret_encrypted,
    ADD UNIQUE KEY user_authenticators_credential_uk (credential_ref);

-- TOTP の秘密を書き戻す（1 利用者 1 行なので、失効していない行のうち新しい方を採る）。
INSERT INTO user_totp_secrets (user_id, secret_encrypted, confirmed_at, created_at)
SELECT a.user_id, a.secret_encrypted, a.confirmed_at, a.created_at
FROM user_authenticators a
WHERE a.authenticator_type = 'totp'
  AND a.status <> 'revoked'
  AND a.secret_encrypted IS NOT NULL
  AND NOT EXISTS (
      SELECT 1 FROM (SELECT * FROM user_authenticators) newer
      WHERE newer.user_id = a.user_id
        AND newer.authenticator_type = 'totp'
        AND newer.status <> 'revoked'
        AND newer.secret_encrypted IS NOT NULL
        AND newer.created_at > a.created_at
  );

-- パスキーを書き戻し、`credential_ref` を同じ id へ向ける。
INSERT INTO user_webauthn_credentials
    (id, user_id, credential_id, passkey_json, name, created_at, last_used_at)
SELECT a.id, a.user_id, a.credential_id, a.secret_encrypted, a.label, a.created_at, a.last_used_at
FROM user_authenticators a
WHERE a.authenticator_type = 'webauthn'
  AND a.status <> 'revoked'
  AND a.secret_encrypted IS NOT NULL
  AND a.credential_id IS NOT NULL;

UPDATE user_authenticators a
JOIN user_webauthn_credentials c ON c.id = a.id
SET a.credential_ref = c.id;
