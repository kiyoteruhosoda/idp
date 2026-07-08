-- F5: Token 管理 — Access Token 失効リスト（RFC 7009 revocation endpoint 対応）。
-- JWT Access Token は自己完結型のためリボーク不能だが、jti をここに記録して
-- /userinfo・/introspect 検証時に照合することで擬似的な即時失効を実現する。
-- expires_at は元の Access Token の exp に合わせて設定し、期限切れエントリは定期 PURGE 可能にする。

CREATE TABLE revoked_access_tokens (
    jti        VARCHAR(64)  NOT NULL,
    revoked_at DATETIME(6)  NOT NULL,
    expires_at DATETIME(6)  NOT NULL,
    PRIMARY KEY (jti),
    KEY revoked_access_tokens_expires_idx (expires_at)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
