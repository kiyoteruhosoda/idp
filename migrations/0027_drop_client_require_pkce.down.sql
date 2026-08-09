-- 列を戻す（値は既定の 1 = 必須。元の値は復元できないが、どのみち参照されていなかった）。
ALTER TABLE clients
    ADD COLUMN require_pkce TINYINT(1) NOT NULL DEFAULT 1 AFTER token_endpoint_auth_method;
