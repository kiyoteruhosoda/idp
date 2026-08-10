-- SAML の外部 IdP を落として OIDC 前提の列構成へ戻す。
--
-- SAML のプロバイダ行は**先に消す**。OIDC の列を NOT NULL へ戻すとき、SAML の行は
-- `authorization_endpoint` 等が NULL なので変換に失敗する。ここで消えるのは「この
-- マイグレーションを当てて以降に登録された SAML の設定」だけで、OIDC の設定は無傷である
-- （SAML は down 後の版では動かせないので、残しても設定として意味を持たない）。
DELETE FROM external_identity_providers WHERE protocol = 'saml';

-- SAML の進行状態は `code_verifier_encrypted` が NULL なので、NOT NULL へ戻す前に消す。
DELETE FROM external_login_requests WHERE code_verifier_encrypted IS NULL;

ALTER TABLE external_login_requests
    MODIFY COLUMN code_verifier_encrypted TEXT NOT NULL
        COMMENT 'PKCE の code_verifier（AES-256-GCM）',
    MODIFY COLUMN nonce VARCHAR(128) NOT NULL
        COMMENT 'ID Token の nonce と照合する値';

ALTER TABLE external_identity_providers
    MODIFY COLUMN authorization_endpoint VARCHAR(2048) NOT NULL,
    MODIFY COLUMN token_endpoint VARCHAR(2048) NOT NULL,
    MODIFY COLUMN jwks_uri VARCHAR(2048) NOT NULL
        COMMENT 'ID Token の署名検証に使う JWKS の URL',
    MODIFY COLUMN client_id VARCHAR(255) NOT NULL
        COMMENT '外部 IdP に登録した本 IdP のクライアント ID';

ALTER TABLE external_identity_providers
    DROP CONSTRAINT external_idps_protocol_ck,
    DROP COLUMN saml_name_id_format,
    DROP COLUMN saml_certificates,
    DROP COLUMN saml_sso_url,
    DROP COLUMN protocol;
