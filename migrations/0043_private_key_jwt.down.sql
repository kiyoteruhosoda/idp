-- 0043 の巻き戻し（ADR-0030）。
--
-- 巻き戻し時点で残っている `private_key_jwt` 行は旧 CHECK に違反するため、先に別の値へ倒す必要が
-- ある。倒し先は `client_secret_basic` とする —— `none`（＝認証なし）へ倒すと confidential
-- クライアントの認証が黙って外れる。ただし 0030 の巻き戻しと違い、こちらは**認証が通らなくなる**
-- 点に注意する: `private_key_jwt` のクライアントには照合できる `client_secret_hash` が無い
-- （登録時に secret を発行していない）。巻き戻す場合は、対象クライアントの secret を再発行して
-- RP 側へ配る運用が別途要る。対象は次で洗い出せる。
--
--   SELECT tenant_id, client_id, app_name FROM clients
--    WHERE token_endpoint_auth_method = 'private_key_jwt';
UPDATE clients
SET token_endpoint_auth_method = 'client_secret_basic'
WHERE token_endpoint_auth_method = 'private_key_jwt';

DROP TABLE client_assertion_jtis;

ALTER TABLE clients
    DROP COLUMN jwks;

ALTER TABLE clients
    DROP CONSTRAINT clients_token_auth_chk;

ALTER TABLE clients
    ADD CONSTRAINT clients_token_auth_chk
        CHECK (token_endpoint_auth_method IN ('client_secret_basic', 'client_secret_post', 'none'));

ALTER TABLE clients
    MODIFY COLUMN token_endpoint_auth_method VARCHAR(32) NOT NULL
        COMMENT 'client_secret_basic = Authorization: Basic / client_secret_post = body / none = public';
