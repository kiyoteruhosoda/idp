-- 0030 の巻き戻し（G3）。
--
-- 巻き戻し時点で残っている `client_secret_post` 行は旧 CHECK に違反するため、先に別の値へ倒す
-- 必要がある。`client_secret_basic` へ倒すのは、これが同じ secret を使う**別の提示場所**でしか
-- なく（RFC 6749 §2.3.1）、クライアントの機密性・secret の値そのものは変わらないため。
-- `none`（＝認証なし）へ倒すと confidential クライアントの認証が黙って外れてしまう。
-- 倒したクライアントは Basic ヘッダで secret を送るよう RP 側の設定変更が要る。
UPDATE clients
SET token_endpoint_auth_method = 'client_secret_basic'
WHERE token_endpoint_auth_method = 'client_secret_post';

ALTER TABLE clients
    DROP CONSTRAINT clients_token_auth_chk;

ALTER TABLE clients
    ADD CONSTRAINT clients_token_auth_chk
        CHECK (token_endpoint_auth_method IN ('client_secret_basic', 'none'));

ALTER TABLE clients
    MODIFY COLUMN token_endpoint_auth_method VARCHAR(32) NOT NULL;
