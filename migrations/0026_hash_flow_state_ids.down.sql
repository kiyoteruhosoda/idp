-- 列名・型だけを元へ戻す（SHA-256 は一方向なので**平文は復元できない**）。
--
-- 戻した時点で進行中のフローは Cookie 値と行が一致しなくなるため成立しない。いずれも
-- 短命な一時状態（auth_session は既定 600 秒）で、利用者は `/authorize` からやり直せば
-- よいだけなので、進行状態は破棄する。破棄せずに残すと「引けないのに GC されない行」が
-- 溜まるだけになる。
DELETE FROM auth_sessions;
DELETE FROM saml_sso_requests;
DELETE FROM passkey_challenges;
DELETE FROM external_login_requests;

ALTER TABLE auth_sessions
    CHANGE COLUMN id_hash id VARCHAR(64) NOT NULL;

ALTER TABLE saml_sso_requests
    CHANGE COLUMN id_hash id VARCHAR(64) NOT NULL;

ALTER TABLE passkey_challenges
    CHANGE COLUMN auth_session_id_hash auth_session_id VARCHAR(64) NULL;

ALTER TABLE external_login_requests
    CHANGE COLUMN auth_session_id_hash auth_session_id VARCHAR(128) NULL
        COMMENT '呼び出し元の OIDC auth_session。ポータル経由なら NULL';
