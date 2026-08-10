-- 認証器の秘密を登録簿（`user_authenticators`）へ集約する（AP11。AP9 の contract フェーズ 前半）。
--
-- AP9（0023）で入れたのは**状態の登録簿**までで、秘密そのものは元の表に残っていた:
-- TOTP の共有鍵は `user_totp_secrets`、パスキーの公開鍵・署名カウンタは
-- `user_webauthn_credentials`。登録簿は `credential_ref` で元の行を指すだけで、検証経路は
-- 従来どおり元の表を読んでいた。
--
-- # なぜ 2 回に分けるか
--
-- 秘密の移送は失敗すると**利用者が MFA を通れなくなり自力で復旧できない**。しかもローリング
-- デプロイ中は古いプロセス（元の表しか読まない）が動き続ける。そこで:
--
--   * 本マイグレーション（+ 同じリリースのコード）＝ **両方が読める期間**。登録簿を先に見て、
--     無ければ元の表へ落ちる。書き込みは両方へ行う。
--   * 次のリリース ＝ 元の表と `credential_ref` の撤去（contract）。
--
-- 元の表を消すのは、**その前のリリースが全ノードへ行き渡った後**でなければならない。
-- 同じリリースで消すと、まだ古いコードを動かしているプロセスが認証できなくなる。
--
-- # `credential_id` 列を足す理由
--
-- パスキーの検証は WebAuthn credential ID からの逆引きで始まる（認証レスポンスが持ってくるのは
-- この値だけ）。逆引きの索引は今 `user_webauthn_credentials` にあり、登録簿には無い。登録簿を
-- 唯一の出所にするには、この 1 列だけ連れてくる必要がある。

ALTER TABLE user_authenticators
    ADD COLUMN credential_id VARCHAR(512) NULL
        COMMENT 'WebAuthn credential ID（base64url）。認証レスポンスからの逆引き用。他の種別では NULL'
        AFTER credential_ref,
    -- 逆引きは一意でなければならない（同じ credential ID が 2 人に当たると、どちらの
    -- 公開鍵で検証するかが索引の都合で決まってしまう）。VARCHAR(512) 全体には索引を張れないため
    -- 先頭 255 文字で張る（元の表と同じ）。
    ADD UNIQUE KEY user_authenticators_credential_id_uk (credential_id(255));

-- TOTP: 共有鍵を登録簿へ写す。0023 が登録簿の行を作ってあるので、ここは UPDATE で足りる。
-- 冪等（再実行しても同じ値を書くだけ）。
UPDATE user_authenticators a
JOIN user_totp_secrets t ON t.user_id = a.user_id
SET a.secret_encrypted = t.secret_encrypted,
    a.confirmed_at = COALESCE(a.confirmed_at, t.confirmed_at)
WHERE a.authenticator_type = 'totp'
  AND a.status <> 'revoked';

-- パスキー: 公開鍵・署名カウンタ（`passkey_json` 全体）と credential ID を登録簿へ写す。
-- 対応付けは 0023 が入れた `credential_ref`。
UPDATE user_authenticators a
JOIN user_webauthn_credentials c ON c.id = a.credential_ref
SET a.secret_encrypted = c.passkey_json,
    a.credential_id = c.credential_id,
    a.label = c.name,
    a.last_used_at = COALESCE(a.last_used_at, c.last_used_at)
WHERE a.authenticator_type = 'webauthn'
  AND a.status <> 'revoked';

-- 0023 の取り込み後に元の表だけへ書かれた行（古いプロセスが作ったパスキー）を拾う。
-- id の作り方は 0023 と同じ理由で v4 相当（登録簿の id は時系列ソートに使わない）。
INSERT INTO user_authenticators
    (id, user_id, authenticator_type, status, label, secret_encrypted, credential_ref,
     credential_id, confirmed_at, last_used_at, created_at)
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
    'active',
    c.name,
    c.passkey_json,
    c.id,
    c.credential_id,
    c.created_at,
    c.last_used_at,
    c.created_at
FROM user_webauthn_credentials c
WHERE NOT EXISTS (
    SELECT 1 FROM user_authenticators a WHERE a.credential_ref = c.id
);

-- 同じく TOTP の取りこぼし。
INSERT INTO user_authenticators
    (id, user_id, authenticator_type, status, label, secret_encrypted, credential_ref,
     confirmed_at, created_at)
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
    CASE WHEN t.confirmed_at IS NULL THEN 'pending' ELSE 'active' END,
    '',
    t.secret_encrypted,
    NULL,
    t.confirmed_at,
    t.created_at
FROM user_totp_secrets t
WHERE NOT EXISTS (
    SELECT 1 FROM user_authenticators a
    WHERE a.user_id = t.user_id AND a.authenticator_type = 'totp'
);
