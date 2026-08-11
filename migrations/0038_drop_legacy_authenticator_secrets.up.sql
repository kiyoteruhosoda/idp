-- 認証器の秘密の置き場所を登録簿へ一本化する（AP11b。AP9 の contract フェーズ **後半**）。
--
-- 0035（前半）で秘密は登録簿（`user_authenticators.secret_encrypted`）と元の表
-- （`user_totp_secrets` / `user_webauthn_credentials`）の**両方**に載るようになった。読みは登録簿を
-- 先に見て無ければ元の表へ落ち、書きは両方へ行っていた。本マイグレーションでその期間を終わらせ、
-- 元の表と `credential_ref` 列を落とす。
--
-- # 適用してよい条件
--
-- **0035 を含むリリースが全ノードへ行き渡っていること。** 元の表しか読まない古いプロセスが
-- 残っている間にこれを当てると、そのプロセスは MFA を通せなくなる（利用者は自力で復旧できない）。
--
-- # 落とす前に必ず取り込む
--
-- 元の表にしか秘密が無い行が残っている。0035 の後に**前半のコードで登録された認証器**が
-- そうなる:
--
--   * パスキー: 登録は「元の表へ INSERT → 登録簿へ行を作る」の順で、登録簿へ秘密を載せる
--     UPDATE は行が出来る前に走る。結果として登録簿の行は `secret_encrypted` が NULL のまま
--     （読みは元の表へ落ちて成立していた）。
--   * TOTP: 同じく「秘密を書く → 登録簿へ pending 行を作る」の順で、秘密は**直前の（すぐ失効
--     させられる）行**へ書かれ、新しい pending 行は NULL のままになる。
--
-- そのため、落とす前に 0035 と同じ取り込みをもう一度流す（冪等）。ここを省くと、前半の期間に
-- MFA を登録した利用者だけが通れなくなる —— 最も気づきにくい壊れ方である。

-- TOTP: 元の表の秘密を、失効していない登録簿の行へ写す。両方にある場合も元の表の値で揃える
-- （書きは両方へ行っていたので同じ値。ずれているとしたら上記の順序によるもので、新しいのは
-- 元の表の側）。
UPDATE user_authenticators a
JOIN user_totp_secrets t ON t.user_id = a.user_id
SET a.secret_encrypted = t.secret_encrypted,
    a.confirmed_at = COALESCE(a.confirmed_at, t.confirmed_at)
WHERE a.authenticator_type = 'totp'
  AND a.status <> 'revoked';

-- TOTP: 登録簿に生きた行が無い利用者の分を作る。
INSERT INTO user_authenticators
    (id, user_id, authenticator_type, status, label, secret_encrypted, confirmed_at, created_at)
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
    t.confirmed_at,
    t.created_at
FROM user_totp_secrets t
WHERE NOT EXISTS (
    SELECT 1 FROM user_authenticators a
    WHERE a.user_id = t.user_id AND a.authenticator_type = 'totp' AND a.status <> 'revoked'
);

-- パスキー: 公開鍵・署名カウンタ（`passkey_json`）と credential ID を登録簿へ写す。
UPDATE user_authenticators a
JOIN user_webauthn_credentials c ON c.id = a.credential_ref
SET a.secret_encrypted = c.passkey_json,
    a.credential_id = c.credential_id,
    a.label = c.name,
    a.last_used_at = COALESCE(c.last_used_at, a.last_used_at)
WHERE a.authenticator_type = 'webauthn'
  AND a.status <> 'revoked';

-- パスキー: 登録簿に行の無いもの（0035 の後に古いプロセスが作った行）を作る。
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

-- 取り込みが済んだので、元の表への参照（`credential_ref`）を落とす。以後、登録簿の行 id が
-- パスキー 1 本の識別子になる。
ALTER TABLE user_authenticators
    DROP INDEX user_authenticators_credential_uk,
    DROP COLUMN credential_ref;

-- 元の表を落とす。ここから先、秘密の置き場所は登録簿だけである。
DROP TABLE user_webauthn_credentials;
DROP TABLE user_totp_secrets;
