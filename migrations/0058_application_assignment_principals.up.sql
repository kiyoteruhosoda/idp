-- アプリを使う主体を「人」と「サービスアカウント」の 2 種類にし、宛名の貸し出し
-- （`client_resources`）をサービスアカウントの割り当てへ置き換える（ADR-0059 の決定 5・6）。
--
-- ⚠ 種類で振る舞いが違う（読む側で種類を必ず見る）:
--   * 人の割り当て          = ログインしてよい（code の発行時の判定が見るのは人だけ）
--   * サービスアカウントの割り当て = そのアプリの宛名（`resource` の名乗り）宛のトークンを取ってよい
--   * 「全員（EVERYONE）」に含まれるのは人だけ。サービスアカウントは必ず個別に割り当てる
--   * 名簿（self）に載るのは人だけ
--
-- 1) `application_assignments` に `id`（主キー）と `kind` を足し、`user_id` / `client_id` の
--    どちらか 1 つだけが埋まる形へ広げる。既存の行はすべて人（`USER`）。
-- 2) `client_resources` を写す。⚠ 推測では写さない。写せない行があれば、0) で何も変える前に止める。
-- 3) `client_resources` を落とす。

-- ---------------------------------------------------------------------------
-- 0) 写せるかを確かめる（⚠ 何かを変える前に止まる）
-- ---------------------------------------------------------------------------
--
-- ⚠ **推測で写さない。** X がどのアプリの名乗りでもない貸し出しが 1 行でもあれば、移行を止める。
--   「宛名 → アプリ」の対応は、この移行の前に人が管理コンソールで宛名をアプリの名乗りとして
--   結び付けることで決める（対応表は DB の `application_bindings` そのもの）。
-- ⚠ 貸していた相手がサービスアカウントでない（`authorization_code` も持つ）行も止める。管理 API は
--   そういう client をサービスアカウントとして割り当てさせないので、写すと API で作れない行ができる。
BEGIN NOT ATOMIC
    IF EXISTS (
        SELECT 1
        FROM client_resources cr
        LEFT JOIN application_bindings b ON b.kind = 'resource' AND b.resource_id = cr.resource_id
        WHERE b.id IS NULL
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT =
            '0058: a lent resource is not bound to any application; bind it as the application''s resource first';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM client_resources cr
        JOIN clients c ON c.id = cr.client_id
        WHERE NOT (
            JSON_CONTAINS(c.grant_types, '"client_credentials"')
            AND NOT JSON_CONTAINS(c.grant_types, '"authorization_code"')
        )
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT =
            '0058: a resource is lent to a client that is not a service account';
    END IF;
END;


-- ---------------------------------------------------------------------------
-- 1) 割り当てを 2 種類へ広げる
-- ---------------------------------------------------------------------------
--
-- 主キーを `(application_id, user_id)` から代理キーへ移す。サービスアカウントの行は `user_id` が
-- NULL で、NULL を含む列は主キーに置けない。一意性は種類ごとの UNIQUE で保つ（MariaDB の UNIQUE は
-- NULL を重複と見なさないので、もう一方の種類の行を妨げない）。
ALTER TABLE application_assignments
    ADD COLUMN id CHAR(36) NULL COMMENT 'UUIDv7' FIRST,
    ADD COLUMN kind VARCHAR(16) NOT NULL DEFAULT 'USER'
        COMMENT 'USER = 人 / SERVICE_ACCOUNT = サービスアカウント' AFTER application_id,
    ADD COLUMN client_id CHAR(36) NULL
        COMMENT 'kind = SERVICE_ACCOUNT のときの clients.id（client_credentials だけの client）'
        AFTER user_id;

-- 既存の行の `id` を UUIDv7 の形で埋める（MariaDB 10.11 には UUID_v7() が無いので手組みする。
-- 形は 0002 と同じ）。時刻の部分には `assigned_at` を使い、割り当てた順に並ぶようにする。
-- 乱数の部分は `(application_id, user_id)` のハッシュから取る ——行ごとに一意で、流し直しても
-- 同じ値になる（`UUID()` / `RAND()` を使うと、失敗して流し直したときに値が変わる）。
UPDATE application_assignments
SET id = LOWER(CONCAT(
    SUBSTR(LPAD(HEX(CAST(FLOOR(UNIX_TIMESTAMP(assigned_at) * 1000) AS UNSIGNED)), 12, '0'), 1, 8),
    '-',
    SUBSTR(LPAD(HEX(CAST(FLOOR(UNIX_TIMESTAMP(assigned_at) * 1000) AS UNSIGNED)), 12, '0'), 9, 4),
    '-7',
    SUBSTR(SHA2(CONCAT('0058:', application_id, ':', user_id), 256), 1, 3),
    '-',
    HEX(8 | (CONV(SUBSTR(SHA2(CONCAT('0058:', application_id, ':', user_id), 256), 4, 1), 16, 10) & 3)),
    SUBSTR(SHA2(CONCAT('0058:', application_id, ':', user_id), 256), 5, 3),
    '-',
    SUBSTR(SHA2(CONCAT('0058:', application_id, ':', user_id), 256), 8, 12)))
WHERE id IS NULL;

ALTER TABLE application_assignments
    DROP PRIMARY KEY,
    MODIFY COLUMN id CHAR(36) NOT NULL COMMENT 'UUIDv7',
    MODIFY COLUMN user_id CHAR(36) NULL COMMENT 'kind = USER のときの users.id',
    ADD PRIMARY KEY (id),
    ADD UNIQUE KEY application_assignments_user_uk (application_id, user_id),
    ADD UNIQUE KEY application_assignments_client_uk (application_id, client_id),
    ADD KEY application_assignments_client_idx (client_id),
    ADD CONSTRAINT application_assignments_kind_chk CHECK (kind IN ('USER', 'SERVICE_ACCOUNT')),
    ADD CONSTRAINT application_assignments_principal_chk CHECK (
        (kind = 'USER' AND user_id IS NOT NULL AND client_id IS NULL)
        OR
        (kind = 'SERVICE_ACCOUNT' AND client_id IS NOT NULL AND user_id IS NULL)
    ),
    ADD CONSTRAINT application_assignments_client_fk FOREIGN KEY (client_id)
        REFERENCES clients (id) ON DELETE CASCADE;

-- 既定値は移行のためだけに置いた。書き込む側は必ず種類を明示する。
ALTER TABLE application_assignments
    ALTER COLUMN kind DROP DEFAULT;

-- ---------------------------------------------------------------------------
-- 2) 宛名の貸し出しを、サービスアカウントの割り当てへ写す
-- ---------------------------------------------------------------------------
--
-- 貸し出し 1 行（client, 宛名 X）は、「X を名乗るアプリ A」への（A, client）の割り当てになる。
-- 写せない行が無いことは、冒頭（0) 写せるかを確かめる）で確かめてある。
INSERT INTO application_assignments (id, application_id, kind, user_id, client_id, assigned_at, assigned_by)
SELECT
    LOWER(CONCAT(
        SUBSTR(parts.ts_hex, 1, 8), '-', SUBSTR(parts.ts_hex, 9, 4),
        '-7', SUBSTR(parts.rand_hex, 1, 3),
        '-', HEX(8 | (CONV(SUBSTR(parts.rand_hex, 4, 1), 16, 10) & 3)), SUBSTR(parts.rand_hex, 5, 3),
        '-', SUBSTR(parts.rand_hex, 8, 12))),
    parts.application_id,
    'SERVICE_ACCOUNT',
    NULL,
    parts.client_id,
    parts.granted_at,
    NULL
FROM (
    -- 1 つのサービスアカウントが同じアプリの宛名を 2 つ借りていても、割り当ては 1 行。
    SELECT
        grouped.application_id,
        grouped.client_id,
        grouped.granted_at,
        LPAD(HEX(CAST(FLOOR(UNIX_TIMESTAMP(grouped.granted_at) * 1000) AS UNSIGNED)), 12, '0') AS ts_hex,
        SHA2(CONCAT('0058:', grouped.application_id, ':', grouped.client_id), 256) AS rand_hex
    FROM (
        SELECT b.application_id, cr.client_id, MIN(cr.granted_at) AS granted_at
        FROM client_resources cr
        JOIN application_bindings b ON b.kind = 'resource' AND b.resource_id = cr.resource_id
        GROUP BY b.application_id, cr.client_id
    ) AS grouped
) AS parts
WHERE NOT EXISTS (
    SELECT 1 FROM application_assignments x
    WHERE x.application_id = parts.application_id AND x.client_id = parts.client_id
);

-- ---------------------------------------------------------------------------
-- 3) 貸し出しの表を落とす
-- ---------------------------------------------------------------------------
DROP TABLE client_resources;
