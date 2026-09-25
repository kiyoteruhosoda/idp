-- 0061 の `tenant_member_notes` を落とす（ADR-0065 の決定 2 の contract）。
--
-- メモは 0063 から `account_notes` に置いている。0063 の後に旧バイナリが入れ替わりの間だけ旧表へ
-- 書いたメモがあれば、落とす前に写す（`account_notes` に無い人の行だけ。あるものは新しい側を正とする）。
INSERT INTO account_notes (id, tenant_id, kind, user_id, client_id, note, updated_at, updated_by)
SELECT
    LOWER(CONCAT(
        SUBSTR(parts.ts_hex, 1, 8), '-', SUBSTR(parts.ts_hex, 9, 4),
        '-7', SUBSTR(parts.rand_hex, 1, 3),
        '-', HEX(8 | (CONV(SUBSTR(parts.rand_hex, 4, 1), 16, 10) & 3)), SUBSTR(parts.rand_hex, 5, 3),
        '-', SUBSTR(parts.rand_hex, 8, 12))),
    parts.tenant_id,
    'USER',
    parts.user_id,
    NULL,
    parts.note,
    parts.updated_at,
    parts.updated_by
FROM (
    SELECT
        n.tenant_id,
        n.user_id,
        n.note,
        n.updated_at,
        n.updated_by,
        LPAD(HEX(CAST(FLOOR(UNIX_TIMESTAMP(n.updated_at) * 1000) AS UNSIGNED)), 12, '0') AS ts_hex,
        SHA2(CONCAT('0064:', n.tenant_id, ':', n.user_id), 256) AS rand_hex
    FROM tenant_member_notes n
) AS parts
WHERE NOT EXISTS (
    SELECT 1 FROM account_notes x
    WHERE x.tenant_id = parts.tenant_id AND x.user_id = parts.user_id
);

DROP TABLE tenant_member_notes;
