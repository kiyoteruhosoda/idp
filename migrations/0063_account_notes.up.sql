-- 管理者メモを「アカウント」（人とサービスアカウント）に付ける（ADR-0065 の決定 2）。
--
-- 0061 のメモは利用者の表（`tenant_member_notes.user_id`）に付いていたので、サービスアカウントには
-- 書けなかった。形は `application_assignments`（0059）と同じにする: `kind` と、`user_id` /
-- `client_id` のどちらか 1 つだけが埋まる。
--
--   * 人のメモ      = メンバーシップ（テナント × 利用者）に付く。0061 と同じ複合外部キー（CASCADE）
--   * サービスアカウントのメモ = `clients.id` に付く。1 テナントにしか属さないのでメンバーシップの段は無い
--
-- ⚠ expand のみ。0061 の表はこの移行では落とさない（旧バイナリが入れ替わりの間も読み書きする）。
--   落とすのは次の移行（contract）。入れ替わりの間に旧バイナリが書いた人のメモは、ここでは写らない。

CREATE TABLE account_notes (
    id         CHAR(36)    NOT NULL COMMENT 'UUIDv7',
    tenant_id  CHAR(36)    NOT NULL,
    kind       VARCHAR(16) NOT NULL COMMENT 'USER = 人 / SERVICE_ACCOUNT = サービスアカウント',
    user_id    CHAR(36)    NULL COMMENT 'kind = USER のときの users.id',
    client_id  CHAR(36)    NULL COMMENT 'kind = SERVICE_ACCOUNT のときの clients.id',
    note       TEXT        NOT NULL COMMENT '管理者メモ（自由記述。空にしたら行ごと消す）',
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_by CHAR(36)    NULL COMMENT '最後に書いた管理者（users.id）。機械経由は NULL',
    PRIMARY KEY (id),
    -- 種類ごとに 1 つ。MariaDB の UNIQUE は NULL を重複と見なさないので、もう一方の種類の行を妨げない。
    UNIQUE KEY account_notes_user_uk (tenant_id, user_id),
    UNIQUE KEY account_notes_client_uk (tenant_id, client_id),
    KEY account_notes_client_idx (client_id),
    CONSTRAINT account_notes_kind_chk CHECK (kind IN ('USER', 'SERVICE_ACCOUNT')),
    CONSTRAINT account_notes_principal_chk CHECK (
        (kind = 'USER' AND user_id IS NOT NULL AND client_id IS NULL)
        OR
        (kind = 'SERVICE_ACCOUNT' AND client_id IS NOT NULL AND user_id IS NULL)
    ),
    -- メンバーシップが消えればメモも消える。ゲストを解除して招き直したとき、前回のメモが黙って戻る
    -- 形にはしない（0061 と同じ）。
    CONSTRAINT account_notes_membership_fk FOREIGN KEY (tenant_id, user_id)
        REFERENCES tenant_memberships (tenant_id, user_id) ON DELETE CASCADE,
    -- サービスアカウントは論理削除（0044）なので、ふだんは行が消えない。物理削除されたときだけ消える。
    CONSTRAINT account_notes_client_fk FOREIGN KEY (client_id)
        REFERENCES clients (id) ON DELETE CASCADE,
    CONSTRAINT account_notes_updated_by_fk FOREIGN KEY (updated_by)
        REFERENCES users (id) ON DELETE SET NULL
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- 0061 のメモを写す。`id` は 0059 と同じ手組みの UUIDv7（時刻は `updated_at`、乱数の部分は
-- `(tenant_id, user_id)` のハッシュ）——流し直しても同じ値になる。
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
        SHA2(CONCAT('0063:', n.tenant_id, ':', n.user_id), 256) AS rand_hex
    FROM tenant_member_notes n
) AS parts
WHERE NOT EXISTS (
    SELECT 1 FROM account_notes x
    WHERE x.tenant_id = parts.tenant_id AND x.user_id = parts.user_id
);
