-- 0064 の巻き戻し。0061 と同じ定義で旧表を作り直し、人のメモを写す（0063 の down が読む）。
-- ENGINE・CHARSET・COLLATE まで揃えないと外部キーが errno 150 で落ちる。
CREATE TABLE tenant_member_notes (
    tenant_id  CHAR(36)    NOT NULL,
    user_id    CHAR(36)    NOT NULL,
    note       TEXT        NOT NULL COMMENT '管理者メモ（自由記述。空にしたら行ごと消す）',
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_by CHAR(36)    NULL COMMENT '最後に書いた管理者（users.id）。機械経由は NULL',
    PRIMARY KEY (tenant_id, user_id),
    CONSTRAINT tenant_member_notes_membership_fk FOREIGN KEY (tenant_id, user_id)
        REFERENCES tenant_memberships (tenant_id, user_id) ON DELETE CASCADE,
    CONSTRAINT tenant_member_notes_updated_by_fk FOREIGN KEY (updated_by)
        REFERENCES users (id) ON DELETE SET NULL
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

INSERT INTO tenant_member_notes (tenant_id, user_id, note, updated_at, updated_by)
SELECT tenant_id, user_id, note, updated_at, updated_by
FROM account_notes
WHERE kind = 'USER';
