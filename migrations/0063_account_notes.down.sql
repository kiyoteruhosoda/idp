-- 0063 の巻き戻し。
--
-- 人のメモは 0061 の表へ書き戻す（0063 の後に書かれた・直されたものを失わないため）。
-- ⚠ サービスアカウントのメモは失われる（0061 の表に置き場が無い）。
DELETE FROM tenant_member_notes;

INSERT INTO tenant_member_notes (tenant_id, user_id, note, updated_at, updated_by)
SELECT tenant_id, user_id, note, updated_at, updated_by
FROM account_notes
WHERE kind = 'USER';

DROP TABLE account_notes;
