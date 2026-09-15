-- 0055 の巻き戻し。`application_ids` を `client_ids` へ戻す。
--
-- ⚠ **完全には戻らない。** アプリに OIDC の binding が 2 本あれば `client_id` は 2 つに増え、
--   SAML だけのアプリは戻せる相手を持たない。`up` と同じ理由（件数を保つ）で、戻せない相手には
--   実在しない `client_id` を置き、「何にも一致しない」を保つ。
UPDATE authentication_policies p
SET p.conditions = JSON_SET(
        JSON_REMOVE(p.conditions, '$.application_ids'),
        '$.client_ids',
        COALESCE(
            (
                SELECT JSON_ARRAYAGG(COALESCE(c.client_id, '__unmapped_application__'))
                FROM JSON_TABLE(
                         JSON_EXTRACT(p.conditions, '$.application_ids'),
                         '$[*]' COLUMNS (application_id VARCHAR(36) PATH '$')
                     ) AS jt
                LEFT JOIN application_bindings b
                       ON b.application_id = jt.application_id AND b.protocol = 'oidc'
                LEFT JOIN clients c
                       ON c.id = b.client_id
            ),
            JSON_ARRAY()
        )
    )
WHERE JSON_CONTAINS_PATH(p.conditions, 'one', '$.application_ids');
