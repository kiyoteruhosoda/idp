-- 認証ポリシーの適用条件を `client_ids` から `application_ids` へ寄せる（ADR-0054 の決定 5）。
--
-- 寄せない限り**SAML のアプリはポリシーの外に残り、MFA を要求できない**。条件に
-- `service_provider_ids` を並べる案を取らないのは、プロトコルが増えるたびに条件が増えるためである
-- ——条件の側はポリシーを書く人が読む場所で、そこにプロトコルの都合を並べると「このアプリに MFA を
-- 掛けたい」が「このアプリの OIDC と SAML の両方に MFA を掛けたい」という書き方に変わる。
--
-- ✅ いま寄せるのは無害。本番の `authentication_policies` は 1 行だけで、条件は
-- `{"requested_acr":["urn:assay:ac:mfa"]}` ——**`client_ids` を使っている行が 1 つも無い**
-- （2026-09-15 実測）。SAML の SP も 0 件。
--
-- ⚠ **列は増やさない。** `conditions` は JSON なので、キーの置き換えだけで済む。
--   「空 = 制限しない」の既定は両方のキーで同じなので、キーを持たない行は触らなくてよい。

-- ⚠ **件数を保ったまま写す。** `client_ids` の 1 件が 1 件の `application_ids` になるよう、
--   LEFT JOIN で欠けを埋める。素直な INNER JOIN にすると、**解決できない `client_id` だけを持つ
--   条件が空配列になり、「何にも一致しない」が「すべてに一致する」へ意味ごと反転する**
--   （空 = 制限しない、なので）。
--
--   解決できない相手には nil UUID（`00000000-0000-0000-0000-000000000000`）を入れる。アプリの id は
--   UUIDv7 なので**この値には決してならず**、「何にも一致しない」がそのまま保たれる。そうなるのは
--   元から死んでいた条件（存在しない `client_id` を名指ししていた行）だけである。
UPDATE authentication_policies p
SET p.conditions = JSON_SET(
        JSON_REMOVE(p.conditions, '$.client_ids'),
        '$.application_ids',
        COALESCE(
            (
                SELECT JSON_ARRAYAGG(
                           COALESCE(b.application_id, '00000000-0000-0000-0000-000000000000')
                       )
                FROM JSON_TABLE(
                         JSON_EXTRACT(p.conditions, '$.client_ids'),
                         '$[*]' COLUMNS (client_id VARCHAR(255) PATH '$')
                     ) AS jt
                LEFT JOIN clients c
                       ON c.tenant_id = p.tenant_id AND c.client_id = jt.client_id
                LEFT JOIN application_bindings b
                       ON b.client_id = c.id
            ),
            JSON_ARRAY()
        )
    )
WHERE JSON_CONTAINS_PATH(p.conditions, 'one', '$.client_ids');
