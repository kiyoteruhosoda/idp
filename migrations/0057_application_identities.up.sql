-- アプリの名乗り（binding）を 4 種類に広げる（ADR-0059）。
--
-- アプリが「自分」として assay に現れる口は、ログインの口（OIDC・SAML）だけではない。
--
--   oidc            ログイン用の client（`authorization_code`）
--   saml            SAML の SP
--   service_account アプリ自身が assay を呼ぶときの client（`client_credentials` だけ。ADR-0038）
--   resource        アプリの API の宛名（`resources`。トークンの `aud` に入る値。ADR-0042）
--
-- どれも **1 つの相手は 1 つのアプリにだけ属する**（UNIQUE）。名簿の self の口
-- （`/admin/applications/self/users`）は、呼んできた client の `service_account` の名乗りから
-- アプリを 1 つに決める。
--
-- ⚠ 列の名前を `protocol` から `kind` へ改める。サービスアカウントと宛名はプロトコルではなく、
--   `protocol = 'resource'` と書くと読み手が意味を取り違える。
--
-- 1) 移行 0054 が `client_credentials` の client に作った「自分だけのアプリ」を消す。
-- 2) `application_bindings` を 4 種類へ広げる。
--
-- ⚠ サービスアカウント・宛名をどのアプリの名乗りにするかは**この移行では決めない**。
--   `app_name` の似ている client を探して結び付けるような推測はしない ——誤って結び付けると、
--   そのサービスアカウントが別のアプリの名簿を読めてしまう。人が画面・API で結び付ける。

-- ---------------------------------------------------------------------------
-- 1) サービスアカウントのアプリを消す
-- ---------------------------------------------------------------------------
--
-- 0054 は `clients` の全行をアプリへ開いた。そのうち `client_credentials` だけを使う client
-- （サービスアカウント）には入ってくる利用者が居ない ——**サービスアカウントはアプリではなく、
-- アプリの名乗り（または、アプリを使う主体）である**。残すと、名前の同じ「アプリ」が 2 つ並び、
-- 人はどちらに割り当てればよいのか迷う。
--
-- 消してよいのは、そのアプリが**サービスアカウントの 1 本しか持たず、誰にも使われていない**とき
-- だけである。次のどれかに当たる行があれば、⚠ **移行を失敗させる**（黙って残さない・黙って消さない）:
--
--   * 割り当てがある（誰かが名簿に入れた）
--   * 認証ポリシーの条件（`application_ids`）から参照されている
--   * 他の名乗りも持っている（人が別の client や SP を足した）
--
-- 対象の特定は `grant_types` で行う。ADR-0032 Revised により `authorization_code` と
-- `client_credentials` は同居しないが、古い登録が両方を持っていてもサービスアカウントとは
-- 扱わない（利用者が入ってくる相手のアプリを消さない）。
CREATE TEMPORARY TABLE migration_0057_service_account_applications (
    application_id CHAR(36) NOT NULL PRIMARY KEY
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

INSERT INTO migration_0057_service_account_applications (application_id)
SELECT DISTINCT b.application_id
FROM application_bindings b
JOIN clients c ON c.id = b.client_id
WHERE b.protocol = 'oidc'
  AND JSON_CONTAINS(c.grant_types, '"client_credentials"')
  AND NOT JSON_CONTAINS(c.grant_types, '"authorization_code"');

BEGIN NOT ATOMIC
    IF EXISTS (
        SELECT 1
        FROM migration_0057_service_account_applications t
        JOIN application_assignments x ON x.application_id = t.application_id
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT =
            '0057: a service-account application has assignments; move them to the real application first';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM migration_0057_service_account_applications t
        JOIN application_bindings b ON b.application_id = t.application_id
        LEFT JOIN clients c ON c.id = b.client_id
        WHERE NOT (
            b.protocol = 'oidc'
            AND c.id IS NOT NULL
            AND JSON_CONTAINS(c.grant_types, '"client_credentials"')
            AND NOT JSON_CONTAINS(c.grant_types, '"authorization_code"')
        )
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT =
            '0057: a service-account application also has other bindings; unbind them first';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM migration_0057_service_account_applications t
        JOIN authentication_policies p
          ON JSON_CONTAINS(
                 JSON_EXTRACT(p.conditions, '$.application_ids'),
                 JSON_QUOTE(t.application_id)
             )
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT =
            '0057: a service-account application is referenced by an authentication policy';
    END IF;
END;

-- 名乗り（binding）は CASCADE で一緒に消える。
DELETE a FROM applications a
JOIN migration_0057_service_account_applications t ON t.application_id = a.id;

DROP TEMPORARY TABLE migration_0057_service_account_applications;

-- ---------------------------------------------------------------------------
-- 2) 名乗りを 4 種類へ広げる
-- ---------------------------------------------------------------------------
--
-- CHECK 制約は列を名指ししているので、改名の前に外す。
ALTER TABLE application_bindings
    DROP CONSTRAINT application_bindings_target_chk,
    DROP CONSTRAINT application_bindings_protocol_chk;

ALTER TABLE application_bindings
    RENAME COLUMN protocol TO kind;

ALTER TABLE application_bindings
    MODIFY COLUMN kind VARCHAR(16) NOT NULL COMMENT 'oidc / saml / service_account / resource',
    MODIFY COLUMN client_id CHAR(36) NULL
        COMMENT 'kind = oidc / service_account のときの clients.id',
    MODIFY COLUMN service_provider_id CHAR(36) NULL
        COMMENT 'kind = saml のときの saml_service_providers.id',
    ADD COLUMN resource_id CHAR(36) NULL COMMENT 'kind = resource のときの resources.id'
        AFTER service_provider_id,
    -- ⚠ 1 つの宛名は 1 つのアプリにだけ属する。2 つに属せると、その宛名のトークンを誰に出して
    --   よいか（どのアプリの割り当てを見るか）が決まらない。`client_id` の UNIQUE は元からあり、
    --   ログイン用とサービスアカウントの両方に効く（1 つの client は 1 つの名乗りだけ）。
    ADD UNIQUE KEY application_bindings_resource_uk (resource_id),
    ADD CONSTRAINT application_bindings_kind_chk
        CHECK (kind IN ('oidc', 'saml', 'service_account', 'resource')),
    -- 種類と実際に埋まっている列を食い違わせない。どの種類でも、埋まるのはちょうど 1 列。
    ADD CONSTRAINT application_bindings_target_chk CHECK (
        (kind IN ('oidc', 'service_account')
            AND client_id IS NOT NULL AND service_provider_id IS NULL AND resource_id IS NULL)
        OR
        (kind = 'saml'
            AND service_provider_id IS NOT NULL AND client_id IS NULL AND resource_id IS NULL)
        OR
        (kind = 'resource'
            AND resource_id IS NOT NULL AND client_id IS NULL AND service_provider_id IS NULL)
    ),
    ADD CONSTRAINT application_bindings_resource_fk FOREIGN KEY (resource_id)
        REFERENCES resources (id) ON DELETE CASCADE;
