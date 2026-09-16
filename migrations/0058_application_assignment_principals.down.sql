-- 0058 の巻き戻し。
--
-- サービスアカウントの割り当ては、宛名の貸し出し（`client_resources`）へ戻す。割り当て 1 行
-- （A, client）は、「A が名乗る宛名」のそれぞれへの貸し出しになる（A が宛名を名乗っていなければ、
-- 戻す相手が無いので消えるだけ ——その割り当ては元からトークンを出していなかった）。
--
-- ⚠ 戻した後の判定は「宛名がクライアントへ貸されているか」になる。0058 の後に宛名の名乗りを
--   別のアプリへ付け替えていた場合、貸し出しは付け替え後のアプリの割り当てから作られる。

-- `client_resources` は 0048 と同じ定義で作り直す（ENGINE・CHARSET・COLLATE まで揃えないと
-- 外部キーが errno 150 で落ちる）。
CREATE TABLE client_resources (
    client_id   CHAR(36)    NOT NULL COMMENT '要求する側（clients.id）',
    resource_id CHAR(36)    NOT NULL COMMENT '要求してよい宛名（resources.id）',
    granted_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (client_id, resource_id),
    KEY client_resources_resource_idx (resource_id),
    CONSTRAINT client_resources_client_fk FOREIGN KEY (client_id)
        REFERENCES clients (id) ON DELETE CASCADE,
    CONSTRAINT client_resources_resource_fk FOREIGN KEY (resource_id)
        REFERENCES resources (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

INSERT INTO client_resources (client_id, resource_id, granted_at)
SELECT a.client_id, b.resource_id, a.assigned_at
FROM application_assignments a
JOIN application_bindings b ON b.application_id = a.application_id AND b.kind = 'resource'
WHERE a.kind = 'SERVICE_ACCOUNT';

DELETE FROM application_assignments WHERE kind = 'SERVICE_ACCOUNT';

ALTER TABLE application_assignments
    DROP FOREIGN KEY application_assignments_client_fk,
    DROP CONSTRAINT application_assignments_principal_chk,
    DROP CONSTRAINT application_assignments_kind_chk;

ALTER TABLE application_assignments
    DROP PRIMARY KEY,
    DROP INDEX application_assignments_client_uk,
    DROP INDEX application_assignments_client_idx,
    MODIFY COLUMN user_id CHAR(36) NOT NULL,
    ADD PRIMARY KEY (application_id, user_id);

ALTER TABLE application_assignments
    DROP INDEX application_assignments_user_uk,
    DROP COLUMN client_id,
    DROP COLUMN kind,
    DROP COLUMN id;
