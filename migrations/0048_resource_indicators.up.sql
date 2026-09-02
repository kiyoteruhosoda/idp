-- リソース指標（RFC 8707）—— トークンに**宛先**を刻めるようにする（ADR-0042）。
--
-- 背景: `client_credentials` で出るトークンの `aud` は `{issuer}/userinfo` 固定で、どのアプリ宛に
-- 出したものかが載っていない。受け取ったリソースサーバは「自分宛か」を判定できず、**あるアプリへ
-- 渡したトークンが別のアプリでもそのまま通る**。実際、blobshare は `aud` の検証を諦めて
-- `client_id` の突き合わせだけで認可している（blobshare ADR-0042）。
--
-- 1) `resources` —— 宛名の登録簿。`resource_uri` が `aud` に入る値そのもの。
-- 2) `client_resources` —— 「どのクライアントがどの宛先を要求してよいか」。
--
-- ⚠ **語彙（`page:write` のような業務権限）は持たせない。** 載せるのは宛名だけで、何をしてよいかは
--   リソースサーバが `client_id` で決める（ADR-0033 を崩さない）。列を用意すると「idp に権限を
--   書けるのだから書こう」という圧力が生まれ、アプリを直すたびに idp を触ることになる。
--
-- ⚠ 管理 API（`{issuer}/admin`）はこの表に載せない。`perms` クレームと短い TTL を持つ別物で
--   （ADR-0037）、同じ表に混ぜると発行時の分岐がかえって増える。

-- 1) Resources（宛名の登録簿）
CREATE TABLE resources (
    id           CHAR(36)     NOT NULL COMMENT 'UUIDv7',
    tenant_id    CHAR(36)     NOT NULL,
    resource_uri VARCHAR(255) NOT NULL
        COMMENT 'aud に入る値。絶対 URI・fragment 不可（RFC 8707 §2）。叩く先ではなく宛名',
    display_name VARCHAR(255) NOT NULL COMMENT '画面に出す名前（例: nolumiawiki の機械 API）',
    status       VARCHAR(16)  NOT NULL DEFAULT 'ACTIVE',
    created_at   DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at   DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    -- 宛名はテナント内で一意。同じ名前が 2 行あると、どちらの許可が効くのかが決まらない。
    UNIQUE KEY resources_tenant_uri_uk (tenant_id, resource_uri),
    CONSTRAINT resources_status_chk CHECK (status IN ('ACTIVE', 'DISABLED')),
    CONSTRAINT resources_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE RESTRICT
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- 2) ClientResources（クライアント ↔ 宛名）
--
-- `client_permissions` と同じ形にする。参照先を `clients.client_id`（テナント内一意）ではなく
-- 代理キー `clients.id` にするのは、クライアント ID を付け替えたときに許可行が孤児にならないため。
-- テナントは `clients.tenant_id` と `resources.tenant_id` がそれぞれ持つので、この表は持たない。
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

-- 3) 権限コードのマスタ（許可値の単一出所。ADR-0006）
INSERT INTO permissions (code, description) VALUES
    ('idp.resources:read',
     'Read protected resources (audiences) and the clients allowed to request them'),
    ('idp.resources:write',
     'Modify protected resources: register, disable, delete, grant and revoke to clients')
ON DUPLICATE KEY UPDATE description = VALUES(description);
