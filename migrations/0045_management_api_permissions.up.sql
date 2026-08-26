-- IdP 管理 API の権限セット（リソース × 読み書き）と、クライアントへの権限付与（ADR-0037）。
--
-- 背景: 権限コードは `idp.system.admin` / `idp.tenant.admin` の 2 つしか無く、管理 API を
-- 1 つでも呼ばせたい相手には**管理操作すべて**を渡すしかなかった。利用者の棚卸しをしたいだけの
-- バッチに、クライアント削除も設定変更もできる資格情報を配ることになる。
--
-- 1) 権限コードのマスタへ、リソース × 読み書きの粒度を追加する。
--    `idp.tenant.admin` はこれらすべてを含む上位として残す（含意は Rust 側 `domain::permission`
--    が単一の出所として持つ。DB には含意関係を持たせない —— 判定が 2 か所に分かれるため）。
--    したがって**既存の付与行は 1 行も書き換えない**。今の管理者は今までどおり全部を通る。
--
-- 2) `client_permissions` を追加し、システム用クライアント（`client_credentials`）自身へ
--    権限コードを付与できるようにする。主体が `client_id` のまま一貫する（ADR-0033）。

-- 1) 権限コードのマスタ（許可値の単一出所。ADR-0006）
INSERT INTO permissions (code, description) VALUES
    ('idp.users:read',
     'Read users: search, fetch, list login identifiers'),
    ('idp.users:write',
     'Modify users: create, update, delete, reset password/MFA, unlock, manage login identifiers'),
    ('idp.clients:read',
     'Read OAuth/OIDC clients and their status'),
    ('idp.clients:write',
     'Modify OAuth/OIDC clients: create, update, delete, rotate secret'),
    ('idp.members:read',
     'Read tenant members'),
    ('idp.members:write',
     'Modify tenant members: invite, suspend/resume, revoke guest membership'),
    ('idp.permissions:read',
     'Read permission grants of users and clients'),
    ('idp.permissions:write',
     'Grant and revoke permissions (idp.system.admin still requires idp.system.admin)'),
    ('idp.audit:read',
     'Read audit logs'),
    ('idp.keys:read',
     'Read signing keys (public material and status)'),
    ('idp.keys:write',
     'Modify signing keys: generate, retire, delete'),
    ('idp.tenant-settings:read',
     'Read the settings of the requested tenant (display name etc.)'),
    ('idp.tenant-settings:write',
     'Modify the settings of the requested tenant (display name etc.)'),
    ('idp.authentication-policies:read',
     'Read authentication policies'),
    ('idp.authentication-policies:write',
     'Modify authentication policies'),
    ('idp.external-idps:read',
     'Read external identity provider configurations'),
    ('idp.external-idps:write',
     'Modify external identity provider configurations'),
    ('idp.saml-service-providers:read',
     'Read SAML service providers'),
    ('idp.saml-service-providers:write',
     'Modify SAML service providers')
ON DUPLICATE KEY UPDATE description = VALUES(description);

-- 2) ClientPermissions（クライアント ↔ 権限）
--
-- scope 列を置かないのは、`clients.id` が既にテナントを一意に決めるためである（`clients.tenant_id`）。
-- 列を足すと「クライアントの所属テナント」と「権限の scope」が食い違う状態を表現できてしまい、
-- どちらが正なのかを毎回問うことになる。**表せない状態は作らない。**
--
-- 参照先を `clients.client_id`（テナント内一意）ではなく代理キー `clients.id` にするのは、
-- クライアント ID を付け替えたときに権限行が孤児にならないようにするため。
CREATE TABLE client_permissions (
    client_id       CHAR(36)    NOT NULL
        COMMENT '対象クライアント（clients.id。テナントは clients.tenant_id が持つ）',
    permission_code VARCHAR(64) NOT NULL,
    granted_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (client_id, permission_code),
    KEY client_permissions_code_idx (permission_code),
    CONSTRAINT client_permissions_client_fk FOREIGN KEY (client_id)
        REFERENCES clients (id) ON DELETE CASCADE,
    CONSTRAINT client_permissions_code_fk FOREIGN KEY (permission_code)
        REFERENCES permissions (code) ON DELETE RESTRICT,
    -- 包括的な管理権限はクライアントへ付与させない（ADR-0037）。機械の資格情報は人の資格情報より
    -- 長く生き、失効の導線も弱い。「とりあえず tenant.admin を付ける」を DB 側で塞ぐことで、
    -- 細粒度コードを選ばせる。アプリ層でも同じ判定を行う（二重防御）。
    CONSTRAINT client_permissions_no_blanket_admin_chk
        CHECK (permission_code NOT IN ('idp.system.admin', 'idp.tenant.admin'))
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
