-- 利用者が自分で登録する SSH の公開鍵（task #885。ADR-0072）。
--
-- 持ち主の PC が乗っ取られても SSH の鍵を持ち出せないよう、登録できるのは sk 型（セキュリティキー・
-- TPM・スマホのパスキーの中に秘密鍵がある鍵）だけにする。ここに置くのは公開鍵だけで、配る側（deploy-repo の
-- host/sshkeys）が機械の口（`GET /{tenant}/admin/ssh-keys`）から読んで各機器の authorized_keys へ書く。
--
-- 鍵は登録した組織（`tenant_id`）ごとに持つ。取り消しは行を消す（経緯は監査ログに残る）。
CREATE TABLE user_ssh_keys (
    id          CHAR(36)     NOT NULL COMMENT 'UUIDv7',
    tenant_id   CHAR(36)     NOT NULL COMMENT '登録した組織（この組織の一覧に載る）',
    user_id     CHAR(36)     NOT NULL COMMENT '登録した利用者',
    name        VARCHAR(100) NOT NULL COMMENT '利用者が付けた名前',
    key_type    VARCHAR(64)  NOT NULL COMMENT '鍵の型（sk-ssh-ed25519@openssh.com・sk-ecdsa-sha2-nistp256@openssh.com）',
    key_blob    VARCHAR(512) NOT NULL COMMENT '公開鍵の本体（base64。authorized_keys の 2 つ目の欄）',
    fingerprint CHAR(50)     NOT NULL COMMENT 'SHA256: で始まる指紋（ssh-keygen -l と同じ値）',
    created_at  DATETIME(6)  NOT NULL COMMENT '登録した時刻（UTC）',
    PRIMARY KEY (id),
    UNIQUE KEY user_ssh_keys_tenant_fingerprint_uq (tenant_id, fingerprint),
    KEY user_ssh_keys_user_idx (user_id),
    CONSTRAINT user_ssh_keys_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT user_ssh_keys_user_fk FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- 配る機械だけが読む細粒度コード。`idp.tenant.admin` が含意する（テナント管理者がクライアントへ付けられる）が、
-- 口はクライアントのトークンしか通さない（人の管理トークンでは読めない）。
INSERT INTO permissions (code, description) VALUES
    ('idp.ssh-keys:read',
     'Read the registered SSH public keys of the tenant (machine clients only)')
ON DUPLICATE KEY UPDATE description = VALUES(description);
