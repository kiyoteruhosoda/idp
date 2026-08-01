-- 認証ポリシー（ユーザー認証・認証ポリシー仕様書 §7）。
--
-- テナント単位で「認証時に満たすべき条件（拒否・MFA 必須）」を管理する。評価は Rust の
-- ドメイン層（domain/authentication_policy.rs）が行い、本テーブルは規則の保存のみを担う。
-- effect は DB ネイティブ ENUM を使わず VARCHAR + CHECK（許可値の単一の出所は Rust 側 enum）。
-- conditions は JSON（client_ids / user_ids。空 = 制限しない）。時刻は UTC の DATETIME(6)。
CREATE TABLE authentication_policies (
    id          CHAR(36)     NOT NULL
        COMMENT '内部識別子（UUID 正準文字列）',
    tenant_id   CHAR(36)     NOT NULL
        COMMENT 'ポリシーを所有するテナント（テナント越しに適用されない）',
    policy_code VARCHAR(100) NOT NULL
        COMMENT 'テナント内一意の識別コード（監査ログ・API パスに載る英数字と -_.）',
    policy_name VARCHAR(200) NOT NULL
        COMMENT '管理画面表示用の名称',
    priority    INT          NOT NULL
        COMMENT '評価順（昇順 = 小さいほど優先）',
    enabled     BOOLEAN      NOT NULL DEFAULT TRUE
        COMMENT '無効化されたポリシーは評価対象外',
    effect      VARCHAR(30)  NOT NULL
        COMMENT 'ポリシー効果（allow / deny / require_mfa）',
    conditions  JSON         NOT NULL
        COMMENT '適用条件（client_ids / user_ids。空 = 制限しない）',
    created_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY authentication_policies_code_uq (tenant_id, policy_code),
    KEY authentication_policies_tenant_idx (tenant_id, enabled, priority),
    CONSTRAINT authentication_policies_effect_chk
        CHECK (effect IN ('allow', 'deny', 'require_mfa')),
    CONSTRAINT authentication_policies_tenant_fk FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
