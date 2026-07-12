-- 自己登録（POST /{tenant_id}/auth/register）のテナント単位トグル（SEC6）。
-- 従来は全テナントで無条件開放だったが、既定 OFF（0）に倒す（fail-closed）。
-- 有効化はテナント管理者（idp.tenant.admin）が設定画面のテナント設定区画から行う。
ALTER TABLE tenants
    ADD COLUMN self_registration_enabled TINYINT(1) NOT NULL DEFAULT 0
        COMMENT '自己登録（/auth/register）を許可するか。既定は無効（SEC6）'
        AFTER status;
