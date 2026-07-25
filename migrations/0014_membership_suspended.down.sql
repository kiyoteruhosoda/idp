-- 0014 の巻き戻し（MT24）。
--
-- 巻き戻し時点で残っている `SUSPENDED` 行は旧 CHECK に違反するため、先に別の値へ倒す必要がある。
-- **`ACTIVE` には戻さない**: 管理者が意図して止めたゲストのアクセスが、スキーマのロールバックという
-- 無関係な操作で黙って復活してしまうため。`INVITED`（＝ 非 ACTIVE）へ倒せば停止状態は保たれる。
-- 招待トークン（`invitation_token_hash`）は NULL のままなので誰も承諾できず、管理者が改めて
-- 再招待するか解除するかを選べる。
UPDATE tenant_memberships SET status = 'INVITED' WHERE status = 'SUSPENDED';

ALTER TABLE tenant_memberships
    DROP CONSTRAINT tenant_memberships_status_chk;

ALTER TABLE tenant_memberships
    ADD CONSTRAINT tenant_memberships_status_chk
        CHECK (status IN ('INVITED', 'ACTIVE'));

ALTER TABLE tenant_memberships
    MODIFY COLUMN status VARCHAR(16) NOT NULL
        COMMENT 'INVITED = 招待中（未承諾） / ACTIVE';
