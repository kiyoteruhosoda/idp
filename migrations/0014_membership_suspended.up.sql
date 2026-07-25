-- ゲストメンバーシップの一時停止（MT24。ADR-0009 §3）。
--
-- 従来、ゲストのアクセスを止める手段は解除（削除）だけだった。解除は当該テナント scope の権限行も
-- 消すため、戻すには招待からやり直しになる。休職・委託の中断のような**一時的**な停止のために
-- `SUSPENDED` を追加し、メンバーシップ行と権限行を保持したままアクセスだけを止められるようにする。
--
-- `is_active_member`（OIDC フローのメンバーシップ判定）は `status = 'ACTIVE'` を見るため、
-- 新しい値の追加だけで停止が効く（判定側の変更は不要）。
--
-- expand フェーズのみ: 許可値を増やすだけで既存行の `status` は変更しない。旧バージョンのアプリは
-- `SUSPENDED` を書かないため、ローリングデプロイ中に混在しても壊れない（読み側は Rust の enum
-- パースを通るが、旧バイナリが `SUSPENDED` 行を読むと未知値エラーになる。ゲストの停止操作は
-- 新バイナリの配置完了後に行うこと）。
ALTER TABLE tenant_memberships
    DROP CONSTRAINT tenant_memberships_status_chk;

ALTER TABLE tenant_memberships
    ADD CONSTRAINT tenant_memberships_status_chk
        CHECK (status IN ('INVITED', 'ACTIVE', 'SUSPENDED'));

ALTER TABLE tenant_memberships
    MODIFY COLUMN status VARCHAR(16) NOT NULL
        COMMENT 'INVITED = 招待中（未承諾） / ACTIVE / SUSPENDED = 一時停止（GUEST のみ）';
