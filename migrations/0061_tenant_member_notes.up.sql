-- メンバーの管理者メモ（ADR-0063）。
--
-- 「どういう経緯のアカウントか」を管理者が書き残す欄。人に向けた自由記述で、判定には一切使わない。
--
-- ⚠ `tenant_memberships` の列にしない。メモは**テナントの管理者が持つ事実**であり、同じ利用者でも
--   テナントごとに別のことを書く（HOME と GUEST 先で経緯は違う）。メンバーシップの行に載せると
--   招待・承諾・停止の全 SELECT と `TenantMembership` 構造体を巻き込むうえ、トークンや userinfo へ
--   写す経路の近くに自由記述を置くことになる。別表にして、読むのは管理画面の経路だけにする。
--
-- メンバーシップが消えればメモも消える（複合外部キーで CASCADE）。ゲストを解除して招き直したとき、
-- 前回のメモが黙って復活する形にはしない。
CREATE TABLE tenant_member_notes (
    tenant_id  CHAR(36)    NOT NULL,
    user_id    CHAR(36)    NOT NULL,
    note       TEXT        NOT NULL COMMENT '管理者メモ（自由記述。空にしたら行ごと消す）',
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_by CHAR(36)    NULL COMMENT '最後に書いた管理者（users.id）。機械経由は NULL',
    PRIMARY KEY (tenant_id, user_id),
    CONSTRAINT tenant_member_notes_membership_fk FOREIGN KEY (tenant_id, user_id)
        REFERENCES tenant_memberships (tenant_id, user_id) ON DELETE CASCADE,
    -- 書いた管理者が消えてもメモは残す（`application_assignments.assigned_by` と同じ方針）。
    CONSTRAINT tenant_member_notes_updated_by_fk FOREIGN KEY (updated_by)
        REFERENCES users (id) ON DELETE SET NULL
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
