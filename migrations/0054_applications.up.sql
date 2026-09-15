-- アプリ（application）という段を足す（ADR-0054）。
--
-- これまで assay に「アプリ」は無く、プロトコルごとの設定が独立して並んでいるだけだった
-- ——OIDC の `clients` と SAML の `saml_service_providers` が互いを参照しておらず、
-- **同じアプリが OIDC と SAML の両方で繋がる**という普通の形を表せない。その結果、
-- 認証ポリシー・同意・権限・宛名・back-channel logout の配信は**すべて OIDC 側にしか付かない**
-- （SAML のアプリには MFA を要求できない）。
--
-- 1) `applications`         —— アプリそのもの。表示名・状態・**利用者の割り当てモード**を持つ。
-- 2) `application_bindings` —— アプリ ↔ プロトコル設定。1 アプリに 0〜N。
-- 3) `application_assignments` —— アプリ × 利用者。「使ってよいか」の 1 ビット。
--
-- ⚠ この時点では誰も判定に使わない。表と移行だけを入れ、挙動は 1 つも変えない
--   （判定は ADR-0054 の段階導入に従って別のマイグレーション・別のリリースで入る）。

-- 1) Applications
--
-- `display_name` にテナント内一意を課さない。移行で 23 件の `clients.app_name` をそのまま
-- 持ち上げるため、同じ名前の client が 2 つあると移行自体が失敗してしまう。名前は人が読むための
-- ものであって、同一性は `id` が持つ。
CREATE TABLE applications (
    id              CHAR(36)     NOT NULL COMMENT 'UUIDv7',
    tenant_id       CHAR(36)     NOT NULL COMMENT 'アプリを所有するテナント（テナント越しに共有しない）',
    display_name    VARCHAR(255) NOT NULL COMMENT '画面・拒否メッセージに出す名前',
    status          VARCHAR(16)  NOT NULL DEFAULT 'ACTIVE'
        COMMENT 'DISABLED は登録を残したまま利用だけを止める',
    assignment_mode VARCHAR(16)  NOT NULL DEFAULT 'INDIVIDUAL'
        COMMENT 'EVERYONE = テナントの利用者は誰でも / INDIVIDUAL = 割り当てられた利用者だけ',
    created_at      DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at      DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    KEY applications_tenant_idx (tenant_id, display_name),
    CONSTRAINT applications_status_chk CHECK (status IN ('ACTIVE', 'DISABLED')),
    CONSTRAINT applications_assignment_mode_chk CHECK (assignment_mode IN ('EVERYONE', 'INDIVIDUAL')),
    -- `clients` と同じ RESTRICT。テナントを消す前に中身を空にする、という既存の手順を
    -- アプリだけ例外にしない（消えたテナントのアプリだけが残る形も作らない）。
    CONSTRAINT applications_tenant_fk FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE RESTRICT
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- 2) ApplicationBindings（アプリ ↔ 認証方法）
--
-- プロトコル表に `application_id` 列を足すのではなく、独立した表にする。前者だと binding が
-- `clients` / `saml_service_providers` の改修に巻き込まれ（`Client` 構造体・全 SELECT・管理 DTO）、
-- 「表と移行だけを入れて挙動を変えない」という本マイグレーションの約束が守りにくい。
--
-- 参照先は代理キー（`clients.id` / `saml_service_providers.id`）。`clients.client_id` は
-- テナント内一意でしかなく、付け替えたときに binding が孤児になる（`client_resources` と同じ方針）。
--
-- ⚠ 1 つのプロトコル設定は 1 つのアプリにしか属さない（UNIQUE）。両方に属せると、認証ポリシーと
--   割り当てのどちらが効くのかが決まらない。MariaDB の UNIQUE は複数 NULL を許すので、
--   使っていない側の列は素通しになる。
CREATE TABLE application_bindings (
    id                  CHAR(36)    NOT NULL COMMENT 'UUIDv7',
    application_id      CHAR(36)    NOT NULL,
    protocol            VARCHAR(16) NOT NULL COMMENT 'oidc / saml',
    client_id           CHAR(36)    NULL COMMENT 'protocol = oidc のときの clients.id',
    service_provider_id CHAR(36)    NULL COMMENT 'protocol = saml のときの saml_service_providers.id',
    created_at          DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY application_bindings_client_uk (client_id),
    UNIQUE KEY application_bindings_service_provider_uk (service_provider_id),
    KEY application_bindings_application_idx (application_id),
    CONSTRAINT application_bindings_protocol_chk CHECK (protocol IN ('oidc', 'saml')),
    -- protocol と実際に埋まっている列を食い違わせない。片方だけが NOT NULL。
    CONSTRAINT application_bindings_target_chk CHECK (
        (protocol = 'oidc' AND client_id IS NOT NULL AND service_provider_id IS NULL)
        OR
        (protocol = 'saml' AND service_provider_id IS NOT NULL AND client_id IS NULL)
    ),
    CONSTRAINT application_bindings_application_fk FOREIGN KEY (application_id)
        REFERENCES applications (id) ON DELETE CASCADE,
    CONSTRAINT application_bindings_client_fk FOREIGN KEY (client_id)
        REFERENCES clients (id) ON DELETE CASCADE,
    CONSTRAINT application_bindings_service_provider_fk FOREIGN KEY (service_provider_id)
        REFERENCES saml_service_providers (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- 3) ApplicationAssignments（アプリ × 利用者）
--
-- ⚠ ロールの列を持たせない（ADR-0054 の決定 1）。ここに載るのは「使ってよいか」の 1 ビットだけで、
--   アプリの中で何をしてよいかは RP が持つ（ADR-0033 / ADR-0049 の I6）。列を用意すると、
--   G7 で消した `groups` を別の名前で作り直すことになる。
--
-- `assigned_by` は監査のための出所。割り当てた管理者が消えても割り当ては残す（SET NULL）
-- ——消した瞬間に利用者が締め出される方が害が大きい。
CREATE TABLE application_assignments (
    application_id CHAR(36)    NOT NULL,
    user_id        CHAR(36)    NOT NULL,
    assigned_at    DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    assigned_by    CHAR(36)    NULL COMMENT '割り当てた管理者（users.id）。移行・機械経由は NULL',
    PRIMARY KEY (application_id, user_id),
    KEY application_assignments_user_idx (user_id),
    CONSTRAINT application_assignments_application_fk FOREIGN KEY (application_id)
        REFERENCES applications (id) ON DELETE CASCADE,
    CONSTRAINT application_assignments_user_fk FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT application_assignments_assigned_by_fk FOREIGN KEY (assigned_by)
        REFERENCES users (id) ON DELETE SET NULL
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- 4) 既存の OIDC クライアントをアプリへ開く
--
-- SAML の SP は本番に 0 件（2026-09-15 実測）なので、移すのは `clients` だけでよい。
-- 1 client = アプリ 1 件 + OIDC binding 1 件。**まとめない**（同じ `app_name` の client が
-- 2 つあっても別のアプリにする。人が後から束ねられるが、勝手に束ねたものは解けない）。
--
-- ⚠ 生成する行の `id` には、元になった `clients.id` をそのまま使う。
--   * `clients.id` は UUIDv7 なので、採番規約（ADR-0009 §12）を満たす。
--   * 移行が決定的・冪等になり（`WHERE NOT EXISTS` と合わせて何度流しても同じ結果）、
--     `down` で確実に元へ戻せる。
--   * 「このアプリはどの client から開いたか」を、列を足さずに追える。
--   別表なので値が重なっても衝突しない。**同一性を意味する制約は無い**（後からアプリ側だけを
--   作り直せば、当然ずれる）。
--
-- ⚠ `assignment_mode` は既定の `INDIVIDUAL` のまま入れる（ADR-0054 の決定 4「移行は最初から個別」）。
--   この時点で割り当ては 0 件だが、判定がまだどこにも入っていないので誰も締め出されない。
--   名簿は別途 data から書き出す（RP の `federated_identities` ∪ 対応するローカル利用者）。
--
-- 論理削除済み（`client_status = 'DELETED'`。ADR-0035）の client も開く。削除は「使えなくすること」で
-- あって記録を消すことではなく、監査で `client_id` を引いたときにアプリ名が出ないと追えなくなる。
INSERT INTO applications (id, tenant_id, display_name, status, assignment_mode, created_at, updated_at)
SELECT
    c.id,
    c.tenant_id,
    c.app_name,
    CASE WHEN c.client_status = 'ACTIVE' THEN 'ACTIVE' ELSE 'DISABLED' END,
    'INDIVIDUAL',
    c.created_at,
    c.updated_at
FROM clients c
WHERE NOT EXISTS (SELECT 1 FROM applications a WHERE a.id = c.id);

INSERT INTO application_bindings (id, application_id, protocol, client_id, service_provider_id, created_at)
SELECT c.id, c.id, 'oidc', c.id, NULL, c.created_at
FROM clients c
WHERE NOT EXISTS (SELECT 1 FROM application_bindings b WHERE b.client_id = c.id);

-- 5) 権限コードのマスタ（許可値の単一出所。ADR-0006）
INSERT INTO permissions (code, description) VALUES
    ('idp.applications:read',
     'Read applications, their protocol bindings and the users assigned to them'),
    ('idp.applications:write',
     'Modify applications: create, disable, bind protocols, assign and unassign users')
ON DUPLICATE KEY UPDATE description = VALUES(description);
