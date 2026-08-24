-- テナントへドメインを排他的に割り当てる（MT25。ADR-0029）。
--
-- 参加先テナントのログイン画面は「そのテナントの HOME 利用者 ∪ 参加中のゲスト（各自の所属元の
-- 登録簿）」を解決するが、識別子の一意性は 1 テナントの中でしか担保していない。ゲストは所属元を
-- またいで集まるので、同じユーザー名のゲストが 2 人参加した時点でその入力は 2 人に当たり、
-- fail-closed の解決によって**その 2 人とも参加先の画面から入れなくなる**。
--
-- 一意性をクロステナントへ広げると ADR-0009 §1 のテナント独立が壊れる（あるテナントが `admin` を
-- 取ると他のどのテナントでも使えなくなる）。代わりに **ドメインを 1 つのテナントへ排他的に持たせ**、
-- `local@domain` の形の入力はドメインから所属元テナントを 1 つに決めて、そのテナントの登録簿だけを
-- 引く（home realm discovery）。1 テナントの中では 1 正規化値が 1 人のものなので（migration 0041）、
-- この経路では曖昧さが原理的に起きない。
--
-- Entra ID の UPN がグローバル一意なのも同じ理屈で、全体空間が一意なのではなく
-- 「ドメイン × その中のローカル部」が一意である。
CREATE TABLE tenant_domains (
    id         CHAR(36)     NOT NULL
        COMMENT '内部識別子（UUIDv7）',
    tenant_id  CHAR(36)     NOT NULL
        COMMENT 'このドメインを所有するテナント。1 テナントは複数持てる（合併・旧ドメインの併存）',
    domain     VARCHAR(253) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL
        COMMENT '正規化済みドメイン（小文字・末尾ドットなし・A ラベル）。DNS の上限が 253 文字',
    created_at DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    -- **グローバルに一意**（テナントを含めない）。1 ドメインが 2 テナントを指すと所属元が決まらず、
    -- この表を作った意味が無くなる。ログイン経路の等値検索もこの索引に乗る。
    UNIQUE KEY tenant_domains_domain_uk (domain),
    -- テナントのドメイン一覧（管理 API）。
    KEY tenant_domains_tenant_idx (tenant_id),
    -- テナントが消えたら紐づけも消す。ドメインは再び割り当て可能に戻るべきで、消えたテナントの名で
    -- 押さえ続ける理由がない（`users` / `clients` の RESTRICT とは意味が違う）。
    CONSTRAINT tenant_domains_tenant_fk FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
