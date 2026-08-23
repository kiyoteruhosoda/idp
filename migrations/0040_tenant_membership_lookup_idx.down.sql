-- 索引を落とすだけ（行データは変えない）。解決は PK 先頭列の走査へ戻る。
ALTER TABLE tenant_memberships
    DROP INDEX tenant_memberships_tenant_type_status_idx;
