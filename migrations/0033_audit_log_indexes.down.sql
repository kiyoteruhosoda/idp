-- 0001 のベースラインが持っていた単一列索引の構成へ戻す。行データは変えない。
ALTER TABLE audit_log
    DROP INDEX audit_log_tenant_occurred_idx,
    DROP INDEX audit_log_tenant_event_occurred_idx,
    DROP INDEX audit_log_tenant_result_occurred_idx,
    DROP INDEX audit_log_tenant_client_occurred_idx,
    DROP INDEX audit_log_tenant_user_occurred_idx,
    ADD KEY audit_log_event_idx (event_type),
    ADD KEY audit_log_tenant_idx (tenant_id);
