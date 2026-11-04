-- 0075 の巻き戻し。
ALTER TABLE sso_session_contexts
    DROP FOREIGN KEY sso_session_contexts_approver_key_fk,
    DROP INDEX sso_session_contexts_approver_key_idx,
    DROP COLUMN approver_key_id;
DROP TABLE app_approval_requests;
DROP TABLE app_approver_enrollments;
DROP TABLE app_approver_keys;
