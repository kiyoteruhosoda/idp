-- `audit_log` の絞り込み索引を、管理コンソールが実際に投げる形へ揃える（G8）。
--
-- これまでの索引は `event_type` / `correlation_id` / `occurred_at` / `tenant_id` の**単一列 4 本**
-- だった。一方、管理コンソール（`GET /{tenant_id}/admin/audit-logs`）の絞り込みは常に
-- 「テナント × 期間」を土台に、`event_type` / `result` / `client_id` を足す形になる
-- （テナント越しの閲覧は API が禁じているため、`tenant_id` の無い検索は起こらない）。
--
-- 単一列 `tenant_id` の索引ではテナント内の**全期間**を読んでから期間で絞ることになり、
-- 監査ログのように行が増え続ける表では期間検索が事実上の全表走査になる。`client_id` と
-- `user_id` には索引そのものが無く、1 クライアント・1 利用者の履歴を出す操作も同様だった。
--
-- # 索引の選び方
--
-- 先頭列を `tenant_id`、末尾列を `occurred_at` にした複合索引を、絞り込み項目ごとに置く。
-- 末尾に `occurred_at` を置くのは、範囲条件（`from`/`to`）と `ORDER BY occurred_at DESC` の
-- 両方をひとつの索引で賄うため（等値条件の後ろに範囲条件が来る並びでないと索引が効かない）。
--
-- `result` は値が 2 種類しかなく単独では選択性が無いが、`(tenant_id, result, occurred_at)` は
-- 「このテナントの、失敗だけを、この期間で」という**エラー絞り込み**（本表の主な用途）を
-- 索引だけで完結させられる。単一列の `result` 索引は作らない（選択性が無く、書き込みの
-- 負担だけが残る）。
--
-- 既存の単一列索引のうち、
--   - `audit_log_tenant_idx (tenant_id)` は `(tenant_id, occurred_at)` の先頭部分と重複するため落とす。
--   - `audit_log_event_idx (event_type)` はテナントを跨いだ検索が無いため落とす
--     （`(tenant_id, event_type, occurred_at)` が置き換える）。
--   - `audit_log_occurred_idx (occurred_at)` は残す。保持期間による削除（`AUDIT_LOG_RETENTION_DAYS`）が
--     テナントを跨いで `occurred_at < cutoff` を引くため、この索引だけは tenant 非依存で要る。
--   - `audit_log_correlation_idx (correlation_id)` は残す。追跡はテナントを跨いで引く。
--
-- 索引の本数は 4 本から 6 本になる。`audit_log` は追記専用（更新・削除は保持期間の一括削除のみ）で、
-- 1 行あたりの挿入コストの増加より、参照が全表走査に落ちないことを優先する。

ALTER TABLE audit_log
    DROP INDEX audit_log_tenant_idx,
    DROP INDEX audit_log_event_idx,
    ADD KEY audit_log_tenant_occurred_idx (tenant_id, occurred_at),
    ADD KEY audit_log_tenant_event_occurred_idx (tenant_id, event_type, occurred_at),
    ADD KEY audit_log_tenant_result_occurred_idx (tenant_id, result, occurred_at),
    ADD KEY audit_log_tenant_client_occurred_idx (tenant_id, client_id, occurred_at),
    ADD KEY audit_log_tenant_user_occurred_idx (tenant_id, user_id, occurred_at);
