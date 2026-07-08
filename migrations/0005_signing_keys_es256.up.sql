-- K1: EC(ES256) 対応 — signing_keys.algorithm の許可値に ES256 を追加する。
-- MariaDB では CHECK 制約を DROP して再定義することで許可値を追加する。
-- 既存の RS256 鍵は影響を受けない。

ALTER TABLE signing_keys
    DROP CONSTRAINT IF EXISTS signing_keys_alg_chk;

ALTER TABLE signing_keys
    ADD CONSTRAINT signing_keys_alg_chk CHECK (algorithm IN ('RS256', 'ES256'));
