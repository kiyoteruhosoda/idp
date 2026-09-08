-- セッション単位で引くための索引を外す（`sid` 列そのものは 0021 のもので、ここでは触らない）。
ALTER TABLE refresh_tokens
    DROP KEY refresh_tokens_sid_idx;
