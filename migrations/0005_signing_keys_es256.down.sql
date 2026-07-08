-- K1 ロールバック: ES256 を許可値から除外する（ES256 鍵が存在しない場合のみ安全に適用可能）。
ALTER TABLE signing_keys
    DROP CONSTRAINT IF EXISTS signing_keys_alg_chk;

ALTER TABLE signing_keys
    ADD CONSTRAINT signing_keys_alg_chk CHECK (algorithm IN ('RS256'));
