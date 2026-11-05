-- 0074 の巻き戻し。結び付けの記録は失われる（結び付けていたリフレッシュトークンは、鍵なしでも使えるようになる）。
DROP TABLE IF EXISTS dpop_proof_jtis;
ALTER TABLE refresh_tokens DROP COLUMN dpop_jkt;
