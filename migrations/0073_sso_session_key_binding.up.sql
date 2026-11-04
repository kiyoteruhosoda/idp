-- SSO セッションを端末の鍵へ結び付ける（DBSC。task #887・ADR-0074）。
--
-- 結び付けは `sso_session_contexts`（ADR-0071）に置く。`sso_sessions` に列を足さない理由は 0068 と同じ。
-- 1 つのログイン状態に結び付けは 1 回だけ（`key_bound_at` が入ったら書き換えない）。
-- 公開鍵は JWK（JSON）のまま置く。秘密ではないが、指紋（RFC 7638）で引き比べられるようにも持つ。
ALTER TABLE sso_session_contexts
    ADD COLUMN key_session_identifier CHAR(32)     NULL COMMENT 'DBSC の結び付けの識別子（Chrome が Sec-Secure-Session-Id で送る）',
    ADD COLUMN key_algorithm          VARCHAR(8)   NULL COMMENT '署名の方式（ES256 / RS256）',
    ADD COLUMN key_public_jwk         TEXT         NULL COMMENT '結び付けた公開鍵（JWK）',
    ADD COLUMN key_thumbprint         CHAR(43)     NULL COMMENT '公開鍵の指紋（RFC 7638・SHA-256・base64url）',
    ADD COLUMN key_bound_at           DATETIME(6)  NULL COMMENT '結び付けた時刻（UTC）',
    ADD COLUMN key_refreshed_at       DATETIME(6)  NULL COMMENT '最後に鍵で署名して更新した時刻（UTC）',
    ADD CONSTRAINT sso_session_contexts_key_algorithm_chk
        CHECK (key_algorithm IS NULL OR key_algorithm IN ('ES256', 'RS256')),
    ADD UNIQUE KEY sso_session_contexts_key_session_uq (key_session_identifier);
