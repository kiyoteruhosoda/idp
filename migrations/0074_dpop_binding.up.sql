-- スマホのアプリのトークンを DPoP（RFC 9449）で端末の鍵に結び付ける（ADR-0075。task #893）。
--
-- 1. `refresh_tokens.dpop_jkt`: このリフレッシュトークンを結び付けた鍵の指紋（RFC 7638 の JWK Thumbprint。
--    SHA-256 の base64url で 43 文字）。NULL は結び付けなし（今までどおり、持っていれば使える）。
--    rotation で子へ引き継ぐ。expand のみ（既存の行は NULL のまま動く）。
ALTER TABLE refresh_tokens
    ADD COLUMN dpop_jkt VARCHAR(64) NULL COMMENT 'DPoP で結び付けた鍵の JWK Thumbprint（NULL = 結び付けなし）';

-- 2. `dpop_proof_jtis`: 受けた DPoP の証明（鍵ごとの jti）を 1 回だけにするための記録（ADR-0075 決定 4）。
--    「使われていなければ記録する」を主キーへの INSERT 1 回で判定する（client_assertion_jtis と同じ形）。
--    主キーは `sha256(jkt ":" jti)` の 16 進。利用者が決める jti をそのまま主キーの長さに載せない。
--    受ける幅（iat の前後）を過ぎれば同じ証明は時刻で断られるので、`expires_at` を過ぎた行は掃除してよい。
CREATE TABLE dpop_proof_jtis (
    proof_hash CHAR(64)    NOT NULL COMMENT 'sha256(jkt:jti) の 16 進',
    expires_at DATETIME(6) NOT NULL COMMENT 'この時刻を過ぎたら同じ証明は時刻で断られる（掃除してよい）',
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (proof_hash),
    KEY dpop_proof_jtis_expiry_idx (expires_at)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
