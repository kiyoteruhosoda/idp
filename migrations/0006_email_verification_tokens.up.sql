-- 自己登録アカウントのメール検証トークン（SEC6b）。
-- 平文トークンはメールのリンクでのみ本人へ渡し、DB には SHA-256 hex のみ保存する
-- （password_reset_tokens / invitation_token_hash と同方式）。used_at 設定で単回消費とする。
CREATE TABLE email_verification_tokens (
    token_hash VARCHAR(64) NOT NULL COMMENT '検証トークンの SHA-256 hex。平文は保存しない',
    user_id    CHAR(36)    NOT NULL COMMENT '対象ユーザー（users.id）',
    expires_at DATETIME(6) NOT NULL COMMENT '失効時刻（UTC）',
    used_at    DATETIME(6) NULL COMMENT '消費時刻。NULL = 未使用。単回消費の判定に使う',
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (token_hash),
    KEY email_verification_tokens_user_idx (user_id),
    CONSTRAINT email_verification_tokens_user_fk
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
