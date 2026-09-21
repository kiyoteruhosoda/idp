-- 0060 の取り消し。用途の区別を落とし、すべて「本人の再設定」に戻す。
ALTER TABLE password_reset_tokens
    DROP CONSTRAINT password_reset_tokens_purpose_chk,
    DROP COLUMN purpose;
