-- ファミリ鍵を取り除く（再利用検知は提示されたトークン 1 本の失効へ戻る）。
ALTER TABLE refresh_tokens
    DROP KEY refresh_tokens_grant_idx,
    DROP COLUMN grant_hash;
