-- 一意性を種別ごとへ戻す（0041 の巻き戻し）。
--
-- 戻すと「同じ値を種別違いで別人が持つ」を DB が再び許すが、行を落とさないので既存データは
-- そのまま通る（種別を含む方が緩い制約であるため）。
ALTER TABLE user_login_identifiers
    DROP INDEX user_login_identifiers_value_uk,
    ADD UNIQUE KEY user_login_identifiers_value_uk (tenant_id, identifier_type, normalized_value),
    DROP INDEX user_login_identifiers_lookup_idx;
