-- 主識別子として作った行を落とし、`primary_of_user` 列を撤去する。
--
-- `users.preferred_username` は本マイグレーションで触っていない（このリリースは「両方に在る期間」で、
-- 書き込みは両方へ行う）。したがって主識別子を戻す必要は無く、登録簿側を元に戻すだけでよい。
--
-- **格上げした行は消さない。** 管理者が追加識別子として登録していた行を主へ格上げしただけなので、
-- 消すとその利用者がその値でログインできなくなる（元から在った設定を巻き添えにしない）。
-- 見分けは `users.preferred_username` と一致するかではなく「本マイグレーションが作ったか」だが、
-- それを列で持っていないため、**作成時刻が更新時刻と等しい行**（＝以後に更新されていない、
-- ここで作られた行）だけを消す。判別できない行は残す方に倒す（消しすぎるとログインが失われる）。
DELETE i FROM user_login_identifiers i
JOIN users u ON u.id = i.user_id
WHERE i.primary_of_user IS NOT NULL
  AND i.identifier_type = 'username'
  AND i.normalized_value = LOWER(TRIM(COALESCE(u.preferred_username, '')))
  AND i.created_at = i.updated_at;

ALTER TABLE user_login_identifiers
    DROP INDEX user_login_identifiers_primary_uk,
    DROP CONSTRAINT user_login_identifiers_primary_ck,
    DROP COLUMN primary_of_user;
