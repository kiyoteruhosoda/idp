-- ADR-0050 の巻き戻し。
--
-- 主メール行は**消す**。残すと、戻したコード（`users.email` を登録簿へ同期しない）が
-- メールアドレスを変更したときに古い値の行が居座り、その値で誰も登録できなくなる。
-- 管理者が明示的に足した `email` 種別の行（`primary_email_of_user IS NULL`）は残す。
DELETE FROM user_login_identifiers WHERE primary_email_of_user IS NOT NULL;

ALTER TABLE user_login_identifiers
    DROP INDEX user_login_identifiers_primary_email_uk,
    DROP CONSTRAINT user_login_identifiers_primary_email_self_ck,
    DROP COLUMN primary_email_of_user;

ALTER TABLE tenants
    DROP COLUMN email_login_enabled;
