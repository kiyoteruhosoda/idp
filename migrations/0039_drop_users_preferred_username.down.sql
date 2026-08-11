-- 0039 の巻き戻し。`users.preferred_username` を作り直し、登録簿の主識別子から書き戻す。
--
-- 値は登録簿に在るので戻せる。戻らないのは「登録簿へ写せなかった利用者」の分だが、それは
-- 0039 が guard で止めているため、通過した DB には存在しない。

ALTER TABLE users
    ADD COLUMN preferred_username VARCHAR(255)
        CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL
        AFTER email_verified,
    ADD UNIQUE KEY users_tenant_preferred_username_uk (tenant_id, preferred_username);

UPDATE users u
JOIN user_login_identifiers p ON p.primary_of_user = u.id
SET u.preferred_username = p.display_value;
