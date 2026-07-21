-- 初期管理者 admin@example.com の既定パスワードを、メールアドレスと同じ 'admin@example.com' へ更新する。
--
-- 0002 seed が投入した旧既定ハッシュ（平文 'ChangeMe!123'）のままのアカウントに限定して置き換える。
-- 利用者が既に変更したパスワードは上書きしない（旧既定ハッシュに一致する行だけが対象）。
-- 追記型マイグレーション（migrations/README.md）に従い 0002 は書き換えず、本マイグレーションで更新する。
--
-- 冪等性: 再適用しても、新ハッシュに一致する行は WHERE 条件（= 旧既定ハッシュ）で除外されるため二重更新
-- されない。root は parent_tenant_id IS NULL の唯一の行として構造的に特定する（0002 と同じ方針）。
-- 新ハッシュはアプリと同一の Argon2id（PHC 文字列、m=65536,t=3,p=4）で、平文はコードに保持しない。
SET @root := (SELECT id FROM tenants WHERE parent_tenant_id IS NULL);

UPDATE users
SET password_hash = '$argon2id$v=19$m=65536,t=3,p=4$L1NMbjFwV21BYllKWng5Ng$zTuAfd+FBQlcvMQF9KQyUFGkk2wqYNdAadNiCwKlTnY',
    must_change_password = 1
WHERE tenant_id = @root
  AND email = 'admin@example.com'
  AND password_hash = '$argon2id$v=19$m=65536,t=3,p=4$rDuN4UZ1uO9aCuJjci4tQw$9qhizRUIJntV/0+5fsyfdKt5Xmjw6WyEmPOLkOhY7QM';
