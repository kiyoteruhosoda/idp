-- 0009 の巻き戻し（開発用）。初期管理者の既定パスワードを 0002 seed の旧既定ハッシュ
-- （平文 'ChangeMe!123'）へ戻す。0009 で更新した新既定ハッシュのままの行だけを対象にし、
-- 利用者が変更したパスワードは上書きしない。root は parent_tenant_id IS NULL で特定する。
SET @root := (SELECT id FROM tenants WHERE parent_tenant_id IS NULL);

UPDATE users
SET password_hash = '$argon2id$v=19$m=65536,t=3,p=4$rDuN4UZ1uO9aCuJjci4tQw$9qhizRUIJntV/0+5fsyfdKt5Xmjw6WyEmPOLkOhY7QM'
WHERE tenant_id = @root
  AND email = 'admin@example.com'
  AND password_hash = '$argon2id$v=19$m=65536,t=3,p=4$L1NMbjFwV21BYllKWng5Ng$zTuAfd+FBQlcvMQF9KQyUFGkk2wqYNdAadNiCwKlTnY';
