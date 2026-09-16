-- 0057 の巻き戻し: `idp.smtp:*` の説明を 0053 の文言へ戻す。
--
-- ⚠ 説明を戻すだけで、テナントの中で既に付与した行は消さない（付与の可否は Rust 側が決める）。
--   コードを巻き戻して root に限るなら、root 以外で付与した行は手で外すこと。
UPDATE permissions
   SET description = 'Read the system SMTP settings (password is never returned; root tenant only)'
 WHERE code = 'idp.smtp:read';
UPDATE permissions
   SET description = 'Modify the system SMTP settings (root tenant only)'
 WHERE code = 'idp.smtp:write';
