-- `idp.smtp:*` の説明を「root テナントのみ」から「scope のテナントの経路」へ改める（ADR-0058 §8）。
--
-- ADR-0051 §3 は、このコードを root scope でしか持てないとしていた。根拠は「`system_settings` は
-- テナント列を持たない全体の表で、テナントの中で配ると全テナントのメール経路を変えられる」だった。
-- ADR-0058 でテナントごとの経路（`tenant_settings`）ができ、その根拠が消えたので覆す。
--
-- 付与の可否はデータではなく Rust 側（`domain::permission::is_grantable_in_tenant`）が決める。
-- ここで直すのは画面の付与フォームに出る説明だけである ——説明が「root のみ」のまま残ると、
-- 配れるのに配ってはいけないように読める。
-- ⚠ 全体の経路の口（`/admin/system-settings/smtp`）は、今までどおり要求テナントが root でなければ 403。
UPDATE permissions
   SET description = 'Read the SMTP settings of the tenant (password is never returned; the whole-IdP route only in the root tenant)'
 WHERE code = 'idp.smtp:read';
UPDATE permissions
   SET description = 'Modify the SMTP settings of the tenant (the whole-IdP route only in the root tenant)'
 WHERE code = 'idp.smtp:write';
