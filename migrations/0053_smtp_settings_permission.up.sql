-- メール送信（SMTP）設定だけを触れる細粒度コード（ADR-0051）。
--
-- 背景: システム設定は `idp.system.admin` の完全一致でしか触れず（ADR-0037 §4）、その包括コードは
-- クライアントへ**付与できない**（同 §5 の CHECK 制約）。つまり SMTP の設定を機械から入れる手段が
-- 無く、SMTP パスワードを人が画面へ手で貼るしかなかった ——秘密が人の手とクリップボードを通る。
--
-- 分割するのは SMTP の 1 枚だけである。再起動・テナント作成・テナント横断のログ参照は
-- 引き続き `idp.system.admin` の完全一致だけが通る。
--
-- ⚠ **この 2 つは root scope でしか保有できない。** `system_settings` はテナント列を持たない
--    システム全体の表なので、テナントの中で配れるようにすると、そのテナントの管理者が
--    全テナントのメール経路を変えられる。判定の単一の出所は Rust 側
--    （`domain::permission::ROOT_SCOPED_CODES` と `is_grantable_in_tenant`）に置く
--    ——`client_permissions` には scope 列が無く（クライアントの所属テナントが scope）、
--    DB だけでは「root のクライアントか」を CHECK で表せないため。
INSERT INTO permissions (code, description) VALUES
    ('idp.smtp:read',
     'Read the system SMTP settings (password is never returned; root tenant only)'),
    ('idp.smtp:write',
     'Modify the system SMTP settings (root tenant only)')
ON DUPLICATE KEY UPDATE description = VALUES(description);
