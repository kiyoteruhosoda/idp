-- 管理者の口座を扱う細粒度コード（task #579。脆弱性確認 2026-10-20 の高-1）。
--
-- 背景: 細粒度コードは「テナントの中の分担」のためのもので、集めても管理者には届かない約束
-- （ADR-0037）。ところが `idp.users:write` だけで管理者のパスワード再発行・MFA 解除ができ、
-- `idp.permissions:write` だけで誰にでも `idp.tenant.admin` を付けられた。これを
-- 「呼び出し元が含意する範囲でしか付与・剥奪できない」「自分より強い口座は扱えない」に締める。
--
-- そのうえで、管理者の口座を扱うこと自体を仕事にする主体（break-glass の機械）のために、
-- その範囲を**名指しで**渡すコードを 1 つ足す。`idp.tenant.admin` が含意する（テナント管理者は
-- 今までどおり管理者の口座を扱える）。`idp.system.admin` の持ち主の口座と、その付与には届かない。
INSERT INTO permissions (code, description) VALUES
    ('idp.admins:write',
     'Manage accounts that hold administrative permissions, and grant or revoke idp.tenant.admin')
ON DUPLICATE KEY UPDATE description = VALUES(description);
