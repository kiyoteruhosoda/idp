# ADR-0069: 細粒度コードは管理者へ届かない（付与と口座の操作を、呼び出し元の権限で縛る）

- Status: Accepted
- Date: 2026-10-21
- 関連: `docs/adr/0037-management-api-access-tokens-and-permission-set.md`（細粒度コードとクライアント主体）、
  task #579（脆弱性確認 2026-10-20 の高-1）

## 背景

細粒度コード（`idp.users:write` など）は「テナントの中の分担」のためのもので、集めても
`idp.tenant.admin` / `idp.system.admin` には届かない、というのが ADR-0037 の約束だった。
ところが各口は「その口のコードを持つか」しか見ていなかったので、次の 3 つで約束が破れていた。

- `idp.users:write` だけで、管理者のパスワード再発行・MFA 解除ができ、返る設定リンクでなりすませた
  （root ではシステム管理者まで）
- `idp.permissions:write` だけで、自分の持たないコード（`idp.tenant.admin`・`idp.smtp:write`）を付けられた
- `idp.clients:write` だけで、クライアントへ自分の持たないコードを付けられた

一方で、break-glass の機械（deploy-repo の `host/breakglass`）は、非常用口座へ `idp.tenant.admin` を
付け、その口座のパスワードを作り直すことを仕事にしている。機械は包括コードを持てない（ADR-0037 §5）。

## 決定

1. **付与・剥奪は、呼び出し元が含意する範囲だけ**（`permission::may_assign`）。利用者へもクライアントへも同じ。
   剥奪も縛る（自分の持たないコードを外せると、管理者から `idp.tenant.admin` を外して締め出せる）。
   付与フォームの候補も同じ判定で絞る。
2. **口座の操作は、対象の権限を全部、呼び出し元が付与できるときだけ**（`permission::may_manage_account`）。
   対象の権限は**すべての scope で**見る（ゲストとして他のテナントで持つもの）。メンバーシップの停止・解除は
   要求テナントの scope だけを見る。判定は `AdminAccountGuard` が各口の本体の前で行う。
3. **例外の口として `idp.admins:write` を足す。** `idp.tenant.admin` の範囲までの口座の操作と付与・剥奪を
   名指しで渡す。`idp.tenant.admin` が含意し、クライアントにも付けられる。⚠ `idp.system.admin` の持ち主の口座と、
   その付与には届かない。
4. 呼び出し元の権限は管理トークンの `perms`（`RequirePerms` と同じ材料）で見る。

## 結果

- break-glass の 2 つの機械には `idp.admins:write` を足す（持ち主が管理コンソールで付ける）。付けるまで
  `create` / `rotate` は 403 になる。
- テナント管理者は今までどおり、ゲストとして他のテナントの管理者を兼ねる自テナントの口座も扱える
  （所属元の管理者が口座を治める、という ADR-0009 §3 の形は変えていない）。
