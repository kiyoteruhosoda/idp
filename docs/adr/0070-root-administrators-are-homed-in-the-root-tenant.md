# ADR-0070: root を管理する口座は root を所属元にする（子テナントから扱わせない）

- Status: Accepted
- Date: 2026-10-30
- 関連: `docs/adr/0009-*`（§3 所属元の管理者が口座を治める）、`docs/adr/0069-fine-grained-codes-never-reach-administrators.md`、
  task #757（点検 #729 の API5）

## 背景

ADR-0069 は、ゲストとして他のテナントで持つ権限を「`idp.admins:write` の範囲（`idp.tenant.admin` まで）なら扱える」とした。
所属元の管理者が口座を治める（ADR-0009 §3）という形に沿うためだが、その「他のテナント」が root でも同じ判定だった。

そのため、所属元が子テナントで root の `idp.tenant.admin` を持つ利用者のパスワードや MFA を、子テナントの管理者が作り直して、
root の管理に届けた。テナント同士の境界が、子から親へ破れる形である。

本番で当てはまったのは break-glass の 2 口座だけだった（2026-10-30 に確認）。

## 決定

1. **root の権限を持つ口座は、root 以外のテナントからは操作できない**（`permission::may_manage_account`。
   対象のコードが何であっても断る）。所属元の管理者でも、`idp.admins:write` を持っていても同じ。
2. 他の子テナントのゲストの権限は今までどおり（ADR-0069）。root テナント自身の管理者の扱いも変えない。
3. **root を管理する口座は root を所属元にする。** break-glass の口座は kyon から root へ移す（deploy-repo の
   `nolumia-breakglass move-home`）。root の機械が扱い、kyon へはゲストとして入る。

## 結果

- 所属元が子テナントで root の権限を持つ口座は、パスワードや MFA を管理者が作り直せない。本人が変えるか、root の権限を
  外してからにする。
- ⚠ この判定を配る前に break-glass の口座を移す。移さずに配ると `nolumia-breakglass rotate` が 403 になる。
- 移した後の break-glass の口座は kyon のゲストなので、kyon の管理者は参加の停止・解除だけができる
  （`ensure_may_manage_membership`。root への道は開かない）。
