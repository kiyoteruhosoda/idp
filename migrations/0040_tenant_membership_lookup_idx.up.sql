-- 参加先テナントのゲストを解決する引き方（ADR-0009 §8）に索引を合わせる。
--
-- `UserRepository::find_active_guest_by_login_identifier` は「要求テナントに ACTIVE な GUEST として
-- 参加している利用者」から入り、その利用者の所属元の登録簿（`user_login_identifiers`）へ辿る。
-- ところが `tenant_memberships` で `tenant_id` から辿れる索引は PK `(tenant_id, user_id)` だけで
-- （もう 1 本の `tenant_memberships_user_idx` は `user_id` 始まりのためこの引き方には効かない）、
-- 先頭列で絞れるのは**当該テナントの全メンバー**まで（HOME 行も同じ表に入る）。
-- `membership_type` / `status` は読んでから捨てることになり、走査量がテナントのメンバー数に比例する。
--
-- この経路が走るのは所属元での解決が空振りしたとき、つまり**参加先の画面からのゲストのログイン
-- すべて**と、**存在しないユーザー名でのログイン試行**のたびである。前者は通常のログインであり、
-- 後者は総当たりが最も送ってくる形でもある。認証のホットパスをメンバー数に比例させないため、
-- ACTIVE な GUEST だけを索引だけで取り出せるようにする（通常はテナントあたり少数）。
--
-- PK と先頭列が重複するが、PK は続く列が `user_id` で種別・状態を絞れないため置き換えにはならない。
-- 列順は等値条件の並び（テナント → 種別 → 状態）に合わせる。

ALTER TABLE tenant_memberships
    ADD KEY tenant_memberships_tenant_type_status_idx (tenant_id, membership_type, status);
