-- ログイン識別子を preferred_username に統一（ADR-0009 §8）。従来 NULL 許容だった preferred_username を
-- 既存ユーザーについて email と同値で埋め、ログイン（preferred_username 照合）を継続できるようにする。
-- 新規作成時の既定値化（未指定なら email）はアプリ層（register / user_management）で実施する。
--
-- 衝突回避: 従来 email と preferred_username は別々の UNIQUE 索引で、作成経路も他ユーザーの email と
-- 明示 username を突き合わせていなかったため、あるユーザーの email が別ユーザーの preferred_username と
-- 一致し得る。そのまま email を埋めると (tenant_id, preferred_username) UNIQUE 違反でマイグレーションが
-- 中断する。そこで同一テナント内に「その email を既に preferred_username として使う別ユーザー」が
-- 存在しない行だけを埋める（LEFT JOIN + IS NULL）。衝突する行は NULL のまま残し、運用で個別解消する。
UPDATE users u
LEFT JOIN users existing
       ON existing.tenant_id = u.tenant_id
      AND existing.preferred_username = u.email
SET    u.preferred_username = u.email
WHERE  u.preferred_username IS NULL
  AND  existing.id IS NULL;
