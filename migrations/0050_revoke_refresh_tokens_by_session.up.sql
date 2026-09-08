-- SSO セッションが終わったら、そのセッション由来の refresh token も失効させる（ADR-0044）。
--
-- `sid` は 0021 で足したが、**書き込むだけで一度も引いていなかった**。そのため
-- 「この端末をログアウト」（`sso_sessions` の行を消すだけ）を押しても、その端末の
-- アプリが持つ refresh token は無傷のまま残り、更新が通り続けていた
-- （アクセストークンは 15 分で切れるが、リフレッシュが止まらないので意味を持たない）。
--
-- セッション単位で引くための索引を足す。`sid` は `sso_session::sid_of` が
-- session_hash から導出した 32 桁の 16 進なので、これ 1 本で十分に絞れる。
ALTER TABLE refresh_tokens
    ADD KEY refresh_tokens_sid_idx (sid);
