-- 再利用検知でトークンファミリを一括失効させるための鍵（SEC8）。
--
-- refresh token の rotation は `parent_hash` で 1 つ前を指すだけなので、再利用を検知しても
-- 「提示された（親）トークン」しか失効させられなかった。そこから rotation 済みの子トークンは
-- 有効なまま残り、攻撃者が先に交換して得たトークンで使い続けられる。
--
-- `grant_hash` は **その認可グラント（authorization code）の SHA-256** で、code 交換で発行される
-- 根トークンと、そこから rotation で派生したすべての子孫が同じ値を持つ。これにより
--   (a) refresh token の再利用検知 → 同じ `grant_hash` の行を 1 文で失効、
--   (b) authorization code の再利用検知 → `SHA-256(code)` でそのグラント由来のトークンを失効、
-- の両方が索引 1 本で引ける（`parent_hash` を辿るループが要らない）。
--
-- チェーンを辿らずに済ませるため、値は「祖先を辿った結果」ではなく発行時に引き継ぐ設計にした。
-- RFC 6819 §5.2.2.3 / OAuth 2.1 の「同一グラントから発行したトークンをまとめて失効させる」推奨に沿う。
ALTER TABLE refresh_tokens
    ADD COLUMN grant_hash CHAR(64) NULL
        COMMENT 'この token を生んだ認可グラント（authorization code）の SHA-256。rotation で引き継ぐ。再利用検知時のファミリ一括失効に使う',
    ADD KEY refresh_tokens_grant_idx (grant_hash);

-- 既存行の埋め戻し。
--
-- 根（`parent_hash IS NULL` = code 交換で発行された行）は自分自身の hash を家族 id とする。
-- 元の code の hash はもう手元に無い（`authorization_codes` は TTL 60 秒で消える）ので、
-- 「同一グラントから派生した集合」を一意に指せればよい家族 id としてはこれで足りる。
--
-- 既に rotation 済みの子孫は NULL のまま残す。祖先を辿るには再帰 CTE が要り、DML での可用性が
-- バージョン差の影響を受けるため、ここでは踏まない。代わりにアプリ側が rotation のたびに
-- 親の `grant_hash`（無ければ親の `token_hash`）を引き継ぐので、**移行前から生きている
-- チェーンも次の rotation でファミリを持つ**。refresh token には有効期限があるため、
-- 埋まらない行は TTL 経過で消える。
UPDATE refresh_tokens SET grant_hash = token_hash WHERE parent_hash IS NULL AND grant_hash IS NULL;
