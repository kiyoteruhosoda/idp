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
-- **チェーン全体**を根から辿って同じ家族 id にする。根だけを埋めて子孫を NULL のままにすると、
-- 移行前に 1 度でも rotation 済みのチェーン（R → C）が `R` と `C` に分裂し、古い `R` を再生された
-- ときに `C` 以降の生きているトークンが失効しない ＝ 保護が TTL 満了まで穴のままになる。
--
-- 根（`parent_hash IS NULL` = code 交換で発行された行）の家族 id は自分自身の hash とする。
-- 元の code の hash はもう手元に無い（`authorization_codes` は TTL 60 秒で消える）が、
-- 「同一グラントから派生した集合」を一意に指せればよい家族 id としてはこれで足りる。
--
-- 再帰結果を一時表へ落としてから UPDATE するのは、更新対象と同じ表を再帰の起点にしているため
-- （同一文で読み書きすると実装依存の制限に触れる）。`depth` は破損データによる無限再帰の歯止めで、
-- 実運用の rotation 回数を大きく超える値を上限にしてある。
CREATE TEMPORARY TABLE refresh_token_family_backfill (
    token_hash CHAR(64)  NOT NULL,
    grant_hash CHAR(64)  NOT NULL,
    PRIMARY KEY (token_hash)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

INSERT INTO refresh_token_family_backfill (token_hash, grant_hash)
WITH RECURSIVE chain (token_hash, grant_hash, depth) AS (
    SELECT token_hash, token_hash, 0
      FROM refresh_tokens
     WHERE parent_hash IS NULL
    UNION ALL
    SELECT rt.token_hash, c.grant_hash, c.depth + 1
      FROM refresh_tokens rt
      JOIN chain c ON rt.parent_hash = c.token_hash
     WHERE c.depth < 100000
)
SELECT token_hash, grant_hash FROM chain;

UPDATE refresh_tokens t
  JOIN refresh_token_family_backfill b ON b.token_hash = t.token_hash
   SET t.grant_hash = b.grant_hash
 WHERE t.grant_hash IS NULL;

DROP TEMPORARY TABLE refresh_token_family_backfill;

-- 根が既に消えているチェーン（現状 refresh_tokens の GC は無いので発生しない）だけが NULL のまま
-- 残る。その行はアプリが次の rotation で自分の hash を起点に新しい家族を作る（`family_hash()`）。
