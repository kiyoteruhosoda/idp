-- リフレッシュで出す ID Token の `auth_time` を、元のログインの時刻のままにする（task #584。
-- 脆弱性確認 2026-10-20 の中-4）。
--
-- 以前は refresh のたびに `auth_time` を「今」にしていたので、RP が `auth_time` / `max_age` で課す
-- 「重要な操作の前は N 分以内にログインし直す」を、更新を繰り返すだけですり抜けられた。
-- `sid`・`authentication_methods` と同じく、グラントを生んだ認証の時刻を行に持ち、rotation で引き継ぐ。
--
-- 足すだけの列（NULL 可）。既にある行は値を持たず、そのトークンを出した時刻で代える。
ALTER TABLE refresh_tokens
    ADD COLUMN auth_time DATETIME(6) NULL
        COMMENT 'このグラントを生んだ認証の時刻（UTC。ID Token の auth_time。task #584）'
        AFTER authentication_methods;
