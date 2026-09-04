-- 認証の強度を RP へ名乗るための記録（ADR-0043）。
--
-- `acr_values` は認証ポリシーの `requested_acr` 条件として**本当に強制している**（SSO セッションを
-- 復元するときにも評価し直す）のに、満たしたことを RP へ返す口が無かった。そのため、ポリシー行へ
-- 入力した文字列と RP が送る文字列が 1 文字ずれると条件が外れ、既定効果（allow）へ落ちて単要素の
-- ログインが黙って通る。RP には検出する手段が無い。
--
-- ID Token へ `acr` / `amr` を載せれば RP 側で確かめられるが、**トークン発行の時点では認証の文脈が
-- 残っていない**（`/token` は Cookie もセッションも読まない）。`sid` を足したとき（0021）と同じく、
-- 認証した時点の記録を発行まで持ち回す列を足す。
--
-- 保存形式は `sso_sessions.authentication_methods` と同じ**許可値の文字列 JSON 配列**にする。
-- 強度（single_factor / multi_factor）は方式から導ける派生値なので、導出前の値だけを持つ。
--
-- ⚠ **NULL は「単一要素」ではなく「記録なし」である。** 本列の導入前に発行された code / refresh
--    token がこれに当たる。読み出し側は NULL のとき `acr` / `amr` を**載せない**（分からないものを
--    single_factor と名乗ると嘘になる）。
ALTER TABLE auth_sessions
    ADD COLUMN authentication_methods JSON NULL
        COMMENT 'このフローで検証された認証方式（ADR-0043）。同意画面を経由する経路で code 発行まで持ち回す';

ALTER TABLE authorization_codes
    ADD COLUMN authentication_methods JSON NULL
        COMMENT 'ID Token の acr / amr の出所（ADR-0043）。NULL = 記録なし（本列の導入前に発行された code）';

ALTER TABLE refresh_tokens
    ADD COLUMN authentication_methods JSON NULL
        COMMENT 'ID Token の acr / amr の出所（ADR-0043）。rotation で引き継ぐ';
