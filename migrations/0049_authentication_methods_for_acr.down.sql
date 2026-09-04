-- 記録列を取り除く。既に発行済みの code / refresh token は、戻した後の ID Token で
-- `acr` / `amr` を名乗らなくなる（列が無い＝記録なしと同じ扱い）。
ALTER TABLE refresh_tokens DROP COLUMN authentication_methods;
ALTER TABLE authorization_codes DROP COLUMN authentication_methods;
ALTER TABLE auth_sessions DROP COLUMN authentication_methods;
