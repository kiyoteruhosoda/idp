-- 拡張した効果を使っているポリシーは戻せない（CHECK に反する）ため、先に無効化して
-- `deny` へ倒す。消さずに残すのは、ロールバック後に「何が設定されていたか」を運用が
-- 追えるようにするため（無効なので評価はされない）。
UPDATE authentication_policies
   SET enabled = FALSE, effect = 'deny'
 WHERE effect = 'require_specific_method';

ALTER TABLE authentication_policies
    DROP CONSTRAINT authentication_policies_effect_chk,
    ADD CONSTRAINT authentication_policies_effect_chk
        CHECK (effect IN ('allow', 'deny', 'require_mfa')),
    DROP COLUMN effect_params;

ALTER TABLE auth_sessions
    DROP COLUMN acr_values,
    DROP COLUMN login_hint,
    DROP COLUMN ui_locales;
