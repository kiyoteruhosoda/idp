-- 認証ポリシーの条件種別と効果を拡張する（AP3。仕様 §8・§12.2）。
--
-- 1. `effect` に `require_specific_method` を追加する。
--    `require_mfa` は「第二要素を 1 つ足せばよい（方式は問わない）」要求だが、仕様 §12.2 の
--    「WebAuthn 必須」「User Verification 必須」は**方式を指定する**要求で、前者に丸めると
--    「TOTP を登録済みの利用者が WebAuthn 必須をすり抜ける」穴になる。効果として分ける。
--
-- 2. 要求内容を保持する `effect_params`（JSON）を足す。
--    `{"methods": ["webauthn"], "user_verification": true}` の形。`require_specific_method`
--    以外の効果では NULL（整合はアプリ層の `validate_effect_params` が強制する）。
--
-- `conditions`（JSON）には列を足さずに条件種別を増やす（`ip_cidrs` / `time_windows` /
-- `requested_acr`）。既存行は新しいキーを持たないが、いずれも「空 = 制限しない」の既定で
-- 読めるため後方互換で、埋め戻しは要らない。
--
-- CHECK 制約は許可値を Rust 側 enum と一致させるために張り直す（MariaDB は CHECK の
-- 置き換えに DROP + ADD が要る）。
ALTER TABLE authentication_policies
    ADD COLUMN effect_params JSON NULL
        COMMENT 'require_specific_method の要求内容（methods / user_verification）。他の効果では NULL'
        AFTER effect,
    DROP CONSTRAINT authentication_policies_effect_chk,
    ADD CONSTRAINT authentication_policies_effect_chk
        CHECK (effect IN ('allow', 'deny', 'require_mfa', 'require_specific_method'));

-- 認可要求の `acr_values` を進行状態へ保存する（G12 の任意パラメータ。AP3 の
-- `requested_acr` 条件はこの値を見る）。ログイン画面のプリフィル用 `login_hint` と、
-- RP が指定する表示言語 `ui_locales` も同じ理由（評価がログイン時点まで持ち越されるため）で保存する。
ALTER TABLE auth_sessions
    ADD COLUMN acr_values VARCHAR(255) NULL
        COMMENT '認可リクエストの acr_values（空白区切りの生値。認証ポリシーの requested_acr 条件が参照）',
    ADD COLUMN login_hint VARCHAR(255) NULL
        COMMENT '認可リクエストの login_hint（ログイン画面のユーザー名プリフィル）',
    ADD COLUMN ui_locales VARCHAR(255) NULL
        COMMENT '認可リクエストの ui_locales（RP が要求する表示言語。空白区切りの BCP47 タグ）';
