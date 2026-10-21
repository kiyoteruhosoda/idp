-- 外部 IdP ログインの進行状態を、開始したブラウザに結び付ける（task #581。脆弱性確認 2026-10-20 の中-1）。
--
-- 戻り口（OIDC の callback・SAML の ACS）は `state` だけで進行状態を引いていた。`state` は外部 IdP を
-- 経て URL に載る値なので、攻撃者が自分のアカウントで途中まで進めた戻り URL を他人に踏ませると、
-- その人のブラウザに攻撃者のアカウントでログインした状態が入った（ログイン CSRF）。
-- 開始時にブラウザだけへ渡す値（Cookie）の SHA-256 を持ち、戻り口で照らす。
--
-- 足すだけの列（NULL 可）。既にある行（寿命 10 分）は値を持たず、戻り口で断られてやり直しになる。
ALTER TABLE external_login_requests
    ADD COLUMN browser_binding_hash CHAR(64) NULL
        COMMENT '開始したブラウザに渡した値（Cookie）の SHA-256（task #581）'
        AFTER auth_session_id_hash;
