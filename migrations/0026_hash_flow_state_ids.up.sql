-- 進行状態テーブルの「Cookie 値そのものが主キー」をやめ、SHA-256 だけを保存する（SEC6）。
--
-- `auth_sessions.id` は web の host-only `auth_session_id` Cookie（およびハンドオフで web へ返す値）
-- **そのもの**で、提示できれば同意待ち・MFA 待ちの認可セッションを操作できる bearer credential である。
-- ところが他の bearer credential —— `sso_sessions.session_hash`・`authorization_codes.code_hash`・
-- `refresh_tokens.token_hash`・同じ表の `handle_hash` —— は全てハッシュ保存で、ここだけが平文だった。
-- DB の読み取りを得た者は TTL の間、進行中の認可セッションをそのまま乗っ取れる。
--
-- `saml_sso_requests.id` も同じ構造（web の `saml_request_id` Cookie がそのまま主キー）なので、
-- 片方だけ直すと非対称が残る。`passkey_challenges` / `external_login_requests` が持つ
-- auth_session_id の**写し**も同様に平文だったため、まとめてハッシュへ寄せる。
-- 1 か所でも平文の写しが残ると、主キーをハッシュ化した意味が無くなる。
--
-- 変換は MariaDB の `SHA2(..., 256)` で既存行をその場で潰す。アプリの導出（Rust の
-- `sha256_hex` = 小文字 16 進 64 文字）と同じ表現になるため、進行中のフローも Cookie を
-- 持ったまま継続できる。列は CHAR(64) へ縮める（ハッシュは固定長）。
--
-- 照合順序は他の表と揃えて `utf8mb4_unicode_ci` のまま残す。従来は「ci 照合の下で秘密値を
-- 比較している」のが弱点だったが、格納するのが小文字 16 進のハッシュになったことで
-- 大小のゆらぎで別の値に一致する余地は無くなる（アプリは常に小文字で書き込む）。
--
-- **expand/contract に分けていない理由**（CLAUDE.md「DDL 管理」・db-migration スキルの例外）:
-- 対象はいずれも TTL 数十秒〜10 分の一時状態だけを持つ表で、行の寿命がデプロイ 1 回より短い。
-- 列を並存させて両読みする期間を設けても守れるのは「ローリング中に進行していたログインが
-- やり直しになる」ことだけで、利用者は `/authorize` からやり直せば通る。一方で並存させると
-- 「平文の id がまだ書かれている列」が contract まで残り、直そうとしている当の弱点が
-- 期間限定で生き延びる。短命な表に限った判断であり、利用者データを持つ表には適用しない。

-- 1. auth_sessions: 主キーをハッシュへ。
ALTER TABLE auth_sessions
    CHANGE COLUMN id id_hash VARCHAR(64) NOT NULL
        COMMENT 'auth_session_id の SHA-256（平文は DB に置かない。SEC6）';
UPDATE auth_sessions SET id_hash = LOWER(SHA2(id_hash, 256));
ALTER TABLE auth_sessions
    MODIFY COLUMN id_hash CHAR(64) NOT NULL
        COMMENT 'auth_session_id の SHA-256（平文は DB に置かない。SEC6）';

-- 2. saml_sso_requests: 同上（web の `saml_request_id` Cookie）。
ALTER TABLE saml_sso_requests
    CHANGE COLUMN id id_hash VARCHAR(64) NOT NULL
        COMMENT 'saml_request_id の SHA-256（平文は DB に置かない。SEC6）';
UPDATE saml_sso_requests SET id_hash = LOWER(SHA2(id_hash, 256));
ALTER TABLE saml_sso_requests
    MODIFY COLUMN id_hash CHAR(64) NOT NULL
        COMMENT 'saml_request_id の SHA-256（平文は DB に置かない。SEC6）';

-- 3. passkey_challenges: auth_session_id の写し。
ALTER TABLE passkey_challenges
    CHANGE COLUMN auth_session_id auth_session_id_hash VARCHAR(64) NULL
        COMMENT '継続する OIDC auth_session の id_hash。register では NULL';
UPDATE passkey_challenges
   SET auth_session_id_hash = LOWER(SHA2(auth_session_id_hash, 256))
 WHERE auth_session_id_hash IS NOT NULL;
ALTER TABLE passkey_challenges
    MODIFY COLUMN auth_session_id_hash CHAR(64) NULL
        COMMENT '継続する OIDC auth_session の id_hash。register では NULL';

-- 4. external_login_requests: auth_session_id の写し。
ALTER TABLE external_login_requests
    CHANGE COLUMN auth_session_id auth_session_id_hash VARCHAR(128) NULL
        COMMENT '呼び出し元の OIDC auth_session の id_hash。ポータル経由なら NULL';
UPDATE external_login_requests
   SET auth_session_id_hash = LOWER(SHA2(auth_session_id_hash, 256))
 WHERE auth_session_id_hash IS NOT NULL;
ALTER TABLE external_login_requests
    MODIFY COLUMN auth_session_id_hash CHAR(64) NULL
        COMMENT '呼び出し元の OIDC auth_session の id_hash。ポータル経由なら NULL';
