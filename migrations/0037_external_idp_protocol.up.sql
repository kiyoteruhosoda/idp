-- 外部 IdP に SAML を足す（AP12。ADR-0027）。
--
-- AP10（0024）で入れた `external_identity_providers` は OIDC 前提の列構成
-- （`authorization_endpoint` / `token_endpoint` / `jwks_uri` / `client_id`）で、SAML の
-- IdP メタデータ（SSO URL・署名証明書・NameID 形式）を表現できなかった。
--
-- # 同じ表の列に置く（JSON 列にも別表にもしない）
--
-- JSON 列に寄せると、列ごとの NOT NULL・CHECK・長さ制限が掛けられない。「SSO URL が空のまま
-- 登録された SAML プロバイダ」が登録時ではなく**ログイン時**に落ちることになる。設定の誤りは
-- 管理者が直せる時点で弾きたい。
--
-- 別表にも分けない。プロバイダは認証のたびに読むもので、1 プロトコルにつき 1 行しか無い付随表を
-- join するか 2 回引くかの選択が、共通項だけを読みたい一覧（ログイン画面のボタン）にも掛かる。
-- どの組み合わせが妥当かは Rust の enum（`ExternalIdpConfig`）が単一の出所として持ち、
-- リポジトリは行 → enum の変換でしか値を作らないので、`protocol = 'saml'` なのに SSO URL が
-- NULL という行は**読み出しで失敗する**（黙って既定に落ちない）。
--
-- # OIDC の列を NULL 可へ緩める
--
-- SAML の行では OIDC の列を使わない。DB ネイティブ ENUM を使わない方針（`CLAUDE.md`）どおり、
-- `protocol` は VARCHAR + CHECK にする。

ALTER TABLE external_identity_providers
    ADD COLUMN protocol VARCHAR(16) NOT NULL DEFAULT 'oidc'
        COMMENT '外部 IdP のプロトコル。許可値は Rust の ExternalIdpProtocol が単一の出所'
        AFTER display_name,
    ADD CONSTRAINT external_idps_protocol_ck
        CHECK (protocol IN ('oidc', 'saml')),
    -- SAML の SSO エンドポイント（HTTP-Redirect binding で AuthnRequest を送る先）。
    ADD COLUMN saml_sso_url VARCHAR(2048) NULL
        COMMENT 'SAML: IdP の SingleSignOnService URL（HTTP-Redirect binding）',
    -- 署名証明書は**配列**で持つ。IdP の証明書更新期間は新旧 2 枚が同時に有効なので、
    -- 1 枚しか持てないと更新のたびにログインが止まる。
    ADD COLUMN saml_certificates JSON NULL
        COMMENT 'SAML: 署名検証に使う X.509 証明書（base64 DER）の配列。更新期間に新旧 2 枚を並べる',
    ADD COLUMN saml_name_id_format VARCHAR(255) NULL
        COMMENT 'SAML: AuthnRequest で要求する NameIDFormat';

-- OIDC 専用の列を NULL 可にする（SAML の行では使わない）。既存行はすべて `protocol = 'oidc'`
-- なので値はそのまま残る。
ALTER TABLE external_identity_providers
    MODIFY COLUMN authorization_endpoint VARCHAR(2048) NULL
        COMMENT 'OIDC: 認可エンドポイント',
    MODIFY COLUMN token_endpoint VARCHAR(2048) NULL
        COMMENT 'OIDC: トークンエンドポイント',
    MODIFY COLUMN jwks_uri VARCHAR(2048) NULL
        COMMENT 'OIDC: ID Token の署名検証に使う JWKS の URL',
    MODIFY COLUMN client_id VARCHAR(255) NULL
        COMMENT 'OIDC: 外部 IdP に登録した本 IdP のクライアント ID';

-- 進行状態（`external_login_requests`）は両プロトコルで共用する。SAML には PKCE に当たるものが
-- 無いので `code_verifier_encrypted` を NULL 可へ緩める。`nonce` 列は「こちらが作り相手が返す値」
-- として役割が同じなので共用する（OIDC: ID Token の nonce / SAML: AuthnRequest の ID）。
ALTER TABLE external_login_requests
    MODIFY COLUMN code_verifier_encrypted TEXT NULL
        COMMENT 'OIDC: PKCE の code_verifier（AES-256-GCM）。SAML では NULL',
    MODIFY COLUMN nonce VARCHAR(128) NOT NULL
        COMMENT 'こちらが作り相手が返す値。OIDC: ID Token の nonce / SAML: AuthnRequest の ID';
