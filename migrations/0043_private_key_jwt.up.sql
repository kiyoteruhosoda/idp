-- 機械（人ではない呼び出し元）のクライアント認証に `private_key_jwt` を追加する（ADR-0030。RFC 7523）。
--
-- confidential クライアントの資格情報はこれまで共有秘密（`client_secret_basic` /
-- `client_secret_post`）だけだった。共有秘密は IdP 側にも保存され、クライアント側では設定ファイル・
-- CI のシークレットストアに置かれ、リクエストごとにネットワークを流れる。人が対話的に使う RP なら
-- 許容できても、無人で長期間動き続ける機械では漏洩経路が積み上がる。`private_key_jwt` は
-- クライアントが秘密鍵で署名した JWT を提示し、IdP は登録済みの公開鍵で検証するだけなので、
-- 秘密はクライアント側にしか存在しない。
--
-- expand フェーズのみ: 許可値と列・表を増やすだけで既存行は変更しない（既存の confidential
-- クライアントは `client_secret_basic` のまま動き続ける）。新しい値を書くのは管理 API・管理
-- コンソールからの明示的な選択だけなので、ローリングデプロイ中に旧バイナリが混在していても
-- 既存行の読み出しは壊れない（旧バイナリは `private_key_jwt` 行を未知値として弾くため、
-- 方式の切り替えは新バイナリの配置完了後に行うこと）。

ALTER TABLE clients
    DROP CONSTRAINT clients_token_auth_chk;

ALTER TABLE clients
    ADD CONSTRAINT clients_token_auth_chk
        CHECK (token_endpoint_auth_method IN
               ('client_secret_basic', 'client_secret_post', 'private_key_jwt', 'none'));

ALTER TABLE clients
    MODIFY COLUMN token_endpoint_auth_method VARCHAR(32) NOT NULL
        COMMENT 'client_secret_basic = Authorization: Basic / client_secret_post = body / private_key_jwt = 署名済み assertion / none = public';

-- client assertion の検証鍵（JWK Set）。公開鍵成分のみを、登録時に検証・正規化して保存する。
-- クライアントの `jwks_uri` は取りに行かない（ADR-0030 決定 3）—— 認証経路にクライアント側の
-- ホスティング障害と任意 URL への送信（SSRF）を持ち込まないため。鍵ローテーションは、この集合へ
-- 新旧を並べてからクライアントを切り替え、落ち着いてから旧鍵を消すことで無停止に行う。
-- `private_key_jwt` 以外のクライアントでは NULL。
ALTER TABLE clients
    ADD COLUMN jwks JSON NULL
        COMMENT 'private_key_jwt の検証鍵（JWK Set。公開鍵のみ）' AFTER token_endpoint_auth_method;

-- 検証を通った client assertion の `jti` を `exp` まで記録し、有効期間内の再利用を拒む
-- （ADR-0030 決定 5）。再生防止が無いと、assertion を一度傍受した相手は `exp` までの間それを
-- 使い回せる ——「共有秘密を流さない」という利点が有効期間の長さだけ目減りする。
--
-- `exp` の上限はアプリ側で 5 分に抑えるため、この表に溜まるのは直近 5 分ぶんの認証回数でしかない。
-- 期限切れの行は掃除して積み上がらないようにする。
-- クライアントは `(tenant_id, client_id)` で一意なので（`clients_tenant_client_id_uk`）、
-- 主キーもその 2 列に `jti` を足した形にする —— `jti` の一意性はクライアントの中でしか
-- 要求できない（RFC 7519 §4.1.7 も発行者ごとの一意性しか定めない）。
CREATE TABLE client_assertion_jtis (
    tenant_id  CHAR(36)     NOT NULL,
    client_id  VARCHAR(255) NOT NULL,
    jti        VARCHAR(255) NOT NULL COMMENT 'client assertion の jti クレーム',
    expires_at DATETIME(6)  NOT NULL COMMENT 'assertion の exp（この時刻を過ぎたら掃除してよい）',
    created_at DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (tenant_id, client_id, jti),
    -- 期限切れ行の一括削除で使う。
    KEY client_assertion_jtis_expiry_idx (expires_at),
    CONSTRAINT client_assertion_jtis_client_fk
        FOREIGN KEY (tenant_id, client_id) REFERENCES clients (tenant_id, client_id)
        ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
