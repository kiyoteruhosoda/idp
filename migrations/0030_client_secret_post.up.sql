-- トークンエンドポイントのクライアント認証方式に `client_secret_post` を追加する（G3。RFC 6749 §2.3.1）。
--
-- これまで confidential クライアントは `client_secret_basic`（`Authorization: Basic`）だけを
-- 使えた。RFC 6749 §2.3.1 は Basic を推奨しつつ、body に `client_id` / `client_secret` を載せる
-- `client_secret_post` の受け入れも認めており、実際の RP ライブラリ・SaaS 連携にはこちらを既定に
-- するものが多い。方式が合わないだけで連携できないのは相互運用上の実害があるため、登録時に
-- 選べるようにする。
--
-- expand フェーズのみ: 許可値を増やすだけで既存行の `token_endpoint_auth_method` は変更しない
-- （既存の confidential クライアントは `client_secret_basic` のまま動き続ける）。新しい値を書くのは
-- 管理 API・管理コンソールからの明示的な選択だけなので、ローリングデプロイ中に旧バイナリが
-- 混在していても既存行の読み出しは壊れない（旧バイナリは `client_secret_post` 行を未知値として
-- 弾くため、方式の切り替えは新バイナリの配置完了後に行うこと）。
ALTER TABLE clients
    DROP CONSTRAINT clients_token_auth_chk;

ALTER TABLE clients
    ADD CONSTRAINT clients_token_auth_chk
        CHECK (token_endpoint_auth_method IN ('client_secret_basic', 'client_secret_post', 'none'));

ALTER TABLE clients
    MODIFY COLUMN token_endpoint_auth_method VARCHAR(32) NOT NULL
        COMMENT 'client_secret_basic = Authorization: Basic / client_secret_post = body / none = public';
