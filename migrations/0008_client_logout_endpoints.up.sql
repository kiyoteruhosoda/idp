-- F4: Logout（RP-initiated / front-channel / back-channel）。
-- clients テーブルにログアウト関連 URI フィールドを追加する。
--   post_logout_redirect_uris: RP-initiated logout 後のリダイレクト先（登録済みのもののみ許可）。
--   frontchannel_logout_uri: front-channel logout 用の iframe URI。
--   backchannel_logout_uri: back-channel logout 用の HTTP POST 先 URI。

ALTER TABLE clients
    ADD COLUMN post_logout_redirect_uris JSON         NULL AFTER redirect_uris,
    ADD COLUMN frontchannel_logout_uri   VARCHAR(2048) NULL AFTER post_logout_redirect_uris,
    ADD COLUMN backchannel_logout_uri    VARCHAR(2048) NULL AFTER frontchannel_logout_uri;
