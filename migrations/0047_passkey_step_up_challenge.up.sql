-- パスキーによる本人確認（step-up。AP5）用のチャレンジ種別を追加する。
--
-- 背景: 認証器の追加・削除の直前に求める本人確認は**パスワードしか受け付けなかった**ため、
-- パスキーで入った利用者は、その先でパスキーを 1 本足すことも、失くした 1 本を消すこともできない
-- （ADR-0040 は「パスキーしか持たない利用者」を前提に置いている）。
--
-- 用途を種別で分ける理由: ADR-0040 決定 4 は「チャレンジの用途は `auth_session_id_hash` の有無で
-- 分ける」とし、`challenge_type` へ値を足す案を採らなかった。**あの列が既に用途を表していた**
-- からである。本人確認のチャレンジは認可フローにも直接ログインにも結合しないため、
-- `auth_session_id_hash` は用途を表せない。ここでは種別を足すのが用途を表す唯一の場所になる。
--
-- セッションを作る（ログイン）ことと、あるセッションを引き上げる（本人確認）ことは別の操作である。
-- 種別を分けないと、本人確認のために出したチャレンジでログインが成立し、その逆も通る。
--
-- 許可値は DB ネイティブ ENUM ではなく VARCHAR + CHECK で持つ（CLAUDE.md「DB モデリング」）。
ALTER TABLE passkey_challenges DROP CONSTRAINT passkey_challenges_type_chk;

ALTER TABLE passkey_challenges
    ADD CONSTRAINT passkey_challenges_type_chk
        CHECK (challenge_type IN ('register', 'authenticate', 'step_up'));
