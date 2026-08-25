-- クライアントの論理削除（ADR-0035）。`client_status` に 'DELETED' を追加する。
--
-- 物理削除にしないのは、発行済みの認可コード・トークン・同意・監査ログが `client_id` で
-- 紐づいているためである。実体を消すと、監査で `client_id` を引いたときに「どのアプリだったか」を
-- 追えなくなる。**削除の目的は「使えなくすること」であって「記録を消すこと」ではない。**
--
-- 別カラム（`deleted_at`）ではなく `client_status` の値を増やすのは、認可・トークン・
-- introspection の各経路が既に `is_active()`（= status が ACTIVE か）で門番をしているためである。
-- 値を増やすだけで、**新しい絞り込みを 1 か所も足さずに**全経路が削除済みを拒む。別カラムにすると
-- 「`deleted_at IS NULL` を足し忘れた経路だけ削除済みが通る」という落とし方ができてしまう。
-- 「いつ消したか」は監査ログ（`ClientDeleted`）と `updated_at` が持つ。
--
-- expand フェーズのみ: 許可値を増やすだけで既存行は変更しない。ローリングデプロイ中に旧バイナリが
-- 混在していても、旧バイナリは 'DELETED' を未知値として弾く（＝削除済みを有効扱いしない）ため、
-- 安全側に倒れる。

ALTER TABLE clients
    DROP CONSTRAINT clients_status_chk;

ALTER TABLE clients
    ADD CONSTRAINT clients_status_chk
        CHECK (client_status IN ('ACTIVE', 'DISABLED', 'DELETED'));
