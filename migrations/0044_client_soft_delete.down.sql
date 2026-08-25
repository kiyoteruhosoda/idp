-- 0044 の巻き戻し（ADR-0035）。
--
-- 巻き戻し時点で残っている 'DELETED' 行は旧 CHECK に違反するため、先に別の値へ倒す。倒し先は
-- 'DISABLED' とする —— 'ACTIVE' へ倒すと、**削除したはずのクライアントが再び使えるようになる**。
-- 'DISABLED' なら「使えない」という利用者から見た性質は保たれ、一覧に戻ってくるだけで済む。
--
-- 巻き戻し後に、どれが削除済みだったかは監査ログ（`client.deleted`）で洗い出せる。
UPDATE clients
   SET client_status = 'DISABLED'
 WHERE client_status = 'DELETED';

ALTER TABLE clients
    DROP CONSTRAINT clients_status_chk;

ALTER TABLE clients
    ADD CONSTRAINT clients_status_chk
        CHECK (client_status IN ('ACTIVE', 'DISABLED'));
