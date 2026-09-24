-- 0062 の取り消し。仮登録の区別を落とす（仮登録だった利用者は ACTIVE と同じ扱いに戻る。
-- パスワードは誰も知らない値のままなので、入れるようにはならない）。
ALTER TABLE users DROP COLUMN pending_setup;
