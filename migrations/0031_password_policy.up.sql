-- パスワードポリシーの拡張（AP7。ユーザー認証・認証ポリシー仕様書 §11.2）。
--
-- これまでのパスワード要件は**最小文字数だけ**だった。ここで足りないのは次の 3 つで、
-- いずれも「その 1 本の要件を満たしていても危険なパスワード」を止められない。
--
--   * 漏えい済みパスワード — 文字数を満たしていても、既に公開された資格情報リストに
--     載っている値はクレデンシャルスタッフィングで即座に破られる。判定は外部の
--     k-匿名性 API（既定は無効）で行うため、DB 側には持ち物が無い。
--   * 過去パスワードの再利用 — 変更を強制しても直前と同じ値に戻せるなら、
--     侵害後の変更要求が意味を持たない。**過去のハッシュを保持する場所**が要る。
--   * 有効期限 — 「いつ設定されたか」を持っていないため、経過日数で変更を促せない。
--
-- 本マイグレーションは後ろ 2 つに必要な**保持先**を用意する。
--
-- # `user_password_history`: 退役したハッシュだけを持つ
--
-- 現行のパスワードは `users.password_hash` にあるため、本表には**置き換えられた（退役した）
-- ハッシュ**だけを積む。現行の写しを持たないのは、2 か所に同じ値があると更新漏れで
-- 「履歴上は現行だが実際は違う」状態が生まれるためである。再利用の判定は
-- 「`users.password_hash` + 本表の新しい順 N-1 件」を見る（アプリ層）。
--
-- 平文も可逆な値も持たない。積むのは argon2 の PHC 文字列そのままで、照合は
-- 候補パスワードを各行のハッシュへ verify する（保存形式は現行パスワードと同一のため、
-- 履歴が新しい攻撃面を作らない）。件数はポリシー値で剪定するので単調増加はしない。
--
-- # `users.password_changed_at`: NULL 許容にする理由
--
-- ローリングデプロイ中は旧プロセスが列を知らないまま `users` に INSERT する。NOT NULL に
-- すると、その INSERT が既定値を持たずに失敗して**利用者を作れなくなる**。NULL は
-- 「未記録」を意味し、アプリ層は `created_at` にフォールバックして経過日数を測る。
--
-- 既存行の埋め戻しにも `created_at` を使う（`updated_at` は表示名変更等でも動くため、
-- 「最後にパスワードを変えた時刻」としては新しすぎる方向へ誤る）。有効期限の既定は
-- 「無期限」なので、この埋め戻しだけで誰かのログインが即座に止まることはない。
CREATE TABLE user_password_history (
    -- 追記のみ・外から参照されない内部表のため、`audit_log` と同じ AUTO_INCREMENT を使う
    -- （識別子を外部へ出さないので UUID にする理由が無い）。
    id           BIGINT       NOT NULL AUTO_INCREMENT,
    user_id      CHAR(36)     NOT NULL,
    -- 現行パスワードと同じ形式（argon2 の PHC 文字列）。平文・可逆な値は持たない。
    password_hash VARCHAR(255) NOT NULL
        COMMENT '退役した argon2 ハッシュ（PHC 文字列）',
    retired_at   DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        COMMENT 'このハッシュが現行でなくなった時刻（= 新しいパスワードが設定された時刻）',
    PRIMARY KEY (id),
    -- 再利用判定は「利用者の新しい順に N 件」を引くため、この並びで索引を張る。
    -- 剪定（古い行の削除）も同じ索引で効く。
    KEY user_password_history_user_idx (user_id, retired_at),
    CONSTRAINT user_password_history_user_fk FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

ALTER TABLE users
    ADD COLUMN password_changed_at DATETIME(6) NULL
        COMMENT '現行パスワードを設定した時刻。NULL は未記録（アプリ層は created_at を使う）'
        AFTER must_change_password;

UPDATE users SET password_changed_at = created_at WHERE password_changed_at IS NULL;
