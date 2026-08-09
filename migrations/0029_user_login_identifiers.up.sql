-- ログイン識別子の複数化（AP8。ユーザー認証・認証ポリシー仕様書 §4）。
--
-- これまでログイン欄に入力できる値は `users.preferred_username` の 1 本だけだった
-- （ADR-0009 §8）。そのため次ができない:
--
--   * 電話番号・社員番号のように、組織がすでに配っている識別子でログインさせる。
--   * 同じ人に複数の入り口を用意する（旧姓のユーザー名を残したまま新しい名前を配る）。
--   * 識別子を**1 本だけ**止める。`users.preferred_username` は 1 本しか無いので、
--     止めるにはアカウントごと無効化するしかない。
--
-- 本テーブルは種別によらない**識別子の登録簿**として、種別・表示値・正規化値・有効/無効を持つ。
--
-- # 表示値と正規化値を分ける理由
--
-- 照合は正規化値（`normalized_value`）だけで行い、画面に出すのは利用者が登録したままの
-- `display_value` にする。電話番号は `090-1234-5678` と `+819012345678` が同じものを指すが、
-- 利用者に見せたいのは登録したときの書き方である。正規化を表示にも使うと「登録した覚えのない
-- 値が管理画面に並ぶ」ことになり、同一性の確認ができなくなる。
--
-- # `users` との関係（expand フェーズ）: 既存の値は**写さない**
--
-- 主たるログイン識別子は `users.preferred_username` のままで、本テーブルには
-- **追加の識別子だけ**を置く。ログイン時の解決は「本テーブルの有効な行 → 無ければ
-- `users.preferred_username`」の順。
--
-- 写しを取らないのは、同じ値が 2 か所にあると**二重書きの同期**が必要になるためである。
-- 同期が漏れた瞬間に「変更前のユーザー名でログインできる」「無効化したのに認証が通る」
-- という状態が生まれ、しかもそれはプロフィール編集・利用者作成・登録簿の更新という
-- 別々の経路をまたぐので、1 か所直せば済む問題にならない。主識別子を本テーブルへ移すのは
-- contract フェーズ（`docs/Progress.md` AP15）でまとめて行う。途中で失敗すると**誰も
-- ログインできなくなる**変更であり、登録簿の導入と同じ回に載せない（ADR-0004 の
-- expand/contract。AP9 / migration 0023 と同じ分け方）。
--
-- `users.email` も同様に取り込まない。取り込むと「今日までメールでログインできなかった
-- 環境で、マイグレーションを当てた瞬間からメールでログインできる」ことになり、認証の
-- 入り口が黙って広がる。メールでのログインを許すかはテナントの判断なので、管理 API から
-- `email` 種別の識別子を明示的に足したときだけ有効になる。
CREATE TABLE user_login_identifiers (
    id               CHAR(36)     NOT NULL
        COMMENT '内部識別子（UUIDv7）',
    tenant_id        CHAR(36)     NOT NULL
        COMMENT '所属元テナント。認証は所属元テナント限定のため一意性もテナント内で見る（ADR-0009 §8）',
    user_id          CHAR(36)     NOT NULL,
    identifier_type  VARCHAR(32)  NOT NULL
        COMMENT '識別子の種別（username / email / phone_number / employee_number）',
    display_value    VARCHAR(320) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL
        COMMENT '利用者が登録したままの値。画面表示に使い、照合には使わない',
    normalized_value VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL
        COMMENT '照合キー。種別ごとの正規化（小文字化・記号除去等）を適用した値',
    is_active        TINYINT(1)   NOT NULL DEFAULT 1
        COMMENT '識別子単位の有効/無効。0 の行はログイン欄で一致しない（行は残る）',
    created_at       DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at       DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    -- ログイン時の解決（テナント × 種別 × 正規化値）が使う索引であり、同時に
    -- 「同じ値で 2 人が解決される」ことを DB で禁じる制約でもある。無効な行も含めて一意にする
    -- （無効化した識別子を別人が横取りできると、戻したときに解決先が変わってしまう）。
    UNIQUE KEY user_login_identifiers_value_uk (tenant_id, identifier_type, normalized_value),
    -- 利用者の識別子一覧（管理画面・プロフィール編集時の同期）が使う索引。
    KEY user_login_identifiers_user_idx (user_id, identifier_type),
    CONSTRAINT user_login_identifiers_type_chk
        CHECK (identifier_type IN ('username', 'email', 'phone_number', 'employee_number')),
    CONSTRAINT user_login_identifiers_user_fk FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT user_login_identifiers_tenant_fk FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE RESTRICT
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
