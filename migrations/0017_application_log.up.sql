-- アプリケーションログ（`log` テーブル。CLAUDE.md「ログ」）。
--
-- 構造化ログ（stdout の JSON）と同時に DB へ非同期書き込みし、管理コンソールから
-- エラー・警告を参照できるようにする。監査ログ（`audit_log`）が「誰が何をしたか」の
-- 業務イベントを記録するのに対し、こちらは「システムが何を失敗したか」の運用情報を記録する。
--
-- 記録対象は WARN / ERROR のみ（INFO 以下は stdout の構造化ログに任せる。DB を肥大させない）。
-- PII は含めない（CLAUDE.md「ログ」。利用者識別が要るときはハッシュ済みの値を message に載せる）。
-- 追記専用の記録のため外部キーは張らない（テナント削除後も行を保持する）。
CREATE TABLE log (
    id             BIGINT       NOT NULL AUTO_INCREMENT,
    occurred_at    DATETIME(6)  NOT NULL
        COMMENT 'イベント発生時刻（UTC）',
    level          VARCHAR(16)  NOT NULL
        COMMENT 'ログレベル（ERROR / WARN のみ記録する）',
    service        VARCHAR(16)  NOT NULL
        COMMENT '出力元サービス（api / web）',
    target         VARCHAR(255) NOT NULL
        COMMENT 'tracing の target（出力元モジュールパス）',
    message        TEXT         NOT NULL
        COMMENT 'ログ本文（運用言語＝英語。多言語化しない）',
    correlation_id VARCHAR(64)  NULL
        COMMENT 'HTTP リクエスト単位の追跡キー（audit_log.correlation_id と同じ値。リクエスト外は NULL）',
    tenant_id      CHAR(36)     NULL
        COMMENT 'テナント文脈があれば記録する（起動時処理・バックグラウンドは NULL）',
    traceback      TEXT         NULL
        COMMENT '例外情報（tracing イベントの error フィールド等。無ければ NULL）',
    PRIMARY KEY (id),
    KEY log_occurred_idx (occurred_at),
    KEY log_level_idx (level),
    KEY log_correlation_idx (correlation_id),
    KEY log_service_idx (service),
    -- 許可値は Rust 側の enum（domain::application_log）で集中管理する。DB ネイティブ ENUM は
    -- 値追加に ALTER TABLE が要るため使わない（CLAUDE.md「DB モデリング」）。
    CONSTRAINT log_level_chk CHECK (level IN ('ERROR', 'WARN')),
    CONSTRAINT log_service_chk CHECK (service IN ('api', 'web'))
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
