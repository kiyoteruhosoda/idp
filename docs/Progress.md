# Progress

進行中・未着手タスクのみを管理する（完了したら本ファイルから削除し、必要なら `CHANGELOG.md` / `history/` へ）。

OIDC IdP MVP（**Rust + MariaDB**）の実装計画。設計仕様は `docs/OIDC_INPUT.md`、
スタック採用理由は `docs/adr/0005-rust-mariadb-stack.md`。フェーズは概ね順序依存。
各フェーズの「概要」末尾の括弧は設計仕様 §10「MVP完了条件」の番号。

| 優先 | # | 概要 | 状態 | 影響度 | 工数 |
|---|---|---|---|---|---|
| 1 | T4 | 認可フロー中核 `/authorize`・`/login`・SSO・code発行共通モジュール・ロック（2,3,4,5,6,7,9） | ⬜未着手 | 大 | 大 |
| 2 | T5 | トークン発行 `POST /token`（client認証・PKCE S256・code原子的one-time消費・ID/Access Token）（8,9,10） | ⬜未着手 | 大 | 大 |
| 3 | T6 | Discovery / JWKS / UserInfo エンドポイント（11,12） | ⬜未着手 | 中 | 中 |
| 4 | T7 | 監査ログ横断結線（login/code/token/client認証/sso_session の全イベント）（13） | ⬜未着手 | 中 | 小 |
| 5 | T8 | テスト & MVP完了条件 E2E 検証（unit＋integration、条件1〜13通し） | ⬜未着手 | 大 | 中 |
| — | D1 | 付随ドキュメント整備（ARCHITECTURE.md・OPERATIONS.md・各README、実装と並行） | ⬜未着手 | 小 | 小 |

> T0（基盤）・T1（データモデル）・T2（署名鍵 & JWT 基盤）・T3（ユーザー登録）は完了（`docs/CHANGELOG.md` 参照）。
> クレートは lib+bin 構成（`src/lib.rs` の `run()`）。リポジトリトレイト（`src/domain/repositories.rs`）は
> 各フェーズで実装追加時に必要に応じて拡張する。
> DB キーに使う識別子（`auth_sessions.id` 等）は ci 照合下で厳密一致となるよう**小文字 16 進**で生成する。

## 詳細

- **T0**: `config.rs` に issuer（末尾スラッシュ無し）・DSN・cookie属性・各TTL（AuthSession 600s / code 60s / SSO idle 8h・absolute 24h / access 900s / id_token 3600s）・クロックスキュー±60s・秘密鍵暗号化キーを集約（環境変数 > DB > 既定値）。起動時に sqlx マイグレーション version と `_sqlx_migrations` を突合し「DB が期待 version 以上」でなければ fail-fast（ADR-0004 の思想）。
- **T1**: 型は MariaDB 読み替え（UUID→`CHAR(36)`、enum→`VARCHAR`+`CHECK`、時刻→UTC `DATETIME(6)`、配列→`JSON`、`preferred_username` は通常 UNIQUE で複数 NULL 許容）。`domain/repositories.rs` に trait を定義（DIP 境界）。
- **T2**: ACTIVE 鍵で署名、ACTIVE+RETIRED を JWKS 公開。ID Token は `typ=JWT`、Access Token は `typ=at+jwt`。秘密鍵は aes-gcm で暗号化保存（鍵は DB 外＝環境変数）。
- **T4**: `code_issuance.rs` は `/authorize` と `/login` の共通モジュール（設計仕様 §4.2/§4.3）。SSO 復元時は `idle_expires_at` を +8h 更新、`auth_time` は SSO 初回値を維持。ロック: username 単位 連続10回失敗→15分、IP 単位レート制限、成功時リセット。CSRF トークン検証。cookie は `HttpOnly`/`Secure`/`SameSite=Lax`。
- **T5**: code の one-time 消費は `UPDATE ... WHERE code_hash=? AND used_at IS NULL AND expires_at>UTC_TIMESTAMP(6)` の affected rows で判定（0行＝`invalid_grant`＋`authorization_code.reuse_detected`）。scope は `AuthorizationCodes.scope` を継承。`Cache-Control: no-store` / `Pragma: no-cache`。
- **D1**: API 仕様は手書きせず utoipa 生成の OpenAPI にリンク（CLAUDE.md 準拠）。

> 実装の詳細計画（アーキテクチャ・クレート選定・検証手順）は本ファイルへ集約済み。着手フェーズを 🚧 に更新し、完了フェーズは行を削除して `CHANGELOG.md` に要約を残す。
