# Progress

進行中・未着手タスクのみを管理する（完了したら本ファイルから削除し、必要なら `CHANGELOG.md` / `history/` へ）。

OIDC IdP MVP（**Rust + MariaDB**）の実装計画。設計仕様は `docs/OIDC_INPUT.md`、
スタック採用理由は `docs/adr/0005-rust-mariadb-stack.md`。

## MVP 充足状況

設計仕様 `docs/OIDC_INPUT.md` の **MVP 完了条件 §10（1〜13）はすべて充足**し、`tests/oidc_flow.rs`
の E2E テストで検証済み（ロックアウト §4.3・IP レート制限・scope 部分集合検証・redirect_uri 完全一致・
code 再利用検知・SSO 復元時の auth_time 継承・監査ログ二重出力を含む）。API §4・トークン仕様 §5・
監査ログ §7 も実装済み。§8 の MVP 対象外項目は意図どおり未実装。

> 既知の軽微な差分（本番運用向け・下表 H1 で対応予定）: HSTS / HTTPS 強制はアプリ層では未実装
> （リバースプロキシ層前提。Cookie の `Secure` は `COOKIE_SECURE` で対応済み）。`prompt` / `max_age` は
> §4.2 のとおり MVP では無視。

## MVP 以降のバックログ（未着手）

設計仕様 §9「今後拡張」に沿った計画。着手時に本表の状態を更新し、完了したら削除して `CHANGELOG.md` へ移す。

| 優先 | # | 概要 | 状態 | 影響度 | 工数 |
|---|---|---|---|---|---|
| 1 | F1 | Client 管理 API（登録 / secret 再発行 / 無効化 / redirect・scope 変更、`private_key_jwt`） | ⬜未着手 | 大 | 大 |
| 2 | F2 | Refresh Token（rotation・reuse detection、`offline_access` scope） | ⬜未着手 | 大 | 大 |
| 3 | F3 | Consent（同意画面・client ごとの同意済み scope 記録・取り消し） | ⬜未着手 | 中 | 中 |
| 4 | F4 | Logout（RP-initiated / front-channel / back-channel、`sso_session.terminated` 有効化） | ⬜未着手 | 中 | 中 |
| 5 | F5 | Token 管理（revocation / introspection endpoint、ユーザー単位の全セッション無効化） | ⬜未着手 | 中 | 中 |
| 6 | H1 | 本番セキュリティ強化（HSTS・HTTPS 強制・セキュリティヘッダ、`prompt` / `max_age` 正式対応） | ⬜未着手 | 中 | 小〜中 |
| 7 | H2 | 署名鍵ローテーションの自動化（スケジュール実行・ACTIVE/RETIRED 重複期間の自動管理） | ⬜未着手 | 中 | 中 |

## 詳細

- **F1（§9.3）**: 現状 client 登録は SQL 手動（`docs/OPERATIONS.md`）。運用性向上のため管理 API を最優先とする。
  scope 検証・監査は既存の Application 層パターンを踏襲。`private_key_jwt` 対応で
  `token_endpoint_auth_method` の許可値・CHECK 制約を拡張（マイグレーション）。
- **F2（§9.1）**: `RefreshTokens` テーブル（ハッシュ保存）を追加。rotation と reuse detection は
  authorization_code の one-time 消費ロジック（`code_issuance`）を参考に原子的更新で実装。
  `offline_access` 要求時のみ発行。Discovery の `grant_types_supported` に `refresh_token` を追加。
- **F3（§9.2）**: 同意済み scope を永続化し、`/authorize` で未同意 scope のみ同意画面へ。
  i18n はログイン画面と同じ `fluent` を流用。
- **F4**: `sso_session.terminated`（§7 で予約済み）を有効化。SSO セッション・関連 code の失効を実装。
  back-channel logout は client 側 logout endpoint への通知が必要。
- **F5（§9.4）**: RFC 7009 revocation・RFC 7662 introspection。introspection は confidential client 認証必須。
- **H1**: `tower-http` の `SetResponseHeader` 等で HSTS・`X-Content-Type-Options` 等を付与。
  HTTPS 前提の運用注記を `docs/OPERATIONS.md` に統合。`prompt=login` / `max_age` による再認証を実装。
- **H2**: `signing_keys` の `not_after` に基づく自動生成・RETIRED 化。MVP は起動時ブートストラップのみ。

> 依存関係: F2 は F1（client の grant_types 管理）と親和。F4・F5 はセッション/トークン失効基盤を共有。
> 各タスクは着手時に `docs/history/` への記録要否（規模が大きく背景まで追う場合のみ）を判断する。
