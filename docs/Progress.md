# Progress

進行中・未着手タスクのみを管理する（完了したら本ファイルから削除し、必要なら `CHANGELOG.md` / `history/` へ）。

OIDC IdP MVP（**Rust + MariaDB**）の実装計画。設計仕様は `docs/OIDC_INPUT.md`、
スタック採用理由は `docs/adr/0005-rust-mariadb-stack.md`。MVP 完了条件（§10）は充足済み（詳細は `CHANGELOG.md`）。

## バックログ

| 優先 | # | 概要 | 状態 | 影響度 | 工数 |
|---|---|---|---|---|---|
| 1 | F2 | Refresh Token（rotation・reuse detection、`offline_access` scope） | ⬜未着手 | 大 | 大 |
| 2 | F3 | Consent（同意画面・同意済み scope 記録・取り消し、`prompt`/`max_age` 正式対応） | ⬜未着手 | 中 | 中 |
| 3 | F4 | Logout（RP-initiated / front-channel / back-channel、`sso_session.terminated` 有効化） | ⬜未着手 | 中 | 中 |
| 4 | F5 | Token 管理（revocation / introspection endpoint、ユーザー単位の全セッション無効化） | ⬜未着手 | 中 | 中 |

## 詳細

### OIDC 拡張（F2〜F5、設計仕様 §9）

- **F2（§9.1）**: `RefreshTokens` テーブル（ハッシュ保存）。rotation / reuse detection は
  authorization_code の原子的 one-time 消費（`code_issuance`）を参考に実装。`offline_access` 要求時のみ発行。
  Discovery の `grant_types_supported` に `refresh_token` を追加。
- **F3（§9.2）**: client ごとの同意済み scope を永続化し、`/authorize` で未同意 scope のみ同意画面へ。
  併せて `prompt=login`（再認証）・`max_age`（auth_time 超過時の再認証）を正式対応（§4.2 MVP 無視分）。
- **F4**: `sso_session.terminated`（§7 で予約済み）を有効化。SSO セッション・関連 code の失効を実装。
  back-channel logout は client 側 logout endpoint への通知が必要。
- **F5（§9.4）**: RFC 7009 revocation・RFC 7662 introspection。introspection は confidential client 認証必須。

> 依存関係:
> - F2 は client の grant_types 管理と親和。F4・F5 はセッション/トークン失効基盤を共有。
> - 各タスクは着手時に `docs/history/` への記録要否（規模が大きく背景まで追う場合のみ）を判断する。
