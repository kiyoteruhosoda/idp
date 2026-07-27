# Progress

進行中・未着手タスクのみを管理する（完了したら本ファイルから削除し、必要なら `CHANGELOG.md` / `history/` へ）。

タスクは改訂後 ADR-0009（テナント独立・Entra ID 型 / UUIDv7 / 完全一致 scope / 初期 DDL 刷新）の
Phase 計画、および ADR-0010（ゼロタッチ配置・設定値の出所管理）に沿う。

## 優先度の算出

| 項目 | 小 (1) | 中 (3) | 大 (5) |
|---|---:|---:|---:|
| 影響度（修正範囲） | 単一機能・単一プロンプト | 複数機能 | システム全体・広範囲 |
| 重要度（セキュリティリスク） | なし | 社内情報への影響 | 個人情報・機密情報への影響 |
| 難易度 | 簡単 | 標準 | 難しい |

| 工数 | 補正値 |
|---|---:|
| 小 | 1 |
| 中 | 2 |
| 大 | 3 |

`優先度スコア = (影響度 × 重要度 × 難易度) ÷ 工数補正値`。バックログは優先度スコアの
降順で並べる。同点はセキュリティリスク、前提タスク、障害復旧性の順で先にする。

## 推奨モデルの基準

各タスクの **難易度（工数）× リスク（影響度）** で Claude モデルを割り当てる。リスクは
「テナント分離・認可境界・トークン検証・自動生成シークレット・データ基盤の整合」を重く見る。

| モデル | 割り当て基準 |
|---|---|
| **Opus 4.8** | 高リスク（セキュリティ境界・分離防御線・保証の要）または高難度（広範囲波及・設計判断を伴う） |
| **Sonnet 5** | 仕様が明確な機能実装・中程度の面。標準的な難度で判断も限定的 |
| **Haiku 4.5** | 定型・低リスク（確立パターンの反復、限定的な UI・文言・設定） |

## バックログ

| 優先度 | ID | 課題内容 | 工数 | 影響度 | 重要度 | 難易度 |
|---:|---|---|---:|---:|---:|---:|
| 45 | T1 | api のホスト名を web の子サブドメインへ移し、Cookie スコープを環境内に閉じる（⬜未着手） | 小 | 中 | 大 | 中 |
| 25 | T2 | api↔web の状態受け渡しから Cookie を外す（`/authorize`・`/logout`。T1 の後。⬜未着手） | 大 | 中 | 大 | 大 |

## 詳細

T1・T2 とも ADR-0018（`docs/adr/0018-cookie-free-api-web-handoff.md`）の決定 1・決定 2 の実装。
**T1 だけで現行の露出は塞がる**（コード変更なし）ため先に実施し、T2 は多層防御として続ける。

### 現状（受容中のリスク）

`domain-split` では api・web の共通の親ドメインを `COOKIE_DOMAIN` に設定する必要があり、
prod（`idp.nolumia.com` / `idpapi.nolumia.com`）・stg（`idpstg.nolumia.com` /
`idpapistg.nolumia.com`）とも `nolumia.com` になる。`Domain=nolumia.com` の Cookie は
**`nolumia.com` 配下の全ホストへ送信される**ため、prod にログイン済みのブラウザが stg のどちらかの
ホストへアクセスすると、prod の `sso_session_id` / `auth_session_id` が stg サービスへ渡る。
これらは平文がそのまま bearer credential（api は受け取った値の SHA-256 で DB を引く。
`application/admin_access.rs`）であり、stg 側で観測・記録できれば prod セッションを再生できる。

**当面の運用前提**: stg を prod と同等の信頼境界で扱う（アクセス制限、リクエストログに Cookie を
残さない、同一ブラウザで両環境を跨いで使わない）。

### T1. api のホスト名を web の子サブドメインへ移す（ADR-0018 決定 1）

api を web の**子**にすると `Domain` を web のホスト名まで絞れ、prod と stg の Cookie スコープが
交わらなくなる。コード変更は不要で、`.env` の 3 キーと DNS・証明書だけで完了する。

| 環境 | web | api | `COOKIE_DOMAIN` | ポート |
|---|---|---|---|---|
| prod | `idp.nolumia.com` | `api.idp.nolumia.com` | `idp.nolumia.com` | 10000 / 10001 |
| stg | `idpstg.nolumia.com` | `api.idpstg.nolumia.com` | `idpstg.nolumia.com` | 10010 / 10011 |

手順:

1. DNS に `api.idp.nolumia.com` / `api.idpstg.nolumia.com` を追加し、証明書を用意する
   （`*.idp.nolumia.com` のワイルドカード 1 枚で web・api 両ホストを賄える）。
2. 前段プロキシの振り分け先は現行のまま（`WEB_PORT` / `API_PORT` は変えない）。
3. `.env` の `ISSUER`・`PUBLIC_WEB_BASE_URL`・`COOKIE_DOMAIN` を上表へ変更し、`.env.*.example` も更新する。
4. **`ISSUER` 変更に伴い RP 側の再設定が必要**（discovery・ID Token の `iss` が変わる）。
   メンテナンス枠で実施する。

### T2. api↔web の状態受け渡しから Cookie を外す（ADR-0018 決定 2）

api がブラウザ Cookie を読み書きしないようにする。実装対象は次の 3 経路のみ
（`/token`・`/userinfo`・`/jwks`・`/introspect` と管理 JSON API は元から Cookie 非依存）。

1. `/authorize` の `auth_session_id`: Set-Cookie をやめ、web へのリダイレクト URL に単回・短命の
   ハンドルとして載せる。web は受領後ただちに自ドメインの host-only Cookie へ移し URL から除去する
   （`handlers/authorize.rs`・`crates/web/src/handlers/{login,consent}.rs`）。
2. `/authorize` の SSO 判定: api は SSO Cookie を読まない。web が自ドメインの host-only
   `sso_session_id` を読み、`/internal/*` の新エンドポイントへ渡す。api は SSO 有効なら
   `redirect_to`（code 付き）を返す（`/internal/authenticate` と同じ応答パターン。
   DTO は `crates/contracts/src/auth.rs`）。
3. `/logout`: 起点を web にする。api は `id_token_hint` 検証・back-channel 通知・
   `post_logout_redirect_uri` 組み立てを担い、SSO Cookie の破棄は web が行う。

完了後に `COOKIE_DOMAIN` を未設定（host-only）へ戻す。既存ブラウザに残る `Domain` 付き Cookie は
削除 Cookie の併送で掃除する（ADR-0012 §3 と逆向き）。`prompt=none`（iframe 経路）の回帰テストを含める。
