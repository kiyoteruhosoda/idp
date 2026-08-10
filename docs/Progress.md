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
| 8 | AP14 | AP3 の残り: 国・端末信頼の条件（判定材料が無いため未実装。GeoIP かプロキシ供給ヘッダの取り決めと、デバイス登録簿が前提）（⬜未着手） | 大 | 中 | 中 | 大 |
| 5 | AP1 | 認証ポリシーの管理画面（web コンソール UI。現状は API のみ。AP3 で増えた条件・効果も対象）（⬜未着手） | 中 | 中 | 小 | 中 |
| 5 | AP15 | AP8 の contract フェーズ（`users.preferred_username` を登録簿へ移し、列を撤去する。解決経路の切替 → 移送 → 撤去を独立したマイグレーションに分ける）（⬜未着手） | 中 | 中 | 小 | 中 |
| 5 | AP11 | AP9 の contract フェーズ（TOTP/WebAuthn の秘密を `user_authenticators` へ集約し、`user_totp_secrets` / `user_webauthn_credentials` を撤去）（⬜未着手） | 中 | 中 | 小 | 中 |
| 5 | AP12 | SAML 外部 IdP（AP10 は OIDC のみ実装。`external_identity_providers` の protocol 拡張が要る）（⬜未着手） | 大 | 中 | 小 | 大 |
| 5 | G12 | `/authorize` の任意パラメータの残り（`response_mode=form_post`・`prompt=select_account` 未対応。`login_hint`・`ui_locales`・`id_token_hint` は対応済み）（🚧進行中） | 中 | 中 | 小 | 中 |
| 3 | SEC10 | `/token`・`/introspect`・`/revoke` にレート制限が無い（Argon2 増幅型 DoS）（⬜未着手） | 小 | 小 | 中 | 小 |
| 3 | AP6 | アカウントロックの管理者解除（仕様 §17.1・§24.6。`locked_until` を即時クリアする管理操作。現状は期限経過待ちのみ）と段階的ロック（⬜未着手） | 小 | 小 | 中 | 小 |
| 3 | G8 | `audit_log` に絞り込み用の索引（`client_id`・`user_id`・`result`・複合 `(tenant_id, occurred_at)`）と保持期間の仕組みが無い（`log` にはある）（⬜未着手） | 小 | 中 | 小 | 小 |
| 2 | AP13 | SMS OTP の送信経路が無い（認証方式・認証器種別としては定義済みだが、送信アダプタと登録画面が未実装）（⬜未着手） | 中 | 小 | 小 | 中 |
| 2 | G6 | メトリクスが無い（`/metrics` 非公開。ログイン成功率・トークン発行レート・レイテンシ・DB プール枯渇を監視できない）（⬜未着手） | 中 | 中 | 小 | 小 |
| 1 | G7 | 一覧 API のページング欠落（`list_clients`・`list_tenants`・権限一覧は全件返す。members・audit にはある）（⬜未着手） | 小 | 小 | 小 | 小 |

## 詳細

### ユーザー認証・認証ポリシー仕様書の残実装（AP1・AP14）

ADR-0020 で認証ポリシー（deny / require_mfa / allow）・管理 API・OIDC ログインフローへの適用・
アカウントロックの設定化を導入し、AP3 で条件種別（ネットワークゾーン・時間帯・requested_acr）と
`require_specific_method` 効果を追加した（ADR-0020 の追補）。残りは以下。

- **AP1** 管理画面（web コンソール UI）。現状は API のみ（手順は `docs/OPERATIONS.md`）。
  AP10 の外部 IdP 設定（`/admin/external-idps`）・AP8 のログイン識別子
  （`/admin/users/{user_id}/login-identifiers`）と、AP3 で増えた条件・効果の編集 UI も対象。
- **AP14** AP3 の残り: 国・端末信頼の条件。**条件式ではなく判定材料が無い**のが本体で、
  国は GeoIP データベースの同梱かフロントプロキシが供給するヘッダの取り決め、端末信頼は
  デバイス登録簿（登録・識別・信頼状態）がそれぞれ前提になる。材料の無い条件を先に置くと
  「設定できるが決して一致しない条件」が管理画面に並ぶため、別タスクへ切り出した。

AP2・AP3・AP4・AP5・AP7・AP8・AP9・AP10 は実装済み（`CHANGELOG.md` 参照）。AP8 の残り
（contract フェーズ）・AP9 の残り（contract フェーズ）・AP10 の残り（SAML 外部 IdP）は
下記「積み残し」にある。

### 積み残し（AP8・AP9・AP10 実装からの繰り越し。AP11〜AP13・AP15）

#### AP15. AP8 の contract フェーズ（主たる識別子の移送）

AP8 は expand フェーズだけを入れた（ADR-0025）。`user_login_identifiers` は種別・表示値・
正規化値・有効/無効を一元管理するが、**主たるログイン識別子は `users.preferred_username` に
残したまま**で、登録簿には**追加の識別子だけ**が入る（写しは取らない）。解決は
「登録簿の有効な行 → `users.preferred_username`」の順。一覧 API は主識別子を読み出し時に
合成して返している（`id` が `null` の行）。

分けた理由は移行リスク。主識別子の移送は失敗すると**誰もログインできなくなる**操作で、
登録簿の導入と同じ回に載せない（AP9 / AP11 と同じ分け方）。

contract フェーズでやること:

1. `users.preferred_username` を登録簿の `username` 種別（`is_primary` 相当）へ移すマイグレーション。
2. 解決から `users.preferred_username` へのフォールバックを外す（登録簿だけを見る）。
   一覧 API の合成行も不要になる。
3. `users.preferred_username` 列の撤去。ID Token の `preferred_username` クレーム・
   利用者一覧の表示・プロフィール編集を登録簿側へ寄せる。

1 と 3 の間に**両方を読める期間**を挟む（ローリングデプロイ中に古いプロセスが残るため）。
`users.preferred_username` を読んでいる箇所（プロフィール編集・利用者検索・`/userinfo` の
クレーム組み立て）を洗い出すのが実質の作業量になる。

移送が済めば、追加識別子と主識別子の衝突を**DB の一意制約**で防げるようになる（expand の間は
アプリ層の事前チェックしか張れず、同時実行の窓が残る。ADR-0025「残る限界」）。

#### AP11. AP9 の contract フェーズ（秘密の集約）

AP9 は expand フェーズだけを入れた。`user_authenticators` は**認証器の種別・状態・ラベル・
最終使用時刻**を一元管理するが、**秘密そのものは既存表に残したまま**である（TOTP の共有鍵は
`user_totp_secrets`、パスキーの公開鍵・署名カウンタは `user_webauthn_credentials`）。
`user_authenticators.credential_ref` が元の行を指し、検証経路は従来どおり元の表を読む。

分けた理由は移行リスク。秘密の移送は暗号化のまま運び直す（あるいは復号→再暗号化する）操作で、
途中で失敗すると**利用者が MFA を通れなくなり自力で復旧できない**。状態管理だけを先に移して
運用で慣らし、参照経路を切り替えてから秘密を動かす。

contract フェーズでやること:

1. 検証経路（TOTP 照合・WebAuthn assertion）の読み出しを `user_authenticators` 側へ切り替える。
2. 秘密を `user_authenticators.secret_encrypted` へ移すマイグレーション（`credential_ref` で対応付け）。
3. `user_totp_secrets` / `user_webauthn_credentials` の削除と、`credential_ref` 列の撤去。

各段は独立したマイグレーションにし、1 と 2 の間に**両方を読める期間**を挟む（ローリングデプロイ中に
古いプロセスが残るため）。

#### AP12. SAML 外部 IdP

AP10 で入れたのは **OIDC の外部 IdP のみ**。`external_identity_providers` は
`issuer` / `authorization_endpoint` / `token_endpoint` / `jwks_uri` / `client_id` という
OIDC 前提の列構成で、SAML の IdP メタデータ（`SingleSignOnService` URL・署名証明書・
`NameID` 形式）を表現できない。対応するなら `protocol` 列（`oidc` / `saml`）を足し、
プロトコル固有の設定は JSON 列へ寄せるか別表に分ける設計判断が要る（ADR 対象）。

なお本 IdP を **SAML の IdP として**振る舞わせる側（`/{tenant}/saml/metadata`・`saml_sso_requests`）は
既に別途存在する。ここで言う SAML は**外部 IdP を利用者の認証元として使う（SP 側）**方向の話で、
向きが逆である。

#### AP13. SMS OTP の送信経路

`AuthenticationMethod::SmsOtp` と `AuthenticatorType::SmsOtp` は AP4 / AP9 で語彙としては定義済み
（認証強度の判定・認証器一覧の表示は SMS を受け入れる）だが、**送信アダプタ（SMS ゲートウェイの
ポートと実装）と電話番号の登録・確認画面が無い**ため、実際には登録も認証もできない。
メール OTP（`lettre`）と同じ形のポート＋インフラ実装を足すのが最小の作業。

送信事業者の選定と、電話番号を PII としてどう保持するか（ログ非出力は既定として、DB では
暗号化するか正規化値のみ持つか）は未決。

### セキュリティレビュー（SEC10）

api / web の別サブドメイン構成を対象にした調査で検出した課題のうち、SEC1・SEC5〜SEC9・SEC12・SEC13 は
対応済み（`CHANGELOG.md` 参照）。良好な点（回帰させない）: redirect_uri/post_logout の完全一致、
code の 256bit・SHA-256・60 秒・原子的ワンタイム、PKCE S256 の無条件強制、client_secret の Argon2 保存、
sso_session_id の 256bit・ハッシュ保存・ログイン毎の再生成、ADR-0018 の Cookie 非依存ハンドオフ、
web の `X-Forwarded-For` ゲート（SEC1）・CSRF 種の `__Host-` 束縛（SEC5）・`auth_session_id` の
認証時再生成（SEC7）・再利用検知でのトークンファミリ失効（SEC8）・アクセスログのクエリ非記録（SEC9）・
進行状態 id のハッシュ保存（SEC6）・失敗カウンタの原子的加算（SEC13）。

#### SEC10. `/token`・`/introspect`・`/revoke` にレート制限が無い

client_secret は Argon2 照合（`crates/core/src/application/token.rs`）で総当たりは非現実的だが、
メモリハード関数の CPU/メモリ増幅型 DoS が成立する。

### 機能・運用のギャップ（G6〜G8・G12）

セキュリティ（SEC）・認証仕様（AP）とは別軸で、**IdP としての機能欠落・運用性**を対象にした
レビューで検出した課題。G1（CORS）・G2（期限切れ GC）・G3（`client_secret_post`）・
G9（シングルインスタンス前提の明文化）・G11（web の統合テスト）は対応済み（`CHANGELOG.md` 参照）。良好な点（回帰させない）:
DDD 4層と crate 境界の一致（web は sqlx に依存できない）、i18n の en/ja キー完全一致、
設定の出所区分（`Builtin`/`EnvLocked`/`DbManaged`）の単一定義、テナント分離の統合テスト、
ADR による設計判断の追跡可能性。

#### G6. メトリクスが無い

`/metrics`（Prometheus）に相当する出口が無く、可観測性は JSON ログと `log`・`audit_log` テーブルだけ。
ログイン成功率・トークン発行レート・エンドポイント別レイテンシ・sqlx コネクションプールの枯渇・
鍵ローテーションの成否といった、IdP の SLO を見るのに要る値が取れない。対策: `metrics` +
`metrics-exporter-prometheus` を入れ、`/metrics` を内部面（`/internal/` と同じくプロキシで公開遮断）に置く。

#### G7. 一覧 API のページング欠落

`list_clients`（`crates/api/src/presentation/handlers/admin_clients.rs`）・`list_tenants`
（`admin_tenants.rs`）・権限一覧が `Vec` を全件返す。`admin_members`・`admin_audit` には
`limit`/`offset` があるので非対称。テナント内クライアントが数百になると管理コンソールが重くなる。

#### G8. `audit_log` の索引不足と保持期間の欠如

索引は `event_type`・`correlation_id`・`occurred_at`・`tenant_id` の**単一列 4 本**のみ
（`migrations/0001_baseline.up.sql`）。管理コンソールの絞り込みは
「テナント × 期間 × event_type × result × client_id」の組み合わせなので、複合索引
`(tenant_id, occurred_at)` が無いと期間検索が事実上の全表走査になり、`client_id`・`result`・
`user_id` には索引すら無い。また `log` には `APP_LOG_RETENTION_DAYS` があるのに `audit_log` には
保持期間の仕組みが無く、法定保存期間の設計も未定。対策: 複合索引の追加と
`AUDIT_LOG_RETENTION_DAYS`（既定は「削除しない」）の導入。

#### G12. `/authorize` の任意パラメータの残り

`acr_values`・`login_hint`・`ui_locales` は `/authorize` が受け付けて `auth_sessions` へ保存する
ところまで実装済み（AP3 と同じ 0028）。Discovery の広告（`response_modes_supported`・
`prompt_values_supported`・`request_parameter_supported`・`claims_parameter_supported`・
`acr_values_supported`・`ui_locales_supported`）も出している。`login_hint` / `ui_locales` の
web での消費と `id_token_hint`（RP-initiated logout）も対応済み（`CHANGELOG.md` 参照）。
残っているのは:

- **`response_mode=form_post`** — 現状 `query` 固定。最終リダイレクトを組み立てるのは web 側の
  複数経路（resume・ログイン成功・同意承認）なので、api が「URL」ではなく「送信先 + パラメータ」を
  返す形への変更が要る。
- **`prompt=select_account`** — `Prompt::parse` は none/login/consent のみ。本 IdP はブラウザごとに
  SSO セッションを 1 つしか持たないため「選ばせる別アカウント」が存在せず、対応するなら
  複数アカウント同時保持の設計から要る（Discovery では未対応として広告済み）。
