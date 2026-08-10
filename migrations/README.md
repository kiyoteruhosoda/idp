# migrations

sqlx マイグレーション（MariaDB）を管理する。

- ファイル名: `<version>_<description>.sql`（reversible 運用時は `.up.sql` / `.down.sql` を対で用意）。
- `version` は sqlx が採番する連番（タイムスタンプ）。この version が
  スキーマ・マスタデータのバージョン整合性の SSOT（`_sqlx_migrations` テーブル）。
- 適用: `sqlx migrate run`（アプリ起動時には**適用しない**。起動時は「DB が期待 version 以上か」を
  照合するのみ ＝ fail-fast。詳細は `docs/adr/0004-schema-version-sync.md`）。
- 規約: DB ネイティブ ENUM 禁止（`VARCHAR` + `CHECK`）、UUID は `CHAR(36)`（エンティティ主キーは
  UUIDv7・揮発トークンは v4。ADR-0009 §12）、時刻は UTC の `DATETIME(6)`。
  詳細は `.claude/skills/db-migration/` と `CLAUDE.md`「DB モデリング」を参照。
- マスタデータ（root テナント・権限コード・初期管理ユーザー等）も冪等 upsert のマイグレーション
  として書く。単一の出所は当該 seed マイグレーション自身とし、値を他所へ重複させない。

> **注意（ADR-0009 §11 の一度限りの刷新）**: マルチテナント対応で初期 DDL・マスタデータを全面的に
> 作り直した（既存データは破棄・全環境 DB 再作成。手順は `docs/OPERATIONS.md`「DB を作り直したいとき」）。
> 刷新後は従来どおり追記型マイグレーション（expand/contract・up/down 対・冪等 seed）に戻る。
> ベースラインの書き換えは以後行わない。

現行のマイグレーション:

- `0001_baseline`: マルチテナント対応の全テーブル（ADR-0009）。`tenants`（`is_root` 番兵列 +
  単一 root UNIQUE）・`tenant_memberships`・`users`（`tenant_id`・`must_change_password`）・
  `clients`（テナント内一意の `client_id`）・`permissions`・`user_permissions`（scope = `tenant_id`）・
  `auth_sessions` / `authorization_codes` / `refresh_tokens` / `client_consents`
  （`(tenant_id, client_id)` 複合外部キー）・`sso_sessions`（ホスト共有のため tenant なし）・
  `signing_keys`・`revoked_access_tokens`・`user_totp_secrets`・`user_webauthn_credentials`・
  `passkey_challenges`・`audit_log`（`tenant_id` 追跡列）。
- `0002_seed_master_data`: マスタデータ seed（冪等）。root テナント（**固定 UUID**
  `00000000-0000-7000-8000-000000000001`。全環境共通で git 管理する。ADR-0011）、
  `idp.system.admin` の scope = root を縛る CHECK 制約（固定 root UUID を
  リテラル化して `PREPARE`/`EXECUTE` で付与）、
  権限コード（`idp.system.admin` / `idp.tenant.admin`）、初期管理者 `admin@example.com`
  （root 所属・HOME メンバーシップ・`must_change_password = 1`・`idp.system.admin` を DB 直接付与）。
- `0009_default_admin_password`: 初期管理者 `admin@example.com` の既定パスワードを、メールアドレスと
  同じ `admin@example.com` へ更新する（0002 の旧既定 `ChangeMe!123` のままの行に限定。変更済み
  パスワードは上書きしない）。追記型のため 0002 は書き換えず、本マイグレーションで更新する。
- `0012_rename_root_tenant`: root テナントの既定表示名を `Root` から `ROOT` へ更新する（0002 の seed
  既定 `Root` のままの行に限定。運用者が別名へ変更した行は上書きしない）。追記型のため 0002 は
  書き換えず、本マイグレーションで更新する。
- `0013_admin_username_email`: 初期管理者 `admin@example.com` のログイン識別子（`preferred_username`）を、
  メールアドレスと同じ `admin@example.com` へ更新する（0002 の seed 既定 `admin` のままの行に限定。
  運用者が別名へ変更した行は上書きしない）。ログインは email ではなく `preferred_username` で照合する
  （ADR-0009 §8）ため、初期案内どおり `admin@example.com` でログインできるようにする。追記型のため
  0002 は書き換えず、本マイグレーションで更新する。
- `0014_membership_suspended`: `tenant_memberships.status` の許可値へ `SUSPENDED` を追加する（MT24）。
  ゲストの一時停止用。CHECK 制約の張り替えのみで既存行は変更しない（expand）。`down` は残存する
  `SUSPENDED` 行を `INVITED` へ倒してから旧 CHECK へ戻す（`ACTIVE` へ戻すと、止めたはずのゲストの
  アクセスがロールバックで復活してしまうため）。
- `0015_drop_saml_identity_providers`: 0008 で追加した外部 IdP 設定表 `saml_identity_providers` を削除する
  （参照コードは既に存在しない。ADR-0004 §6 の expand/contract の contract 側。MT28）。`down` は 0008 と
  同一定義で再作成する（ENGINE・CHARSET・COLLATE を含めて一致させないと外部キーが errno 150 で失敗する）。
  行データは復元しない。

- `0017_application_log`: アプリケーションログ表 `log` を追加する（`CLAUDE.md`「ログ」）。api・web の
  WARN / ERROR を構造化ログと同時に保存し、管理コンソールから参照できるようにする。追記専用の運用情報の
  ため外部キーは張らない（テナント・ユーザー削除後も行を保持する）。許可値（`level` / `service`）は
  DB ネイティブ ENUM ではなく `VARCHAR` + `CHECK` で持ち、Rust 側 enum（`domain::application_log`）で
  集中管理する。`down` は表ごと削除する（業務データを持たないため）。
- `0018_saml_sso_requests`: SAML SP-initiated SSO の進行状態表 `saml_sso_requests` を追加する
  （OIDC の `auth_sessions` に相当。web ハンドオフのハンドル・検証済み ACS・`InResponseTo`・RelayState を
  応答発行まで保持する）。`down` は表ごと削除する（一時状態のみでロールバック時に失うのは進行中の
  SSO フローだけ。SP からやり直せる）。
- `0020_sso_session_authentication_context`: `sso_sessions` に認証コンテキスト
  （`authentication_methods` JSON・`authentication_strength`・`mfa_completed_at`）を追加する（AP4）。
  「どの方式で・どの強度で認証したか」をセッションに残し、Step-up（AP5）と認証ポリシーの
  `require_mfa` 判定の材料となる。既存行は `single_factor` を既定値として埋める（expand）。
  許可値は `VARCHAR` + `CHECK`（Rust 側 `domain::values::AuthenticationStrength` で集中管理）。
- `0021_backchannel_logout_deliveries`: バックチャネルログアウトの配送キュー表
  `backchannel_logout_deliveries` と、`sid` を発行経路へ通すための列
  （`auth_sessions.sso_sid`・`authorization_codes.sid`・`refresh_tokens.sid`）を追加する（G5）。
  `/token` はブラウザ Cookie を読めない（ADR-0018）ため、SSO セッションの `sid` を
  auth_session → authorization_code / refresh_token と受け渡して ID Token へ載せる。
  キューには**署名済み logout_token を保存しない**（再送のたびに発行し直す。長命な bearer を
  DB に寝かせないため）。`down` は表と列を削除する（配送待ちの再試行だけを失う）。
- `0022_sso_session_step_up`: `sso_sessions.step_up_at` を追加する（AP5）。機微操作の再認証鮮度を
  測る基準時刻で、単要素なら本列、多要素なら `mfa_completed_at` を見る。既存行は NULL
  （＝鮮度不明として再認証を要求する fail-closed 側）。
- `0023_user_authenticators`: 認証器の統合レジストリ `user_authenticators` を追加する（AP9。expand
  フェーズ）。種別・状態（`pending`→`active`⇄`suspended`→`revoked`）・ラベル・最終使用時刻を
  一元管理する。**秘密は移送しない**（TOTP は `user_totp_secrets`、パスキーは
  `user_webauthn_credentials` に残し、`credential_ref` で対応付ける）。既存の TOTP・パスキーは
  冪等な `INSERT ... SELECT` で backfill する。秘密の集約は contract フェーズ（`docs/Progress.md` AP11）。
- `0024_external_identity_providers`: 外部 IdP 連携の 3 表を追加する（AP10）。
  `external_identity_providers`（テナントごとの外部 OpenID Provider 設定。クライアント
  シークレットは暗号化列）、`user_external_identities`（`iss` + `sub` による同一性。
  `(provider_id, external_subject)` と `(user_id, provider_id)` を UNIQUE）、
  `external_login_requests`（`state` のハッシュ・`nonce`・PKCE verifier を認可往復の間だけ保持）。
  `down` は 3 表を削除する（連携の対応付けを失うため、再連携が必要になる）。
- `0025_refresh_token_grant_family`: `refresh_tokens.grant_hash`（＋索引）を追加する（SEC8）。
  code 交換で発行した根トークンと、そこから rotation で派生した子孫が同じ値を持つ **トークン
  ファミリの識別子**で、値は元の authorization code の SHA-256。再利用検知時にこの列 1 本で
  ファミリごと失効させる（`parent_hash` は 1 段ずつしか辿れず、子孫を追えなかった）。
  既存行は再帰 CTE で根から辿り、**チェーン全体を同じ家族 id で埋め戻す**（根だけ埋めると
  移行前に rotation 済みのチェーンが分裂し、古いトークンの再生で子孫が失効しない穴が残る）。
  `down` は列と索引を削除する（再利用検知は提示トークン 1 本の失効へ戻る）。
- `0029_user_login_identifiers`: ログイン識別子の登録簿 `user_login_identifiers` を追加する（AP8。
  expand フェーズ。ADR-0025）。種別（`username` / `email` / `phone_number` / `employee_number`）・
  表示値・正規化値・有効/無効を持ち、`(tenant_id, identifier_type, normalized_value)` を UNIQUE に
  する（無効な行も一意の対象＝止めた値を他人が取れない）。**既存データは移さない**。主たる
  ログイン識別子は `users.preferred_username` のままで、本表には追加の識別子だけを置く
  （解決は「登録簿 → `preferred_username`」の順）。写しを取ると同じ値が 2 か所にでき、同期漏れが
  そのまま「変更前の名前でログインできる」「無効化したのに認証が通る」になるため、主識別子の
  移送は contract フェーズ（`docs/Progress.md` AP15）へ分ける。`users.email` も取り込まない
  （取り込むと適用した瞬間からメールでログインできてしまい、認証の入り口が黙って広がる）。
  `down` は表ごと削除する（追加登録した識別子だけを失い、パスワードログインは通り続ける）。
- `0030_client_secret_post`: `clients.token_endpoint_auth_method` の許可値へ `client_secret_post` を
  追加する（G3。RFC 6749 §2.3.1）。CHECK 制約の張り替えのみで既存行は変更しない（expand）。
  多くの RP ライブラリ・SaaS 連携が body での secret 提示を既定にするため、方式が合わないだけで
  連携できない状態を解消する。`down` は残存する `client_secret_post` 行を `client_secret_basic` へ
  倒してから旧 CHECK へ戻す（`none` へ倒すと confidential クライアントの認証が黙って外れるため）。

- `0031_password_policy`: パスワードポリシーの拡張（AP7。ADR-0026）。退役したパスワードハッシュを
  積む `user_password_history` と、現行パスワードの設定時刻 `users.password_changed_at` を追加する。
  履歴に置くのは**置き換えられたハッシュだけ**で、現行の写しは持たない（2 か所にあると更新漏れで
  履歴と現行がずれる）。保存形式は現行と同じ argon2 の PHC 文字列で、平文も可逆な値も持たない。
  `password_changed_at` は **NULL 許容**にする —— NOT NULL にすると、ローリングデプロイ中に列を
  知らない旧プロセスの INSERT が失敗して利用者を作れなくなる。既存行は `created_at` で埋め戻す
  （`updated_at` は表示名変更等でも動くため「最後にパスワードを変えた時刻」としては新しすぎる方向へ
  誤る）。有効期限の既定は無期限なので、この埋め戻しで誰かのログインが即座に止まることはない。
  `down` は列と表を落とす（判定材料が消えるだけで、パスワード認証は通り続ける）。

- `0032_auth_session_prompt_set`: `auth_sessions.prompt` を**値の集合**として保存できるようにする
  （G12）。`prompt` は空白区切りの複数値（`prompt=select_account consent` のように「アカウントを
  選ばせたうえで同意も取り直す」と要求できる）だが、列は単一値の CHECK 付き VARCHAR(16) で、
  複数値も `select_account` も保存できなかった。保存できない値はアプリ側で未知の値として捨てられ、
  **要求が無言で無視される**（有効な SSO があれば黙って現在のアカウントで続く）。CHECK を外して
  VARCHAR(64) へ広げる —— 集合を CHECK で表すと「空白区切りの各要素が許可値であること」を SQL で
  書くことになり、値が増えるたびに壊れやすい式が伸びる。許可値の単一の出所は Rust の `Prompt` で、
  書き込む値は必ず `PromptSet` が正規化した既知の値の並びである。既存行は 1 要素の集合として
  そのまま読めるため移行は不要。`down` は集合・`select_account` の行を NULL へ落としてから
  単一値の列と CHECK へ戻す。

root テナントの UUID は固定値 `00000000-0000-7000-8000-000000000001`（全環境共通・git 管理。ADR-0011）。
管理者ログイン URL は `/00000000-0000-7000-8000-000000000001/...`。

- `0033_audit_log_indexes`: `audit_log` の索引を管理コンソールの絞り込みへ合わせる（G8）。単一列
  `tenant_id` / `event_type` を落とし、`(tenant_id, occurred_at)` を土台に `event_type` / `result` /
  `client_id` / `user_id` を挟んだ複合索引を張る。`occurred_at` 単独と `correlation_id` は残す
  （前者は保持期間削除がテナント横断で引き、後者は追跡がテナント横断のため）。行データは変えない。
