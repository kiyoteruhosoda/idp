# ADR-0020: 認証ポリシー（authentication_policies）の導入

- 日付: 2026-08-01
- 状態: 採用
- 関連: ユーザー認証・認証ポリシー仕様書（§7〜§9・§17・§24）、ADR-0008（MFA 設計）、ADR-0009 §8（認証はテナント境界内）

## 背景

これまで「誰がどの条件でログインできるか」は暗黙のルール（アカウント状態・メール検証・TOTP の
自己登録有無）だけで決まっており、テナント管理者が「このクライアントはログイン禁止」「このユーザーは
MFA 必須」といった**規則**を宣言する手段が無かった。またアカウントロックの閾値（10 回 / 15 分）が
3 つのログインサービス（OIDC・ポータル・管理コンソール）に別々にハードコードされていた。

## 決定

### 1. ポリシーはテナント単位の宣言データとし、評価はドメインの純粋関数で行う

- `authentication_policies` テーブル（テナント境界・`(tenant_id, policy_code)` 一意）に規則を保存する。
  効果（`effect`）は `allow` / `deny` / `require_mfa` の 3 値（DB ネイティブ ENUM を使わず
  `VARCHAR` + CHECK。許可値の単一の出所は Rust の `PolicyEffect`）。
- 適用条件（`conditions`、JSON）は `client_ids` / `user_ids` の 2 軸から始める。各条件は
  **空 = 制限しない**、非空 = いずれかに一致。複数条件は AND。仕様 §8 の他の条件種別
  （ネットワークゾーン・国・端末・時間帯・requested_acr 等）は将来の拡張とし、
  `deny_unknown_fields` で未知キーのタイポ（＝条件が無視され全許可になる事故）を弾く。
- 評価は `domain::authentication_policy::evaluate_policies`（純粋関数）が行う。
  優先順位は昇順（仕様 §9.2）。**`deny` は優先順位に関わらず常に勝つ**（仕様 §9.3 拒否優先）。
  次いで `require_mfa`、次いで `allow`。

### 2. 評価はパスワード検証成功後に行う（列挙防止）

ユーザー特定前に評価できる条件（クライアント）とユーザー特定後にのみ評価できる条件（ユーザー）が
あるが、資格情報を知らない攻撃者にポリシーの存在・内容を観測させないため、評価はパスワード
（またはパスキー）検証の**成功後**に一括で行う。拒否は `login.policy_denied` として監査記録し、
一致したポリシーコードを reason に残す（仕様 §21）。

### 3. `require_mfa` の充足判定

- 確認済み TOTP を持つユーザー: 既存の MFA ステップ（TOTP 入力）を経る（従来どおり）。
- TOTP 未設定のユーザー: 単一要素での成立を許さず **`MfaEnrollmentRequired` として拒否**する
  （仕様 §24.4「MFA 必須ユーザーが単一要素のみでは認証完了しないこと」）。ポータルから
  認証アプリを設定するよう案内する。
- パスキー（WebAuthn）ログイン: 所有要素 + User Verification（知識/生体）の複数要素かつ
  フィッシング耐性認証のため `require_mfa` を**満たす**ものと扱う。`deny` はパスキー経路でも
  適用する（パスワード経路だけ塞いでも迂回できるため）。

### 4. 一致ポリシー無しの既定動作は設定制（既定 allow）

仕様 §9.4 は「明示的に設定する（推奨はデフォルト拒否）」とする。既存環境（ポリシー 0 件）の挙動を
変えないため、既定は `allow` とし、`AUTH_POLICY_DEFAULT_EFFECT`（DbManaged）で `deny` へ
切り替えられるようにする。`deny` 運用では許可ポリシーを明示したクライアント・ユーザーしか
ログインできない。

### 5. アカウントロックは設定注入の値オブジェクトに集約する

ハードコードされていた閾値を `LockoutPolicy`（`max_failed_attempts` / `lock_duration_secs`）に
集約し、`LOGIN_MAX_FAILED_ATTEMPTS` / `LOGIN_LOCK_DURATION_SECS`（DbManaged、既定 10 回 / 900 秒）
から 3 つのログインサービスへ一律に注入する（仕様 §17）。ロックはユーザー単位・期限付きのみ
（恒久ロックはしない。§17.2）。

### 6. 管理は API（CRUD）から始める

`/{tenant_id}/admin/authentication-policies`（GET/POST/PUT/DELETE、`idp.tenant.admin` 必須）で
管理する。変更は `authentication_policy.created` / `.updated` / `.deleted` として監査記録する。
web 管理コンソールの画面は後続タスク（Progress AP1）。

## 適用範囲と非対象（現時点）

- 適用: OIDC 認可コードフローのログイン（パスワード・パスキー両経路）。
- 非対象（フォローアップ。Progress AP2/AP3）: ポータルログイン・管理コンソールログインへの
  ポリシー評価適用、条件種別の拡張、`require_specific_method` 効果、Step-up 認証、
  外部 IdP 連携条件。ポータルはクライアント文脈を持たないため、`client_ids` 条件が主用途の
  現段階では影響が限定的と判断した。

## 影響

- マイグレーション 0019 で `authentication_policies` を追加（reversible）。
- `LoginService` / `PasskeyAuthenticationService` / `PortalLoginService` / `AdminLoginService` の
  コンストラクタ引数が増えた（設定注入）。
- 内部認証 API（`InternalAuthenticateResponse`）に `policy_denied` / `mfa_enrollment_required`、
  パスキー完了 API に `policy_denied` が増えた。web は対応する文言（i18n キー）を表示する。
