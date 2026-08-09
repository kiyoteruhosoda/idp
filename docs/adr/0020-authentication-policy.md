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

---

## 追補（2026-08-09。AP3: 条件種別の拡張と `require_specific_method`）

### 7. 追加した条件種別と、意図的に入れなかったもの

仕様 §8 が挙げる条件のうち、**この IdP が自分で判定できる材料を持つもの**を実装した:

| 条件 | 状態 | 判定材料 |
|---|---|---|
| `client_ids` / `user_ids` | 実装済（0019） | 認可要求・特定済み利用者 |
| `ip_cidrs`（ネットワークゾーン） | **追加** | `RequestContext.ip_address`（SEC1 の `TRUST_FORWARDED_HEADERS` 判定を通った値） |
| `time_windows`（時間帯） | **追加** | `Clock` |
| `requested_acr` | **追加** | `/authorize` の `acr_values`（0028 で `auth_sessions` へ保存） |
| 国 | 未実装 | GeoIP データベースも、それを供給する信頼済みヘッダの取り決めも配置に存在しない |
| 端末信頼 | 未実装 | 端末を登録・識別する仕組み（デバイス登録簿）自体が無い |

未実装の 2 つは「条件式を書けば動く」たぐいの不足ではなく、**判定材料を作る機能がまだ無い**。
材料の無い条件を先に置くと、管理画面に「設定できるが決して一致しない条件」が並ぶ。
Progress へ別タスクとして残す。

条件はすべて AND、各条件の中の複数値は OR。**評価材料が無い条件は「一致しない」に倒す**
（例: 接続元 IP を取れないリクエストは `ip_cidrs` 付きポリシーに一致しない）。`deny` の
取りこぼしにはなるが、逆に「材料が無いから一致とみなす」にすると `allow` が無条件に広がる。
一貫した規則の方が読み違えにくいと判断した。

タイムゾーンは IANA 名ではなく**固定 UTC オフセット（分）**で持つ。夏時間を正しく扱うには
tz データベースの同梱と更新運用が要り、「更新を怠るとポリシーが静かにずれる」というリスクを
新たに背負う。固定オフセットなら判定は常に決定的で、夏時間のある地域は帯を 2 本に分けて表せる。

### 8. `require_specific_method` は `require_mfa` と別の効果にする

`require_mfa` は「第二要素を 1 つ足せばよい（方式は問わない）」、`require_specific_method` は
「その方式でなければ通さない」（§12.2 の WebAuthn 必須・User Verification 必須）。片方に丸めると
**TOTP を登録済みの利用者が「WebAuthn 必須」をすり抜ける**。評価順は
`deny` > `require_specific_method` > `require_mfa` > `allow`（狭い要求を先に見る）。

要求内容は `authentication_policies.effect_params`（JSON）に持つ。方式は OR で、AND を表したい
場合はポリシーを 2 本に分ける（1 本の条件式に暗黙の AND を持ち込むと、管理画面での読み取りと
監査の説明が難しくなる）。

判定は**実際に使われた方式が確定した時点**で行う。具体的には:

- パスワードのみで完了する経路（OIDC パスワード・強制パスワード変更・ポータル・管理コンソール）は
  `[password]` に対して判定する。
- MFA まで進む経路は `MfaLoginService` が `[password, 第二要素]` に対して**再評価**する。
  パスワード段階だけで判定すると「TOTP を登録しているから MFA へ進む」経路で判定を素通りする。
  このために `MfaLoginService` へ認証ポリシーのリポジトリを注入した。
- パスキー経路は `[webauthn]` かつ User Verification 済みとして判定する。
- 外部 IdP 経路は `[external_idp]` として判定する（外部側でどの認証器が使われたかは観測できない
  ため、外部での MFA をもって方式要求を満たしたとはみなさない。§13.3 と同じ立場）。

### 9. 影響

- マイグレーション 0028: `authentication_policies.effect_params` 追加と `effect` の CHECK 拡張、
  `auth_sessions` へ `acr_values` / `login_hint` / `ui_locales` を追加（G12 と共通）。
- 管理 API のリクエスト・レスポンスに `effect_params` / `ip_cidrs` / `time_windows` /
  `requested_acr` が増えた（いずれも省略可、既定は空 = 制限しない）。
- `MfaLoginService` のコンストラクタ引数が増え、`MfaLoginOutcome::PolicyDenied` が増えた。
