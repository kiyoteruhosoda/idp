//! 認証ポリシー（ユーザー認証・認証ポリシー仕様書 §7〜§9）。
//!
//! 認証ポリシーは「認証時に満たすべき条件（拒否・MFA 必須）」を決定する規則であり、
//! 本人確認（パスワード・TOTP 等の認証器）とは分離する（同仕様 §2.3）。ポリシーを満たしても
//! 本人確認に成功していなければ認証成功にはならない。評価は純粋関数（[`evaluate_policies`]）で、
//! DB・フレームワークに依存しない。
#![allow(dead_code)]

use crate::domain::error::DomainError;
use crate::domain::tenant::TenantId;
use crate::domain::values::AuthenticationMethod;
use chrono::{DateTime, Datelike, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

/// ポリシーの効果（仕様 §7.4）。
///
/// `require_additional_authentication` は「第二要素を 1 つ足す」要求なので `RequireMfa`、
/// 「この方式でなければ通さない」要求は `RequireSpecificMethod`（§12.2 の WebAuthn 必須・
/// UV 必須を含む）として表す。両者を分けているのは、前者が**どれでもよい**のに対し
/// 後者は**方式を指定する**ためで、片方に丸めると「TOTP を登録済みなら WebAuthn 必須を
/// すり抜ける」といった穴になる。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyEffect {
    /// 条件を満たした場合に認証を許可する。
    Allow,
    /// 条件を満たした場合に認証を拒否する（拒否は常に許可より優先。仕様 §9.3）。
    Deny,
    /// 条件を満たした場合に MFA（追加認証）を必須とする。方式は問わない。
    RequireMfa,
    /// 条件を満たした場合に**特定の認証方式**を必須とする（AP3。パラメータは
    /// [`AuthenticationPolicy::effect_params`]）。
    RequireSpecificMethod,
}

impl PolicyEffect {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::RequireMfa => "require_mfa",
            Self::RequireSpecificMethod => "require_specific_method",
        }
    }

    /// DB 保存値（`VARCHAR` + CHECK 制約）から復元する。許可値の単一の出所は本 enum。
    pub fn parse(s: &str) -> Result<Self, DomainError> {
        match s {
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            "require_mfa" => Ok(Self::RequireMfa),
            "require_specific_method" => Ok(Self::RequireSpecificMethod),
            other => Err(DomainError::InvalidValue(format!(
                "unknown policy effect: {other}"
            ))),
        }
    }
}

/// `require_specific_method` の要求内容（仕様 §12.2）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredMethods {
    /// 許可する認証方式。**いずれか 1 つ**を実際に使っていれば満たす（OR）。
    /// 空 = 方式の指定なし（`user_verification` だけを要求する場合に使う）。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<AuthenticationMethod>,
    /// WebAuthn の User Verification（生体・PIN による利用者確認）を必須とするか。
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub user_verification: bool,
}

impl RequiredMethods {
    /// 実際に使われた認証方式（と UV の有無）が要求を満たすか。
    ///
    /// `methods` は OR。「password と webauthn の両方」のような AND を表したい場合は
    /// ポリシーを 2 本に分ける（1 本の条件の中に暗黙の AND を持ち込むと、管理画面での
    /// 読み取りと監査の説明が難しくなる）。
    pub fn satisfied_by(&self, used: &[AuthenticationMethod], user_verified: bool) -> bool {
        let method_ok = self.methods.is_empty() || used.iter().any(|m| self.methods.contains(m));
        let uv_ok = !self.user_verification || user_verified;
        method_ok && uv_ok
    }

    /// 要求を人が読める形（監査ログ用。運用言語=英語）に落とす。
    pub fn describe(&self) -> String {
        let methods: Vec<&str> = self.methods.iter().map(|m| m.as_str()).collect();
        match (methods.is_empty(), self.user_verification) {
            (true, true) => "user_verification".to_string(),
            (true, false) => "(none)".to_string(),
            (false, true) => format!("{}+user_verification", methods.join("|")),
            (false, false) => methods.join("|"),
        }
    }
}

/// 曜日・時刻で表す適用時間帯（仕様 §8「時間帯」）。
///
/// タイムゾーンは**固定オフセット（分）**で表す。IANA タイムゾーン名を受け付けないのは、
/// 夏時間の切り替わりを正しく扱うには tz データベースの同梱と更新運用が必要になり、
/// 「その更新を怠ると認証ポリシーが静かにずれる」という運用リスクを新たに背負うため。
/// 固定オフセットなら判定は常に決定的で、夏時間のある地域は 2 本のポリシーで表現できる。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeWindow {
    /// 対象曜日（0 = 日曜 … 6 = 土曜）。空 = 全曜日。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub days: Vec<u8>,
    /// 開始時刻（その日の 0 時からの分。0〜1439）。
    pub start_minute: u16,
    /// 終了時刻（同上。`start_minute` より小さい場合は**日をまたぐ**帯として扱う）。
    pub end_minute: u16,
    /// 判定に使う UTC オフセット（分。例: JST = 540）。
    #[serde(default)]
    pub utc_offset_minutes: i16,
}

impl TimeWindow {
    /// 値域を検証する（管理 API の入力検証。DB へ壊れた帯を入れない）。
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.start_minute > 1439 || self.end_minute > 1439 {
            return Err(DomainError::InvalidValue(
                "time window minutes must be 0-1439".to_string(),
            ));
        }
        if self.days.iter().any(|d| *d > 6) {
            return Err(DomainError::InvalidValue(
                "time window days must be 0 (Sunday) - 6 (Saturday)".to_string(),
            ));
        }
        if self.utc_offset_minutes < -840 || self.utc_offset_minutes > 840 {
            return Err(DomainError::InvalidValue(
                "time window UTC offset must be within +/-14:00".to_string(),
            ));
        }
        Ok(())
    }

    /// `now` がこの帯に入るか。
    pub fn contains(&self, now: DateTime<Utc>) -> bool {
        let local = now + chrono::Duration::minutes(self.utc_offset_minutes as i64);
        let minute = (local.hour() * 60 + local.minute()) as u16;
        // 日をまたぐ帯（例 22:00-06:00）は、開始日の側で曜日を判定する。またいだ翌日の
        // 早朝を「前日の帯」として扱わないと、22:00 開始の帯が 0 時で切れてしまう。
        let (in_range, day) = if self.start_minute <= self.end_minute {
            (
                minute >= self.start_minute && minute < self.end_minute,
                local.weekday().num_days_from_sunday() as u8,
            )
        } else if minute >= self.start_minute {
            (true, local.weekday().num_days_from_sunday() as u8)
        } else if minute < self.end_minute {
            // 前日の帯の続き。
            (true, (local.weekday().num_days_from_sunday() as u8 + 6) % 7)
        } else {
            (false, 0)
        };
        in_range && (self.days.is_empty() || self.days.contains(&day))
    }
}

/// ポリシーの適用条件（仕様 §8。JSON カラムに保存する）。
///
/// 各条件は **空 = 制限しない（全てに一致）**、非空 = いずれかに一致で成立。複数の条件は AND。
/// ユーザー特定前に評価できる条件（`client_ids`）とユーザー特定後にのみ評価できる条件
/// （`user_ids`）が混在するため、評価はユーザー特定後に行う（仕様 §9.1）。
///
/// **評価材料が無い条件は「一致しない」に倒す。** 例えば `ip_cidrs` を持つポリシーは、接続元 IP を
/// 取れないリクエスト（`TRUST_FORWARDED_HEADERS=false` の内部経路など）には一致しない。
/// `deny` ポリシーではこれが取りこぼしになるが、逆に「材料が無いから一致とみなす」にすると
/// `allow` ポリシーが無条件に広がる。どちらかを選ぶなら、**条件は明示的に満たされたときだけ
/// 成立する**という一貫した規則の方が読み違えにくい。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConditions {
    /// 対象クライアント（OAuth/OIDC の `client_id`）。空 = 全クライアント。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub client_ids: Vec<String>,
    /// 対象ユーザー（内部ユーザー ID）。空 = 全ユーザー。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub user_ids: Vec<Uuid>,
    /// 対象ネットワークゾーン（CIDR 表記。IPv4 / IPv6）。空 = 全ネットワーク（AP3）。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip_cidrs: Vec<String>,
    /// 対象時間帯。空 = 常時。複数指定はいずれかに入れば成立（OR。AP3）。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub time_windows: Vec<TimeWindow>,
    /// 認可要求の `acr_values` に含まれる値。空 = 要求内容を問わない（AP3・G12）。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requested_acr: Vec<String>,
}

impl PolicyConditions {
    /// 形式を検証する（管理 API の入力検証）。
    pub fn validate(&self) -> Result<(), DomainError> {
        for cidr in &self.ip_cidrs {
            IpRange::parse(cidr)?;
        }
        for window in &self.time_windows {
            window.validate()?;
        }
        Ok(())
    }

    /// 認証コンテキストに一致するか（空の条件は常に一致）。
    pub fn matches(&self, ctx: &AuthenticationContext) -> bool {
        let client_ok = self.client_ids.is_empty()
            || ctx
                .client_id
                .is_some_and(|c| self.client_ids.iter().any(|allowed| allowed == c));
        let user_ok = self.user_ids.is_empty() || self.user_ids.contains(&ctx.user_id);
        let network_ok = self.ip_cidrs.is_empty() || self.matches_network(ctx.ip_address);
        let time_ok =
            self.time_windows.is_empty() || self.time_windows.iter().any(|w| w.contains(ctx.now));
        let acr_ok = self.requested_acr.is_empty()
            || ctx
                .requested_acr
                .iter()
                .any(|requested| self.requested_acr.iter().any(|v| v == requested));
        client_ok && user_ok && network_ok && time_ok && acr_ok
    }

    fn matches_network(&self, ip_address: Option<&str>) -> bool {
        let Some(ip) = ip_address.and_then(|raw| raw.parse::<IpAddr>().ok()) else {
            // 接続元が分からないリクエストには、ネットワーク条件付きのポリシーは一致しない。
            return false;
        };
        self.ip_cidrs
            .iter()
            .filter_map(|cidr| IpRange::parse(cidr).ok())
            .any(|range| range.contains(ip))
    }
}

/// CIDR 表記のアドレス範囲（`192.0.2.0/24`・`2001:db8::/32`。プレフィクス省略時は単一アドレス）。
///
/// 外部クレートを足さずに扱えるよう、`IpAddr` のバイト列と prefix 長だけで判定する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpRange {
    network: IpAddr,
    prefix_len: u8,
}

impl IpRange {
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        let invalid = || DomainError::InvalidValue(format!("invalid CIDR or IP address: {value}"));
        let (addr_part, prefix_part) = match value.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (value, None),
        };
        let network: IpAddr = addr_part.parse().map_err(|_| invalid())?;
        let max_len = if network.is_ipv4() { 32 } else { 128 };
        let prefix_len = match prefix_part {
            Some(p) => p.parse::<u8>().map_err(|_| invalid())?,
            None => max_len,
        };
        if prefix_len > max_len {
            return Err(invalid());
        }
        Ok(Self {
            network,
            prefix_len,
        })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                prefix_matches(&net.octets(), &addr.octets(), self.prefix_len)
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                prefix_matches(&net.octets(), &addr.octets(), self.prefix_len)
            }
            // IPv4 と IPv6 は跨いで比較しない（IPv4-mapped IPv6 を暗黙に同一視すると、
            // 「IPv6 でアクセスすれば IPv4 の拒否レンジを抜けられる」ような差が生まれる）。
            _ => false,
        }
    }
}

/// 先頭 `prefix_len` ビットが一致するか。
fn prefix_matches(network: &[u8], addr: &[u8], prefix_len: u8) -> bool {
    let full_bytes = (prefix_len / 8) as usize;
    if network[..full_bytes] != addr[..full_bytes] {
        return false;
    }
    let remaining_bits = prefix_len % 8;
    if remaining_bits == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - remaining_bits);
    network[full_bytes] & mask == addr[full_bytes] & mask
}

/// ポリシー評価の入力（認証コンテキスト。仕様 §9.1「ユーザー特定後」時点の情報）。
#[derive(Debug, Clone, Copy)]
pub struct AuthenticationContext<'a> {
    /// フローのクライアント（ポータルログイン等、クライアント非依存の経路では `None`）。
    pub client_id: Option<&'a str>,
    /// 特定済みユーザーの内部 ID。
    pub user_id: Uuid,
    /// 接続元 IP（`TRUST_FORWARDED_HEADERS` の判定を通った値。取れない場合は `None`）。
    pub ip_address: Option<&'a str>,
    /// 評価時刻（時間帯条件の判定に使う）。
    pub now: DateTime<Utc>,
    /// 認可要求の `acr_values`（OIDC 以外の経路では空）。
    pub requested_acr: &'a [String],
}

impl<'a> AuthenticationContext<'a> {
    /// クライアント・ネットワーク・時刻・acr を持たない最小の文脈（ポータル/管理コンソール等）。
    pub fn for_user(user_id: Uuid, now: DateTime<Utc>) -> Self {
        Self {
            client_id: None,
            user_id,
            ip_address: None,
            now,
            requested_acr: &[],
        }
    }
}

/// 認証ポリシー 1 件（`authentication_policies` テーブル。仕様 §7.3 のサブセット）。
#[derive(Debug, Clone)]
pub struct AuthenticationPolicy {
    pub id: Uuid,
    /// ポリシーはテナント単位で管理する（テナント越しに適用されない）。
    pub tenant_id: TenantId,
    /// テナント内一意の識別コード（例: `deny-legacy-client`）。
    pub policy_code: String,
    pub policy_name: String,
    /// 評価順（昇順 = 小さいほど優先。仕様 §9.2）。
    pub priority: i32,
    pub enabled: bool,
    pub effect: PolicyEffect,
    /// `require_specific_method` の要求内容（他の効果では `None`）。
    pub effect_params: Option<RequiredMethods>,
    pub conditions: PolicyConditions,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl AuthenticationPolicy {
    /// `policy_code` の形式検証（英数字・`-`・`_`・`.`、1〜100 文字）。
    /// URL パスセグメント・監査ログにそのまま載せられる安全な文字に限定する。
    pub fn validate_code(code: &str) -> Result<(), DomainError> {
        if code.is_empty() || code.len() > 100 {
            return Err(DomainError::InvalidValue(
                "policy code must be 1-100 characters".to_string(),
            ));
        }
        if !code
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
        {
            return Err(DomainError::InvalidValue(
                "policy code must contain only ASCII alphanumerics, '-', '_' or '.'".to_string(),
            ));
        }
        Ok(())
    }

    /// 効果とパラメータの整合を検証する。
    ///
    /// `require_specific_method` は「何を要求するか」が無いと意味を持たない（何も要求しない
    /// ポリシーが `allow` と同じ顔をして並ぶ）。逆に他の効果でパラメータを持つと、管理画面で
    /// 効果を切り替えたときに死んだ設定が残る。
    pub fn validate_effect_params(
        effect: PolicyEffect,
        params: Option<&RequiredMethods>,
    ) -> Result<(), DomainError> {
        match (effect, params) {
            (PolicyEffect::RequireSpecificMethod, Some(p))
                if !p.methods.is_empty() || p.user_verification =>
            {
                Ok(())
            }
            (PolicyEffect::RequireSpecificMethod, _) => Err(DomainError::InvalidValue(
                "require_specific_method needs at least one method or user_verification"
                    .to_string(),
            )),
            (_, Some(_)) => Err(DomainError::InvalidValue(
                "effect parameters are only valid for require_specific_method".to_string(),
            )),
            (_, None) => Ok(()),
        }
    }

    /// `policy_name` の検証（空でない・200 文字以内）。
    pub fn validate_name(name: &str) -> Result<(), DomainError> {
        if name.trim().is_empty() || name.chars().count() > 200 {
            return Err(DomainError::InvalidValue(
                "policy name must be 1-200 characters".to_string(),
            ));
        }
        Ok(())
    }
}

/// ポリシー評価の結論。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// 認証を継続してよい（`matched_policy_code` = 一致した許可ポリシー。既定許可なら `None`）。
    Allow { matched_policy_code: Option<String> },
    /// 認証を拒否する（仕様 §9.3: 拒否は他の全てに優先する）。
    Deny { policy_code: String },
    /// MFA（追加認証）を完了しなければ認証成功にしない。
    RequireMfa { policy_code: String },
    /// 指定された方式で認証していなければ認証成功にしない（AP3。仕様 §12.2）。
    ///
    /// **一致した方式指定ポリシーを全件持つ。** 1 件目だけを採ると、`RequiredMethods` の
    /// 「AND はポリシーを 2 本に分けて表す」という取り決めが壊れる（優先順位が先の 1 本さえ
    /// 満たせば、もう 1 本の要求を無視して通れてしまう）。要求はすべて満たす必要がある。
    RequireMethods {
        requirements: Vec<MethodRequirement>,
    },
}

/// 一致した方式指定ポリシー 1 件（監査へどのポリシーが要求したかを残すため、コードを伴う）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodRequirement {
    pub policy_code: String,
    pub requirement: RequiredMethods,
}

impl PolicyDecision {
    /// `require_specific_method`（AP3）のうち**満たされていない**最初の 1 件を返す。
    ///
    /// 満たされているとき・そもそも方式指定でないときは `None`。判定をここに置くのは、
    /// ログイン経路が 7 本あり（OIDC パスワード / MFA / パスキー / 外部 IdP / 強制パスワード変更 /
    /// ポータル / 管理コンソール）、それぞれで書くと規則がずれるためである。
    ///
    /// 一致した要求は**全件**を検査する（1 件目だけ見ると AND の表現が壊れる）。
    pub fn unmet_method_requirement(
        &self,
        used: &[AuthenticationMethod],
        user_verified: bool,
    ) -> Option<&MethodRequirement> {
        match self {
            Self::RequireMethods { requirements } => requirements
                .iter()
                .find(|m| !m.requirement.satisfied_by(used, user_verified)),
            _ => None,
        }
    }

    /// 「第二要素を 1 つ足せば満たせるか」。MFA ステップへ誘導してよいかの判定に使う。
    ///
    /// `require_mfa` が「認証器を持つ利用者は MFA ステップへ送り、持たない利用者だけ拒否する」
    /// のと同じ扱いを方式指定にも与えるためのもの。ここで誘導しても、最終的な方式集合に対する
    /// 判定は MFA 完了側でやり直されるので、満たせない第二要素で通ることはない。
    pub fn satisfied_by_adding(
        &self,
        used: &[AuthenticationMethod],
        candidate: AuthenticationMethod,
        user_verified: bool,
    ) -> bool {
        let mut with_candidate = used.to_vec();
        with_candidate.push(candidate);
        self.unmet_method_requirement(&with_candidate, user_verified)
            .is_none()
    }
}

/// 一致するポリシーが 1 件も無いときの既定動作（仕様 §9.4「明示的に設定する」）。
///
/// 既定は `Allow`（ポリシー未設定の既存環境の挙動を変えない）。デフォルト拒否へ倒す場合は
/// 設定（`AUTH_POLICY_DEFAULT_EFFECT`）で `deny` を指定する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultPolicyEffect {
    Allow,
    Deny,
}

impl DefaultPolicyEffect {
    pub fn parse(s: &str) -> Result<Self, DomainError> {
        match s {
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            other => Err(DomainError::InvalidValue(format!(
                "unknown default policy effect: {other}"
            ))),
        }
    }
}

/// アカウントロックのポリシー（仕様 §17。失敗許容回数・ロック時間）。
///
/// 従来は各ログインサービスにハードコードされていた値（10 回 / 15 分）を、設定
/// （`LOGIN_MAX_FAILED_ATTEMPTS` / `LOGIN_LOCK_DURATION_SECS`）から注入する単一の値表現に集約する。
/// ロックはユーザー単位（仕様 §17.2）。恒久ロックは避ける（期限付きロックのみ）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockoutPolicy {
    /// 連続失敗の許容回数（この回数に達したらロック）。
    pub max_failed_attempts: i32,
    /// ロック時間（秒）。
    pub lock_duration_secs: u64,
}

impl LockoutPolicy {
    /// 失敗カウントが `failed_count` に達した時点でロックすべきなら、ロック期限を返す。
    pub fn locked_until_after_failure(
        &self,
        failed_count: i32,
        now: DateTime<Utc>,
    ) -> Option<DateTime<Utc>> {
        (failed_count >= self.max_failed_attempts)
            .then(|| now + chrono::Duration::seconds(self.lock_duration_secs as i64))
    }
}

/// 認証ポリシーを評価する（仕様 §9）。
///
/// - 対象は `enabled` かつ条件一致のポリシーのみ。
/// - `Deny` が 1 件でも一致したら**常に**拒否（優先順位に関わらず。仕様 §9.3「拒否優先」）。
/// - 次いで `RequireMfa` が一致していれば MFA を要求する（許可ポリシーと同時一致でも MFA 優先）。
/// - 残りは `Allow`。最優先（priority 最小、同値は `policy_code` 昇順で安定）の一致を記録する。
/// - 1 件も一致しなければ `default_effect` に従う（既定拒否時の `policy_code` は固定値
///   `(default)` として監査に残す）。
pub fn evaluate_policies(
    policies: &[AuthenticationPolicy],
    ctx: &AuthenticationContext<'_>,
    default_effect: DefaultPolicyEffect,
) -> PolicyDecision {
    let mut matched: Vec<&AuthenticationPolicy> = policies
        .iter()
        .filter(|p| p.enabled && p.conditions.matches(ctx))
        .collect();
    // 優先順位の昇順（同値は policy_code 昇順で決定的に）。
    matched.sort_by(|a, b| {
        a.priority
            .cmp(&b.priority)
            .then_with(|| a.policy_code.cmp(&b.policy_code))
    });

    if let Some(deny) = matched.iter().find(|p| p.effect == PolicyEffect::Deny) {
        return PolicyDecision::Deny {
            policy_code: deny.policy_code.clone(),
        };
    }
    // 方式指定は MFA 要求より先に見る。`require_mfa` は「第二要素を 1 つ足せばよい」だが
    // `require_specific_method` は「その方式でなければ通さない」で、後者の方が狭い要求のため。
    // 逆順にすると、WebAuthn 必須のポリシーがある利用者が TOTP だけで通ってしまう。
    let requirements: Vec<MethodRequirement> = matched
        .iter()
        .filter(|p| p.effect == PolicyEffect::RequireSpecificMethod)
        .map(|p| MethodRequirement {
            policy_code: p.policy_code.clone(),
            requirement: p.effect_params.clone().unwrap_or_default(),
        })
        .collect();
    if !requirements.is_empty() {
        return PolicyDecision::RequireMethods { requirements };
    }
    if let Some(mfa) = matched
        .iter()
        .find(|p| p.effect == PolicyEffect::RequireMfa)
    {
        return PolicyDecision::RequireMfa {
            policy_code: mfa.policy_code.clone(),
        };
    }
    if let Some(allow) = matched.iter().find(|p| p.effect == PolicyEffect::Allow) {
        return PolicyDecision::Allow {
            matched_policy_code: Some(allow.policy_code.clone()),
        };
    }
    match default_effect {
        DefaultPolicyEffect::Allow => PolicyDecision::Allow {
            matched_policy_code: None,
        },
        DefaultPolicyEffect::Deny => PolicyDecision::Deny {
            policy_code: "(default)".to_string(),
        },
    }
}

#[cfg(test)]
mod ap3_tests {
    use super::*;
    use chrono::TimeZone;

    fn at(hour: u32, minute: u32) -> DateTime<Utc> {
        // 2026-08-05 は水曜日（weekday 3）。
        Utc.with_ymd_and_hms(2026, 8, 5, hour, minute, 0).unwrap()
    }

    fn ctx_with(
        ip: Option<&'static str>,
        now: DateTime<Utc>,
        acr: &'static [String],
    ) -> AuthenticationContext<'static> {
        AuthenticationContext {
            client_id: None,
            user_id: Uuid::nil(),
            ip_address: ip,
            now,
            requested_acr: acr,
        }
    }

    #[test]
    fn ipv4_cidr_matches_only_inside_the_range() {
        let range = IpRange::parse("192.0.2.128/25").unwrap();
        assert!(range.contains("192.0.2.130".parse().unwrap()));
        assert!(range.contains("192.0.2.255".parse().unwrap()));
        assert!(!range.contains("192.0.2.127".parse().unwrap()));
        assert!(!range.contains("192.0.3.130".parse().unwrap()));
    }

    #[test]
    fn a_bare_address_is_a_single_host_range() {
        let range = IpRange::parse("203.0.113.7").unwrap();
        assert!(range.contains("203.0.113.7".parse().unwrap()));
        assert!(!range.contains("203.0.113.8".parse().unwrap()));
    }

    #[test]
    fn ipv6_cidr_matches_on_the_prefix() {
        let range = IpRange::parse("2001:db8:abcd::/48").unwrap();
        assert!(range.contains("2001:db8:abcd:1::1".parse().unwrap()));
        assert!(!range.contains("2001:db8:abce::1".parse().unwrap()));
    }

    /// v4 と v6 を跨いで一致させない。同一視すると「IPv6 で来れば IPv4 の拒否レンジを抜けられる」
    /// といった差が生まれる。
    #[test]
    fn address_families_do_not_cross_match() {
        let v4 = IpRange::parse("0.0.0.0/0").unwrap();
        assert!(!v4.contains("::1".parse().unwrap()));
    }

    #[test]
    fn malformed_cidrs_are_rejected_at_validation_time() {
        assert!(IpRange::parse("192.0.2.0/33").is_err());
        assert!(IpRange::parse("not-an-ip").is_err());
        assert!(IpRange::parse("192.0.2.0/abc").is_err());
    }

    /// 評価材料が無いリクエストには、ネットワーク条件付きポリシーは一致しない。
    #[test]
    fn a_network_condition_does_not_match_without_a_client_ip() {
        let conditions = PolicyConditions {
            ip_cidrs: vec!["10.0.0.0/8".to_string()],
            ..Default::default()
        };
        assert!(!conditions.matches(&ctx_with(None, at(12, 0), &[])));
        assert!(conditions.matches(&ctx_with(Some("10.1.2.3"), at(12, 0), &[])));
        assert!(!conditions.matches(&ctx_with(Some("192.0.2.1"), at(12, 0), &[])));
    }

    #[test]
    fn a_time_window_matches_inside_the_range_only() {
        let window = TimeWindow {
            days: vec![],
            start_minute: 9 * 60,
            end_minute: 18 * 60,
            utc_offset_minutes: 0,
        };
        assert!(window.contains(at(9, 0)));
        assert!(window.contains(at(17, 59)));
        assert!(
            !window.contains(at(18, 0)),
            "終了時刻は含まない（半開区間）"
        );
        assert!(!window.contains(at(8, 59)));
    }

    /// 日をまたぐ帯（22:00-06:00）は、翌日の早朝も「前日の帯」として扱う。曜日指定と
    /// 組み合わせたときにここを間違えると、金曜 22 時開始の帯が土曜 0 時で切れる。
    #[test]
    fn a_window_that_crosses_midnight_keeps_the_starting_day() {
        let window = TimeWindow {
            days: vec![3], // 水曜
            start_minute: 22 * 60,
            end_minute: 6 * 60,
            utc_offset_minutes: 0,
        };
        assert!(window.contains(at(23, 0)), "水曜 23:00 は帯の中");
        // 木曜 02:00 は「水曜開始の帯」の続き。
        let thursday_early = Utc.with_ymd_and_hms(2026, 8, 6, 2, 0, 0).unwrap();
        assert!(window.contains(thursday_early));
        // 木曜 23:00 は木曜開始の帯になるので、水曜指定では一致しない。
        let thursday_night = Utc.with_ymd_and_hms(2026, 8, 6, 23, 0, 0).unwrap();
        assert!(!window.contains(thursday_night));
    }

    #[test]
    fn the_utc_offset_shifts_the_window() {
        // JST 09:00-18:00 = UTC 00:00-09:00。
        let window = TimeWindow {
            days: vec![],
            start_minute: 9 * 60,
            end_minute: 18 * 60,
            utc_offset_minutes: 540,
        };
        assert!(window.contains(at(1, 0)), "UTC 01:00 = JST 10:00");
        assert!(!window.contains(at(10, 0)), "UTC 10:00 = JST 19:00");
    }

    #[test]
    fn requested_acr_matches_any_of_the_requested_values() {
        let conditions = PolicyConditions {
            requested_acr: vec!["urn:mace:incommon:iap:silver".to_string()],
            ..Default::default()
        };
        let requested = vec!["urn:mace:incommon:iap:silver".to_string()];
        assert!(conditions.matches(&ctx_with(
            None,
            at(12, 0),
            Box::leak(requested.into_boxed_slice())
        )));
        assert!(!conditions.matches(&ctx_with(None, at(12, 0), &[])));
    }

    #[test]
    fn required_methods_are_satisfied_by_any_listed_method() {
        let requirement = RequiredMethods {
            methods: vec![AuthenticationMethod::WebAuthn, AuthenticationMethod::Totp],
            user_verification: false,
        };
        assert!(requirement.satisfied_by(&[AuthenticationMethod::Totp], false));
        assert!(requirement.satisfied_by(
            &[
                AuthenticationMethod::Password,
                AuthenticationMethod::WebAuthn
            ],
            false
        ));
        assert!(!requirement.satisfied_by(&[AuthenticationMethod::Password], false));
    }

    /// UV 必須は「方式が合っていても UV されていなければ通さない」（§12.2）。
    #[test]
    fn user_verification_is_required_independently_of_the_method() {
        let requirement = RequiredMethods {
            methods: vec![AuthenticationMethod::WebAuthn],
            user_verification: true,
        };
        assert!(!requirement.satisfied_by(&[AuthenticationMethod::WebAuthn], false));
        assert!(requirement.satisfied_by(&[AuthenticationMethod::WebAuthn], true));
    }

    /// 方式指定は MFA 要求より先に効く。逆だと「WebAuthn 必須」の利用者が TOTP で通ってしまう。
    #[test]
    fn a_specific_method_requirement_wins_over_require_mfa() {
        let mut specific = policy_for_test("specific", 10, PolicyEffect::RequireSpecificMethod);
        specific.effect_params = Some(RequiredMethods {
            methods: vec![AuthenticationMethod::WebAuthn],
            user_verification: false,
        });
        let mfa = policy_for_test("mfa", 1, PolicyEffect::RequireMfa);
        let decision = evaluate_policies(
            &[mfa, specific],
            &ctx_with(None, at(12, 0), &[]),
            DefaultPolicyEffect::Allow,
        );
        let PolicyDecision::RequireMethods { requirements } = &decision else {
            panic!("expected RequireMethods, got {decision:?}");
        };
        assert_eq!(requirements.len(), 1);
        assert_eq!(requirements[0].policy_code, "specific");
        assert!(decision
            .unmet_method_requirement(&[AuthenticationMethod::Totp], false)
            .is_some());
        assert!(decision
            .unmet_method_requirement(&[AuthenticationMethod::WebAuthn], true)
            .is_none());
    }

    /// 一致した方式指定は**全件**を持ち、すべて満たす必要がある。1 件目だけを採ると
    /// 「AND はポリシーを 2 本に分けて表す」という取り決めが壊れ、優先順位が先の 1 本さえ
    /// 満たせばもう 1 本を無視して通れてしまう。
    #[test]
    fn every_matching_method_requirement_must_be_satisfied() {
        let mut webauthn = policy_for_test("webauthn", 1, PolicyEffect::RequireSpecificMethod);
        webauthn.effect_params = Some(RequiredMethods {
            methods: vec![AuthenticationMethod::WebAuthn],
            user_verification: false,
        });
        let mut totp = policy_for_test("totp", 2, PolicyEffect::RequireSpecificMethod);
        totp.effect_params = Some(RequiredMethods {
            methods: vec![AuthenticationMethod::Totp],
            user_verification: false,
        });
        let decision = evaluate_policies(
            &[webauthn, totp],
            &ctx_with(None, at(12, 0), &[]),
            DefaultPolicyEffect::Allow,
        );
        let PolicyDecision::RequireMethods { requirements } = &decision else {
            panic!("expected RequireMethods, got {decision:?}");
        };
        assert_eq!(requirements.len(), 2, "一致した方式指定を全件持つ");

        // 優先順位が先の WebAuthn だけを満たしても、TOTP の要求が残る。
        let unmet = decision
            .unmet_method_requirement(&[AuthenticationMethod::WebAuthn], true)
            .expect("totp requirement is still unmet");
        assert_eq!(unmet.policy_code, "totp");
        // 両方を満たせば通る。
        assert!(decision
            .unmet_method_requirement(
                &[AuthenticationMethod::WebAuthn, AuthenticationMethod::Totp],
                true
            )
            .is_none());
    }

    /// 拒否は方式指定よりさらに優先する（仕様 §9.3）。
    #[test]
    fn deny_still_wins_over_a_specific_method_requirement() {
        let mut specific = policy_for_test("specific", 1, PolicyEffect::RequireSpecificMethod);
        specific.effect_params = Some(RequiredMethods {
            methods: vec![AuthenticationMethod::WebAuthn],
            user_verification: false,
        });
        let deny = policy_for_test("deny", 99, PolicyEffect::Deny);
        assert!(matches!(
            evaluate_policies(
                &[specific, deny],
                &ctx_with(None, at(12, 0), &[]),
                DefaultPolicyEffect::Allow
            ),
            PolicyDecision::Deny { .. }
        ));
    }

    fn policy_for_test(code: &str, priority: i32, effect: PolicyEffect) -> AuthenticationPolicy {
        AuthenticationPolicy {
            id: Uuid::nil(),
            tenant_id: TenantId::from(Uuid::nil()),
            policy_code: code.to_string(),
            policy_name: code.to_string(),
            priority,
            enabled: true,
            effect,
            effect_params: None,
            conditions: PolicyConditions::default(),
            created_at: at(0, 0),
            updated_at: at(0, 0),
        }
    }

    /// `require_specific_method` は要求内容が無いと意味を持たない（`allow` と同じ顔をして並ぶ）。
    #[test]
    fn effect_params_must_match_the_effect() {
        assert!(AuthenticationPolicy::validate_effect_params(
            PolicyEffect::RequireSpecificMethod,
            None
        )
        .is_err());
        assert!(AuthenticationPolicy::validate_effect_params(
            PolicyEffect::RequireSpecificMethod,
            Some(&RequiredMethods::default())
        )
        .is_err());
        assert!(AuthenticationPolicy::validate_effect_params(
            PolicyEffect::Allow,
            Some(&RequiredMethods {
                methods: vec![AuthenticationMethod::Totp],
                user_verification: false,
            })
        )
        .is_err());
        assert!(AuthenticationPolicy::validate_effect_params(PolicyEffect::Deny, None).is_ok());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn fixed_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0).unwrap()
    }

    fn tenant() -> TenantId {
        TenantId::from(Uuid::from_u128(0x0197_0000_0000_7000_8000_0000_0000_0001))
    }

    fn policy(
        code: &str,
        priority: i32,
        effect: PolicyEffect,
        conditions: PolicyConditions,
    ) -> AuthenticationPolicy {
        AuthenticationPolicy {
            id: Uuid::new_v4(),
            effect_params: None,
            tenant_id: tenant(),
            policy_code: code.to_string(),
            policy_name: code.to_string(),
            priority,
            enabled: true,
            effect,
            conditions,
            created_at: fixed_now(),
            updated_at: fixed_now(),
        }
    }

    fn ctx(user_id: Uuid, client_id: Option<&str>) -> AuthenticationContext<'_> {
        AuthenticationContext {
            client_id,
            user_id,
            ip_address: None,
            now: fixed_now(),
            requested_acr: &[],
        }
    }

    #[test]
    fn no_policies_falls_back_to_default_effect() {
        let user = Uuid::new_v4();
        assert_eq!(
            evaluate_policies(&[], &ctx(user, None), DefaultPolicyEffect::Allow),
            PolicyDecision::Allow {
                matched_policy_code: None
            }
        );
        assert_eq!(
            evaluate_policies(&[], &ctx(user, None), DefaultPolicyEffect::Deny),
            PolicyDecision::Deny {
                policy_code: "(default)".to_string()
            }
        );
    }

    #[test]
    fn empty_conditions_match_everything() {
        let user = Uuid::new_v4();
        let p = policy(
            "all",
            100,
            PolicyEffect::RequireMfa,
            PolicyConditions::default(),
        );
        assert_eq!(
            evaluate_policies(&[p], &ctx(user, Some("app")), DefaultPolicyEffect::Allow),
            PolicyDecision::RequireMfa {
                policy_code: "all".to_string()
            }
        );
    }

    /// 仕様 §9.3: 拒否は許可・MFA より常に優先する（優先順位の値に関わらず）。
    #[test]
    fn deny_wins_over_allow_and_mfa_regardless_of_priority() {
        let user = Uuid::new_v4();
        let policies = vec![
            policy(
                "allow-any",
                1,
                PolicyEffect::Allow,
                PolicyConditions::default(),
            ),
            policy(
                "mfa-any",
                2,
                PolicyEffect::RequireMfa,
                PolicyConditions::default(),
            ),
            policy(
                "deny-any",
                999,
                PolicyEffect::Deny,
                PolicyConditions::default(),
            ),
        ];
        assert_eq!(
            evaluate_policies(&policies, &ctx(user, None), DefaultPolicyEffect::Allow),
            PolicyDecision::Deny {
                policy_code: "deny-any".to_string()
            }
        );
    }

    /// 仕様 §9.3: 追加認証（MFA）ポリシーは通常許可より優先する。
    #[test]
    fn require_mfa_wins_over_allow() {
        let user = Uuid::new_v4();
        let policies = vec![
            policy(
                "allow-any",
                1,
                PolicyEffect::Allow,
                PolicyConditions::default(),
            ),
            policy(
                "mfa-any",
                100,
                PolicyEffect::RequireMfa,
                PolicyConditions::default(),
            ),
        ];
        assert_eq!(
            evaluate_policies(&policies, &ctx(user, None), DefaultPolicyEffect::Allow),
            PolicyDecision::RequireMfa {
                policy_code: "mfa-any".to_string()
            }
        );
    }

    #[test]
    fn disabled_policies_are_ignored() {
        let user = Uuid::new_v4();
        let mut p = policy(
            "deny-any",
            1,
            PolicyEffect::Deny,
            PolicyConditions::default(),
        );
        p.enabled = false;
        assert_eq!(
            evaluate_policies(&[p], &ctx(user, None), DefaultPolicyEffect::Allow),
            PolicyDecision::Allow {
                matched_policy_code: None
            }
        );
    }

    #[test]
    fn client_condition_limits_scope() {
        let user = Uuid::new_v4();
        let p = policy(
            "deny-legacy",
            1,
            PolicyEffect::Deny,
            PolicyConditions {
                client_ids: vec!["legacy-app".to_string()],
                user_ids: vec![],
                ..Default::default()
            },
        );
        // 対象クライアントのみ拒否。
        assert!(matches!(
            evaluate_policies(
                std::slice::from_ref(&p),
                &ctx(user, Some("legacy-app")),
                DefaultPolicyEffect::Allow
            ),
            PolicyDecision::Deny { .. }
        ));
        // 他クライアント・クライアント無し（ポータル）は一致しない。
        assert!(matches!(
            evaluate_policies(
                std::slice::from_ref(&p),
                &ctx(user, Some("other-app")),
                DefaultPolicyEffect::Allow
            ),
            PolicyDecision::Allow { .. }
        ));
        assert!(matches!(
            evaluate_policies(
                std::slice::from_ref(&p),
                &ctx(user, None),
                DefaultPolicyEffect::Allow
            ),
            PolicyDecision::Allow { .. }
        ));
    }

    #[test]
    fn user_condition_limits_scope_and_conditions_are_anded() {
        let target = Uuid::new_v4();
        let other = Uuid::new_v4();
        let p = policy(
            "mfa-target-on-app",
            1,
            PolicyEffect::RequireMfa,
            PolicyConditions {
                client_ids: vec!["app".to_string()],
                user_ids: vec![target],
                ..Default::default()
            },
        );
        // 両条件一致で成立（AND）。
        assert!(matches!(
            evaluate_policies(
                std::slice::from_ref(&p),
                &ctx(target, Some("app")),
                DefaultPolicyEffect::Allow
            ),
            PolicyDecision::RequireMfa { .. }
        ));
        // 片方だけでは不成立。
        assert!(matches!(
            evaluate_policies(
                std::slice::from_ref(&p),
                &ctx(other, Some("app")),
                DefaultPolicyEffect::Allow
            ),
            PolicyDecision::Allow { .. }
        ));
        assert!(matches!(
            evaluate_policies(
                std::slice::from_ref(&p),
                &ctx(target, Some("another")),
                DefaultPolicyEffect::Allow
            ),
            PolicyDecision::Allow { .. }
        ));
    }

    /// 同効果のポリシーが複数一致した場合は priority 昇順の先頭を記録する（監査で追跡するため）。
    #[test]
    fn lowest_priority_value_wins_within_same_effect() {
        let user = Uuid::new_v4();
        let policies = vec![
            policy(
                "mfa-low",
                100,
                PolicyEffect::RequireMfa,
                PolicyConditions::default(),
            ),
            policy(
                "mfa-high",
                10,
                PolicyEffect::RequireMfa,
                PolicyConditions::default(),
            ),
        ];
        assert_eq!(
            evaluate_policies(&policies, &ctx(user, None), DefaultPolicyEffect::Allow),
            PolicyDecision::RequireMfa {
                policy_code: "mfa-high".to_string()
            }
        );
    }

    #[test]
    fn effect_round_trips_through_str() {
        for effect in [
            PolicyEffect::Allow,
            PolicyEffect::Deny,
            PolicyEffect::RequireMfa,
        ] {
            assert_eq!(PolicyEffect::parse(effect.as_str()).unwrap(), effect);
        }
        assert!(PolicyEffect::parse("unknown").is_err());
    }

    #[test]
    fn policy_code_validation_rejects_unsafe_values() {
        assert!(AuthenticationPolicy::validate_code("deny-high_risk.v2").is_ok());
        assert!(AuthenticationPolicy::validate_code("").is_err());
        assert!(AuthenticationPolicy::validate_code(&"a".repeat(101)).is_err());
        assert!(AuthenticationPolicy::validate_code("スペース入り code").is_err());
        assert!(AuthenticationPolicy::validate_code("slash/code").is_err());
    }

    #[test]
    fn lockout_policy_locks_only_at_threshold() {
        let policy = LockoutPolicy {
            max_failed_attempts: 5,
            lock_duration_secs: 900,
        };
        let now = fixed_now();
        assert_eq!(policy.locked_until_after_failure(4, now), None);
        assert_eq!(
            policy.locked_until_after_failure(5, now),
            Some(now + chrono::Duration::seconds(900))
        );
        assert!(policy.locked_until_after_failure(6, now).is_some());
    }

    #[test]
    fn conditions_serde_round_trip() {
        let user = Uuid::new_v4();
        let conditions = PolicyConditions {
            client_ids: vec!["app".to_string()],
            user_ids: vec![user],
            ..Default::default()
        };
        let json = serde_json::to_string(&conditions).unwrap();
        assert_eq!(
            serde_json::from_str::<PolicyConditions>(&json).unwrap(),
            conditions
        );
        // 空条件は `{}` に落ちる（DB の JSON カラムを簡潔に保つ）。
        assert_eq!(
            serde_json::to_string(&PolicyConditions::default()).unwrap(),
            "{}"
        );
        // 未知のキーは拒否する（タイポで条件が無視され全許可になる事故を防ぐ）。
        assert!(serde_json::from_str::<PolicyConditions>(r#"{"clientIds": []}"#).is_err());
    }
}
