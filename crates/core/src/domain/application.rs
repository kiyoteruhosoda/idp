//! アプリ（application）——**RP がぶら下がる段**（ADR-0054）。
//!
//! 1 行が「利用者から見た 1 つのアプリ」を表す。OIDC の `clients` や SAML の
//! `saml_service_providers` は、そのアプリが**どう繋がるか**（binding）でしかない。
//!
//! # なぜプロトコル設定の上に段が要るか
//!
//! `clients` と `saml_service_providers` は互いを参照していない。そのため同じアプリが OIDC と
//! SAML の両方で繋がる形を表せず、認証ポリシー・同意・権限・宛名・back-channel logout の配信は
//! **すべて OIDC 側にしか付かない**（SAML のアプリには MFA を要求できない）。利用者の割り当てを
//! `clients` にぶら下げると、この一覧に 6 つ目が並ぶだけになる。
//!
//! # 割り当てはロールを持たない
//!
//! [`ApplicationAssignment`] に載るのは「使ってよいか」の 1 ビットだけである。アプリの中で何を
//! してよいかは RP が持つ（ADR-0033 / ADR-0049 の I6）。ロールの列を持つか持たないかは**モデルの
//! 形**なので、アプリごとに選べる類の設定ではない。

use crate::domain::account::AccountRef;
use crate::domain::message::MessageKey;
use crate::domain::tenant::TenantId;
use crate::domain::values::{ApplicationStatus, AssignmentMode, ClientStatus, UserStatus};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// `applications.display_name` のカラム上限。
pub const DISPLAY_NAME_MAX_LEN: usize = 255;

/// アプリ 1 件（`applications` テーブル）。
#[derive(Debug, Clone)]
pub struct Application {
    pub id: Uuid,
    /// アプリを所有するテナント。テナント越しに共有しない（ADR-0009 §1）。
    pub tenant_id: TenantId,
    /// 画面と拒否メッセージに出す名前。
    pub display_name: String,
    pub status: ApplicationStatus,
    pub assignment_mode: AssignmentMode,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// 「この利用者はこのアプリを使ってよいか」の答え（ADR-0054）。
///
/// 判定は**認証の後**に行う。認証するまで誰なのか分からないためで、これは実装の都合ではなく
/// 順序の必然である。だからこそ拒否は RP へ戻さず assay の画面で伝える
/// ——利用者から見れば「入れたのに弾かれた」ので、黙って弾くと障害と区別が付かない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationAccess {
    /// 使ってよい。
    Allowed,
    /// アプリ自体が止まっている。
    Disabled,
    /// アプリは動いているが、この利用者に割り当てが無い。
    NotAssigned,
}

impl ApplicationAccess {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }

    /// 監査ログ・構造化ログに載せる理由（運用言語 = 英語）。
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Disabled => "application_disabled",
            Self::NotAssigned => "not_assigned",
        }
    }
}

impl Application {
    /// 割り当ての有無を受け取って可否を返す（純粋関数。DB を引くのは呼び出し側）。
    ///
    /// `EVERYONE` でも `assigned` を引数に取るのは、呼び出し側が**モードを見て問い合わせを
    /// 省ける**ようにするためである（[`Self::needs_assignment_lookup`]）。ここで DB を引くと、
    /// 判定が純粋でなくなるうえ「全員」のアプリで無駄な問い合わせが毎回走る。
    pub fn admits(&self, assigned: bool) -> ApplicationAccess {
        if self.status != ApplicationStatus::Active {
            return ApplicationAccess::Disabled;
        }
        match self.assignment_mode {
            AssignmentMode::Everyone => ApplicationAccess::Allowed,
            AssignmentMode::Individual if assigned => ApplicationAccess::Allowed,
            AssignmentMode::Individual => ApplicationAccess::NotAssigned,
        }
    }

    /// **サービスアカウント**がこのアプリを使ってよいか（ADR-0059 の決定 5・6）。
    ///
    /// 「使う」とは、このアプリの宛名（`resource` の名乗り）宛のトークンを取ることである。
    /// トークン発行（`client_credentials` + `resource`）とアカウントの画面が同じこの規則を読む
    /// ——⚠ 画面が別の規則で答えると「使えると出ているのにトークンが出ない」が起きる。
    ///
    /// ⚠ **割り当てモードを見ない。** 「全員（`EVERYONE`）」に含まれるのは人だけで、
    /// サービスアカウントは必ず個別に割り当てる。
    pub fn admits_service_account(&self, assigned: bool) -> ApplicationAccess {
        if self.status != ApplicationStatus::Active {
            ApplicationAccess::Disabled
        } else if assigned {
            ApplicationAccess::Allowed
        } else {
            ApplicationAccess::NotAssigned
        }
    }

    /// 判定に割り当ての問い合わせが要るか（`EVERYONE` は要らない）。
    pub fn needs_assignment_lookup(&self) -> bool {
        self.assignment_mode == AssignmentMode::Individual
    }

    /// 新しいトークン・アサーションの発行先に使えるか。
    pub fn is_active(&self) -> bool {
        self.status == ApplicationStatus::Active
    }
}

/// アプリの表示名を検証し、格納する値を返す。
///
/// 他の管理 API と揃えて翻訳キーで返す（訳出は Presentation 層）。
pub fn validate_display_name(raw: &str) -> Result<String, MessageKey> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(MessageKey::new("api-application-name-required"));
    }
    // カラムは VARCHAR(255) ＝ **255 文字**なので、バイト数ではなく文字数で見る
    // （バイトで見ると非 ASCII を含む短い名前を取りこぼす）。
    if value.chars().count() > DISPLAY_NAME_MAX_LEN {
        return Err(MessageKey::with_value(
            "api-application-name-too-long",
            DISPLAY_NAME_MAX_LEN.to_string(),
        ));
    }
    Ok(value.to_string())
}

/// アプリの名乗り（binding の相手。ADR-0059）。
///
/// アプリが「自分」として assay に現れる口は 4 種類ある。どれも **1 つの相手は 1 つのアプリにだけ
/// 属する**（DB の UNIQUE）——2 つのアプリに属せると、その相手から来た要求がどのアプリのものか
/// 決まらない。
///
/// 2 つの null 許容列ではなく enum で持つのは、「OIDC なのに SP が入っている」という
/// 表せてはいけない状態を型で消すためである（DB 側も CHECK 制約で同じことを言っている）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingTarget {
    /// ログイン用の OIDC の RP（`clients.id`。`client_id` ではなく代理キー）。
    Oidc { client_row_id: Uuid },
    /// SAML の SP（`saml_service_providers.id`）。
    Saml { service_provider_id: Uuid },
    /// アプリ自身が assay を呼ぶときのサービスアカウント（`client_credentials` の `clients.id`）。
    ///
    /// ⚠ **サービスアカウントはアプリではない。** アプリの名乗りの 1 つである（例: wiki が名簿を
    /// 引きに来るときの client は、wiki というアプリの名乗り）。名簿の self の口は、呼んできた
    /// client のこの名乗りからアプリを決める。
    ServiceAccount { client_row_id: Uuid },
    /// アプリの API の宛名（`resources.id`。トークンの `aud` に入る値。ADR-0042）。
    Resource { resource_id: Uuid },
}

impl BindingTarget {
    /// DB の `kind` 列に入る値。許可値の単一の出所は本 enum。
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Oidc { .. } => "oidc",
            Self::Saml { .. } => "saml",
            Self::ServiceAccount { .. } => "service_account",
            Self::Resource { .. } => "resource",
        }
    }

    /// 相手の代理キー（種類を問わず 1 つ）。
    pub fn target_id(&self) -> Uuid {
        match self {
            Self::Oidc { client_row_id } | Self::ServiceAccount { client_row_id } => *client_row_id,
            Self::Saml {
                service_provider_id,
            } => *service_provider_id,
            Self::Resource { resource_id } => *resource_id,
        }
    }
}

/// アプリ ↔ 名乗り（`application_bindings` テーブル）。1 アプリに 0〜N。
#[derive(Debug, Clone)]
pub struct ApplicationBinding {
    pub id: Uuid,
    pub application_id: Uuid,
    pub target: BindingTarget,
    pub created_at: DateTime<Utc>,
}

/// アプリ × 主体（`application_assignments` テーブル）。
///
/// ⚠ ロールを持たない。ここに載るのは「使ってよいか」の 1 ビットだけである。
#[derive(Debug, Clone)]
pub struct ApplicationAssignment {
    pub id: Uuid,
    pub application_id: Uuid,
    pub principal: AccountRef,
    pub assigned_at: DateTime<Utc>,
    /// 割り当てた管理者（監査のための出所）。移行・機械経由は `None`。
    pub assigned_by: Option<Uuid>,
}

/// 割り当てられたサービスアカウント 1 行（管理 API と画面が読む読み取りモデル）。
#[derive(Debug, Clone)]
pub struct AssignedServiceAccount {
    pub client_row_id: Uuid,
    /// 発行された `client_id`（人が見分ける値）。
    pub client_id: String,
    /// クライアントの登録名。
    pub app_name: String,
    pub client_status: ClientStatus,
    pub assigned_at: DateTime<Utc>,
}

/// 割り当てられた利用者 1 行（管理 API と画面が読む読み取りモデル）。
///
/// 割り当ての行（[`ApplicationAssignment`]）と分けてあるのは、**問いが違う**ためである。
/// あちらは「誰に割り当てたか」を書くための値で、こちらは「誰が割り当てられているか」を
/// 人が読むための値 ——名前もメールも `users` にしか無いので、1 回の問い合わせで一緒に読む
/// （1 件ずつ利用者を引き直すと、名簿の長さだけ往復が増える）。
#[derive(Debug, Clone)]
pub struct AssignedUser {
    pub user_id: Uuid,
    /// トークンの主体識別子。RP 側の名簿と突き合わせるときの鍵（ADR-0049）。
    pub sub: Uuid,
    pub email: String,
    pub name: Option<String>,
    /// 利用者アカウント自体の状態。⚠ **止まっている利用者の割り当ては残る** ——復帰したときに
    /// 名簿を作り直さずに済むようにするためで、入れるかどうかは利用者の状態が別に決める。
    pub status: UserStatus,
    pub assigned_at: DateTime<Utc>,
}

/// あるアカウントに付いている割り当て 1 件（アカウントの画面が「使えるアプリ」を出すため。
/// ADR-0063 / ADR-0065）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountAssignment {
    pub application_id: Uuid,
    pub assigned_at: DateTime<Utc>,
}

/// 名簿の 1 行（ADR-0057）。RP の定期照合が読む読み取りモデル。
///
/// ⚠ **載るのは `sub` と状態だけである。** 属性の写しはログインのたびに渡っているので
/// （ADR-0049 の I5）、ここは棚卸しの口であって属性を配る口ではない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationUser {
    /// トークンの主体識別子。RP の名簿（`federated_identities`）と突き合わせる鍵。
    pub sub: Uuid,
    pub state: ApplicationUserState,
}

/// 「この人はいまこのアプリを使ってよいか」——**RP が取る行動**で 3 つに分ける（ADR-0057）。
///
/// ⚠ **理由を細かく返さない。** 「割り当てが無い」と「アカウントが止まっている」を分けると
/// 割り当てのモードが RP に漏れる（ADR-0054「RP にモードを知らせない」）うえ、⚠ **RP の行動は
/// どちらも同じ**である ——入れない・結び付きは残す。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationUserState {
    /// いま使ってよい。
    Allowed,
    /// assay に居るが、いまは使えない。⚠ **結び付きは残す**（戻る可能性がある）。
    Blocked,
    /// このテナントの利用者ではない（＝消えた）。結び付きごと落としてよい。
    Unknown,
}

impl ApplicationUserState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Blocked => "blocked",
            Self::Unknown => "unknown",
        }
    }
}

/// 名簿を組み立てるために DB から読む**事実**（判断はしない。ADR-0057 の決定 4）。
///
/// 可否は [`Application::admits`] が決める ——判定（code 発行地点）と一覧が別々の規則を持つと、
/// ⚠ **「名簿に居るのに入れない」「居ないのに入れる」**が起きる。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplicationUserFacts {
    /// 利用者アカウント自体の状態。
    pub user_status: UserStatus,
    /// 仮登録か（ADR-0064）。本人がまだ資格情報を決めていないので、ログインできない。
    pub pending_setup: bool,
    /// 要求テナントでのメンバーシップが**参加中**か。
    pub active_member: bool,
    /// このアプリの割り当て行があるか。
    pub assigned: bool,
}

impl Application {
    /// 事実から名簿の状態を決める（ADR-0057）。
    ///
    /// ⚠ **判定に無い条件を足さない。** `INDIVIDUAL` でメンバーシップを見ないのは
    /// [`Self::admits`] がそうだからで、一覧だけが厳しいと「名簿に居ないのに入れる」側へずれる。
    /// `EVERYONE` がメンバーシップを見るのは、「全員」がテナントの中だけを指すためである
    /// （ADR-0054）。
    pub fn roster_state(&self, facts: ApplicationUserFacts) -> ApplicationUserState {
        // 止まっている利用者・仮登録の利用者はそもそもログインできない。割り当ての有無より先に効く
        // （判定の側は `User::is_active` がどちらも断る）。
        if facts.user_status != UserStatus::Active || facts.pending_setup {
            return ApplicationUserState::Blocked;
        }
        if self.assignment_mode == AssignmentMode::Everyone && !facts.active_member {
            return ApplicationUserState::Blocked;
        }
        if self.admits(facts.assigned).is_allowed() {
            ApplicationUserState::Allowed
        } else {
            ApplicationUserState::Blocked
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(status: ApplicationStatus, mode: AssignmentMode) -> Application {
        let now = Utc::now();
        Application {
            id: Uuid::nil(),
            tenant_id: TenantId::from(Uuid::nil()),
            display_name: "photonest".to_string(),
            status,
            assignment_mode: mode,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn everyone_admits_without_an_assignment() {
        let a = app(ApplicationStatus::Active, AssignmentMode::Everyone);
        assert_eq!(a.admits(false), ApplicationAccess::Allowed);
        assert!(!a.needs_assignment_lookup());
    }

    #[test]
    fn individual_needs_the_row() {
        let a = app(ApplicationStatus::Active, AssignmentMode::Individual);
        assert_eq!(a.admits(false), ApplicationAccess::NotAssigned);
        assert_eq!(a.admits(true), ApplicationAccess::Allowed);
        assert!(a.needs_assignment_lookup());
    }

    /// 止めたアプリは、割り当てがあっても・全員に開いていても通さない。
    #[test]
    fn a_disabled_application_admits_nobody() {
        for mode in [AssignmentMode::Everyone, AssignmentMode::Individual] {
            let a = app(ApplicationStatus::Disabled, mode);
            assert_eq!(a.admits(true), ApplicationAccess::Disabled);
        }
    }

    #[test]
    fn display_name_is_trimmed_and_bounded() {
        assert_eq!(validate_display_name("  photonest  ").unwrap(), "photonest");
        assert!(validate_display_name("   ").is_err());
        let long: String = "あ".repeat(DISPLAY_NAME_MAX_LEN + 1);
        assert!(validate_display_name(&long).is_err());
    }

    /// ADR-0064: 仮登録の人は、割り当てがあっても名簿では「使えない」（ログインできないので）。
    #[test]
    fn a_pending_user_is_blocked_on_the_roster() {
        let application = app(ApplicationStatus::Active, AssignmentMode::Everyone);
        let facts = ApplicationUserFacts {
            user_status: UserStatus::Active,
            pending_setup: true,
            active_member: true,
            assigned: true,
        };
        assert_eq!(
            application.roster_state(facts),
            ApplicationUserState::Blocked
        );
        let facts = ApplicationUserFacts {
            pending_setup: false,
            ..facts
        };
        assert_eq!(
            application.roster_state(facts),
            ApplicationUserState::Allowed
        );
    }
}
