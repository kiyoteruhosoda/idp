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

use crate::domain::message::MessageKey;
use crate::domain::tenant::TenantId;
use crate::domain::values::{ApplicationStatus, AssignmentMode};
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

/// アプリが繋がる先（binding の相手）。
///
/// 2 つの null 許容列ではなく enum で持つのは、「OIDC なのに SP が入っている」という
/// 表せてはいけない状態を型で消すためである（DB 側も CHECK 制約で同じことを言っている）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingTarget {
    /// OIDC の RP（`clients.id`。`client_id` ではなく代理キー）。
    Oidc { client_row_id: Uuid },
    /// SAML の SP（`saml_service_providers.id`）。
    Saml { service_provider_id: Uuid },
}

impl BindingTarget {
    /// DB の `protocol` 列に入る値。許可値の単一の出所は本 enum。
    pub fn protocol(&self) -> &'static str {
        match self {
            Self::Oidc { .. } => "oidc",
            Self::Saml { .. } => "saml",
        }
    }

    /// 相手の代理キー（プロトコルを問わず 1 つ）。
    pub fn target_id(&self) -> Uuid {
        match self {
            Self::Oidc { client_row_id } => *client_row_id,
            Self::Saml {
                service_provider_id,
            } => *service_provider_id,
        }
    }
}

/// アプリ ↔ 認証方法（`application_bindings` テーブル）。1 アプリに 0〜N。
#[derive(Debug, Clone)]
pub struct ApplicationBinding {
    pub id: Uuid,
    pub application_id: Uuid,
    pub target: BindingTarget,
    pub created_at: DateTime<Utc>,
}

/// アプリ × 利用者（`application_assignments` テーブル）。
///
/// ⚠ ロールを持たない。ここに載るのは「使ってよいか」の 1 ビットだけである。
#[derive(Debug, Clone)]
pub struct ApplicationAssignment {
    pub application_id: Uuid,
    pub user_id: Uuid,
    pub assigned_at: DateTime<Utc>,
    /// 割り当てた管理者（監査のための出所）。移行・機械経由は `None`。
    pub assigned_by: Option<Uuid>,
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
}
