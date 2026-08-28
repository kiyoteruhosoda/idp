//! Tenants エンティティ（ADR-0009 §1）。
//!
//! テナントは互いに独立した管理境界（Entra ID 型）。`parent_tenant_id` は作成元の系譜であり、
//! 管理権限・データアクセスの境界としては意味を持たない（権限判定は §4 の完全一致のみ）。
#![allow(dead_code)]

use crate::domain::message::MessageKey;
use crate::domain::values::TenantStatus;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// テナントの一意識別子（値オブジェクト）。生の `Uuid` と区別し、取り違えを防ぐ。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TenantId(Uuid);

impl TenantId {
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl From<Uuid> for TenantId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl From<TenantId> for Uuid {
    fn from(id: TenantId) -> Self {
        id.0
    }
}

impl std::fmt::Display for TenantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

/// テナントのアクセント色（値オブジェクト）。`#rrggbb` の小文字 16 進に正規化して保持する。
///
/// 生の `String` と区別するのは、**この値が HTML の `style` 属性へ入る**ためである。書式を
/// 型で保証しておかないと、検証を通っていない文字列が属性値に届く経路が増える（テンプレートの
/// エスケープは属性値の中身までは見ない）。許可する書式の定義はここが単一の出所で、DB の
/// CHECK は長さと先頭文字だけを見る二重防御に留める。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccentColor(String);

impl AccentColor {
    /// `#rrggbb` として解釈する。前後の空白は落とし、16 進は小文字へ正規化する。
    /// 空・空白のみは「未設定」を表す `Ok(None)`（画面から色を外す操作がこれにあたる）。
    pub fn parse(value: &str) -> Result<Option<Self>, MessageKey> {
        let value = value.trim();
        if value.is_empty() {
            return Ok(None);
        }
        let Some(hex) = value.strip_prefix('#') else {
            return Err(Self::invalid());
        };
        if hex.len() != 6 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Self::invalid());
        }
        Ok(Some(Self(format!("#{}", hex.to_ascii_lowercase()))))
    }

    /// DB・HTML へ渡す値（常に `#rrggbb` の小文字）。
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn invalid() -> MessageKey {
        MessageKey::new("api-tenant-accent-color-invalid")
    }
}

#[derive(Debug, Clone)]
pub struct Tenant {
    pub id: TenantId,
    /// 作成元テナント。`None` は root テナントのみ（構造的に唯一の行）。
    pub parent_tenant_id: Option<TenantId>,
    /// 表示名。一意制約なし・URL には使わない。
    pub name: String,
    /// アクセント色（`#rrggbb`。未設定なら `None`）。画面が「いまどのテナントにいるか」を
    /// 文字を読まずに示すために使う。表示だけの値で、認可にも識別にも使わない。
    pub accent_color: Option<AccentColor>,
    pub status: TenantStatus,
    /// 自己登録（`/auth/register`）を許可するか。既定は無効（fail-closed。SEC6）。
    pub self_registration_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod accent_color_tests {
    use super::AccentColor;

    #[test]
    fn accepts_and_normalises_six_digit_hex() {
        assert_eq!(
            AccentColor::parse(" #A1B2C3 ")
                .expect("valid")
                .unwrap()
                .as_str(),
            "#a1b2c3"
        );
    }

    /// 空は「色を外す」操作。エラーにすると管理画面から未設定へ戻せなくなる。
    #[test]
    fn treats_blank_as_unset() {
        assert_eq!(AccentColor::parse("").expect("valid"), None);
        assert_eq!(AccentColor::parse("   ").expect("valid"), None);
    }

    /// `style` 属性へ入る値なので、書式から少しでも外れたら通さない。
    #[test]
    fn rejects_anything_that_is_not_rrggbb() {
        for bad in [
            "a1b2c3",             // `#` が無い
            "#abc",               // 3 桁略記は受けない（DB の長さ 7 と揃える）
            "#a1b2c33",           // 桁あふれ
            "#a1b2cg",            // 16 進でない
            "#a1b2c3; color:red", // 属性値へ別の宣言を足す形
            "red",
        ] {
            assert!(AccentColor::parse(bad).is_err(), "{bad} must be rejected");
        }
    }
}

impl Tenant {
    /// `parent_tenant_id IS NULL` の唯一の行として root を構造的に識別する（§1）。
    pub fn is_root(&self) -> bool {
        self.parent_tenant_id.is_none()
    }

    pub fn is_active(&self) -> bool {
        self.status == TenantStatus::Active
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn tenant(parent: Option<TenantId>) -> Tenant {
        Tenant {
            id: Uuid::now_v7().into(),
            parent_tenant_id: parent,
            name: "Acme".to_string(),
            accent_color: None,
            status: TenantStatus::Active,
            self_registration_enabled: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn root_has_no_parent() {
        assert!(tenant(None).is_root());
        assert!(!tenant(Some(Uuid::now_v7().into())).is_root());
    }
}
