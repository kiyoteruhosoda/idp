//! テナントへ排他的に割り当てたドメイン（MT25。ADR-0029）。
//!
//! 1 行が「このドメインを名乗る利用者は、このテナントの利用者である」を表す。ログイン欄に
//! `local@domain` の形で入力されたとき、ドメインから**所属元テナントを 1 つに決める**ために使う
//! （home realm discovery）。所属元が決まれば引くのは 1 テナントの登録簿だけになり、参加中の
//! ゲストを横断走査せずに済む —— その走査こそが「同名のゲストが 2 人参加すると双方が締め出される」
//! 原因だった（`crate::application::login_user_resolution`）。
//!
//! # なぜドメインなのか
//!
//! 識別子の一意性をクロステナントへ広げれば解決の範囲と一致するが、ADR-0009 §1 のテナント独立が
//! 壊れる（あるテナントが `admin` を取ると他のどのテナントでも使えなくなる）。ドメインなら
//! 取り合いの対象が所有関係で決まるので、テナント同士が名前の在庫を共有せずに済む。Entra ID の
//! UPN がグローバル一意なのも同じ理屈で、一意なのは全体空間ではなく
//! 「ドメイン × その中のローカル部」である。

use crate::domain::message::MessageKey;
use crate::domain::tenant::TenantId;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// `tenant_domains.domain` の格納先カラム上限（DNS 名の上限と同じ 253）。
pub const DOMAIN_MAX_LEN: usize = 253;
/// DNS のラベル長上限。
const LABEL_MAX_LEN: usize = 63;

#[derive(Debug, Clone)]
pub struct TenantDomain {
    pub id: Uuid,
    /// このドメインを所有するテナント。
    pub tenant_id: TenantId,
    /// 正規化済みのドメイン（[`normalize_domain`]）。
    pub domain: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// ドメインを照合キーへ正規化する（小文字化・前後空白と末尾ドットの除去）。
///
/// 末尾ドットを落とすのは、`corp.example.` と `corp.example` が DNS では同じ名前を指すため。
/// 残すと同じドメインを 2 つのテナントが別々に押さえられてしまい、一意制約が意味を失う。
pub fn normalize_domain(raw: &str) -> String {
    raw.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// 登録できるドメインかを検証し、正規化した値を返す。
///
/// **A ラベル（punycode）だけを受け付ける。** Unicode のドメインをそのまま許すと、同じ名前が
/// U ラベルと A ラベルの 2 通りで登録でき、一意制約をすり抜ける。入力側の `local@domain` も
/// ここと同じ正規化で照合するため、U ラベルで打たれた入力はドメイン経路に掛からない
/// （従来のゲスト走査へ落ちるだけで、入れなくなるわけではない）。
///
/// エラーは利用者ではなく管理者へ返るが、他の管理 API と揃えて翻訳キーで返す（訳出は
/// Presentation 層）。
pub fn validate_domain(raw: &str) -> Result<String, MessageKey> {
    let normalized = normalize_domain(raw);
    if normalized.is_empty() {
        return Err(MessageKey::new("api-tenant-domain-required"));
    }
    if normalized.len() > DOMAIN_MAX_LEN {
        return Err(MessageKey::with_value(
            "api-tenant-domain-too-long",
            DOMAIN_MAX_LEN.to_string(),
        ));
    }
    // 単一ラベル（`corp`）も許す。AD の内部ドメインのように、ドットの無い接尾辞は実在する。
    let labels_are_valid = normalized.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= LABEL_MAX_LEN
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    });
    if !labels_are_valid {
        return Err(MessageKey::new("api-tenant-domain-invalid"));
    }
    Ok(normalized)
}

/// ログイン欄の入力を「ローカル部 + 正規化済みドメイン」へ分解する。
///
/// ドメイン修飾された入力（`alice@corp.example`）だけが分解でき、裸のユーザー名は `None` になる。
/// `@` が複数ある入力も `None` —— どこがドメインか一意に決まらない値でテナントを選ばせない。
///
/// 判定は [`crate::domain::login_identifier::LoginIdentifierType::Email`] の `accepts` と同じ
/// 「`@` を挟んで両側に文字がある」で、そこにドメインの書式検証を重ねる。書式が通らない入力は
/// ドメイン経路に掛からず、従来の解決へ落ちる。
pub fn split_qualified_identifier(input: &str) -> Option<(&str, String)> {
    let trimmed = input.trim();
    let (local, domain) = trimmed.split_once('@')?;
    if local.is_empty() || domain.contains('@') {
        return None;
    }
    let domain = validate_domain(domain).ok()?;
    Some((local, domain))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_case_and_the_trailing_dot() {
        assert_eq!(normalize_domain("  Corp.Example.  "), "corp.example");
        assert_eq!(validate_domain("CORP.EXAMPLE").unwrap(), "corp.example");
    }

    /// 単一ラベルは許し、空ラベル・ハイフン始まり終わり・非 ASCII は弾く。
    #[test]
    fn accepts_plausible_domains_and_rejects_malformed_ones() {
        for ok in ["corp", "corp.example", "a-b.c-d.example", "xn--wgv71a.jp"] {
            assert!(validate_domain(ok).is_ok(), "{ok} は登録できるべき");
        }
        for bad in [
            "",
            ".",
            "corp..example",
            "-corp.example",
            "corp-.example",
            "日本語.jp",
        ] {
            assert!(validate_domain(bad).is_err(), "{bad} は弾くべき");
        }
    }

    /// 長さの上限は列に合わせる（ラベル 63・全体 253）。
    #[test]
    fn rejects_values_that_do_not_fit_the_column() {
        assert!(validate_domain(&"a".repeat(LABEL_MAX_LEN)).is_ok());
        assert!(validate_domain(&"a".repeat(LABEL_MAX_LEN + 1)).is_err());
        let long = std::iter::repeat_n("abcdefgh", 32)
            .collect::<Vec<_>>()
            .join(".");
        assert!(long.len() > DOMAIN_MAX_LEN);
        assert!(validate_domain(&long).is_err());
    }

    /// ドメイン修飾された入力だけが分解でき、ローカル部はそのまま（正規化は種別側が行う）。
    #[test]
    fn splits_only_domain_qualified_input() {
        assert_eq!(
            split_qualified_identifier(" Alice@Corp.Example "),
            Some(("Alice", "corp.example".to_string()))
        );
        assert_eq!(split_qualified_identifier("alice"), None);
        assert_eq!(split_qualified_identifier("@corp.example"), None);
        assert_eq!(split_qualified_identifier("alice@"), None);
        // `@` が複数ある入力でテナントを選ばせない。
        assert_eq!(split_qualified_identifier("a@b@corp.example"), None);
        // ドメインとして読めない値は経路に掛けない（従来の解決へ落ちる）。
        assert_eq!(split_qualified_identifier("alice@-corp.example"), None);
    }
}
