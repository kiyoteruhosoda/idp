//! 保護リソース（protected resource）——**トークンの宛名**（ADR-0042。RFC 8707）。
//!
//! 1 行が「この認可サーバが `aud` に載せてよい名前」を表す。`client_credentials` で
//! `resource=<この名前>` を要求されたとき、発行するトークンの `aud` がこの値になる。
//!
//! # 宛名であって行き先ではない
//!
//! この URI は**誰も叩かない**。認可サーバも接続しないし、リソースサーバがここで待ち受けている
//! 必要もない（実際 blobshare は公開ホスト名ではなく LAN の別ポートで動く）。名前が URI の形を
//! しているのは、組織をまたいでも衝突しない書き方だからで、`api://blobshare` のように解決できない
//! 形でも構わない。`redirect_uri` と紛らわしいが、あちらはブラウザを実際に送り込む**場所**である。
//!
//! # 語彙を持たない
//!
//! 「そこで何をしてよいか」（`page:write` のような業務権限）はここに登録しない。リソースサーバが
//! `client_id` で決める（ADR-0033）。宛名だけを載せるのは、**宛名は変わらないが権限モデルは
//! アプリを直すたびに変わる**ためで、両方を持つと idp がアプリの改修に追随する側になる。

use crate::domain::message::MessageKey;
use crate::domain::tenant::TenantId;
use crate::domain::values::ResourceStatus;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// `resources.resource_uri` のカラム上限。
pub const RESOURCE_URI_MAX_LEN: usize = 255;
/// `resources.display_name` のカラム上限。
pub const DISPLAY_NAME_MAX_LEN: usize = 255;

/// 登録済みの宛名。
#[derive(Debug, Clone)]
pub struct ProtectedResource {
    pub id: Uuid,
    /// この宛名を持つテナント。宛名の一意性はテナント内で閉じる（ADR-0009 §1）。
    pub tenant_id: TenantId,
    /// `aud` に入る値そのもの。照合は**完全一致**（`redirect_uri` と同じ方針）。
    pub resource_uri: String,
    pub display_name: String,
    pub status: ResourceStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ProtectedResource {
    /// 新しいトークンの宛先に使えるか。`DISABLED` は登録を残したまま発行だけを止める。
    pub fn is_active(&self) -> bool {
        self.status == ResourceStatus::Active
    }
}

/// 登録できる宛名かを検証し、格納する値を返す。
///
/// **正規化しない。** `url` で解析した結果（`https://example.com` → `https://example.com/`）を
/// 保存すると、登録した文字列と `aud` に載る文字列が食い違い、リソースサーバ側の完全一致が外れる。
/// 解析は「絶対 URI か」「fragment が無いか」を見るためだけに使い、保存するのは入力そのもの
/// （前後の空白だけ落とす）。
///
/// エラーは管理者に返るが、他の管理 API と揃えて翻訳キーで返す（訳出は Presentation 層）。
pub fn validate_resource_uri(raw: &str) -> Result<String, MessageKey> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(MessageKey::new("api-resource-uri-required"));
    }
    if value.len() > RESOURCE_URI_MAX_LEN {
        return Err(MessageKey::with_value(
            "api-resource-uri-too-long",
            RESOURCE_URI_MAX_LEN.to_string(),
        ));
    }
    // 相対 URI は `Url::parse` が弾く（RFC 8707 §2 は絶対 URI を要求する）。
    let parsed = url::Url::parse(value).map_err(|_| MessageKey::new("api-resource-uri-invalid"))?;
    // fragment は RFC 8707 §2 が明示的に禁じている。`#` 以降はサーバへ送られないため、
    // 「見えない差」で 2 つの宛名を区別できてしまう。
    if parsed.fragment().is_some() {
        return Err(MessageKey::new("api-resource-uri-fragment"));
    }
    Ok(value.to_string())
}

/// 画面に出す名前を検証し、格納する値を返す。
pub fn validate_display_name(raw: &str) -> Result<String, MessageKey> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(MessageKey::new("api-resource-display-name-required"));
    }
    if value.chars().count() > DISPLAY_NAME_MAX_LEN {
        return Err(MessageKey::with_value(
            "api-resource-display-name-too-long",
            DISPLAY_NAME_MAX_LEN.to_string(),
        ));
    }
    Ok(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_name_that_does_not_resolve() {
        // 叩かれない値なので、実在しないスキームでも構わない。
        assert_eq!(
            validate_resource_uri("api://blobshare").unwrap(),
            "api://blobshare"
        );
    }

    #[test]
    fn keeps_the_registered_string_as_it_is() {
        // `Url` の正規化（末尾スラッシュの補完）を保存側へ持ち込まない。
        assert_eq!(
            validate_resource_uri("  https://wiki.nolumia.com  ").unwrap(),
            "https://wiki.nolumia.com"
        );
    }

    #[test]
    fn rejects_relative_and_fragment_and_empty() {
        assert!(validate_resource_uri("/api/machine").is_err());
        assert!(validate_resource_uri("https://wiki.nolumia.com/#x").is_err());
        assert!(validate_resource_uri("   ").is_err());
    }

    #[test]
    fn rejects_a_name_longer_than_the_column() {
        let long = format!("https://example.com/{}", "a".repeat(RESOURCE_URI_MAX_LEN));
        assert!(validate_resource_uri(&long).is_err());
    }
}
