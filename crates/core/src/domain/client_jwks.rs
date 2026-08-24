//! クライアントが登録する検証鍵（JWK Set）の検証・正規化（ADR-0030 決定 3・4）。
//!
//! `private_key_jwt` の client assertion を検証するための公開鍵は、`clients.jwks` に保存した
//! この集合**だけ**を見る。クライアントの `jwks_uri` は取りに行かない —— 認証経路に
//! クライアント側のホスティング障害と、任意 URL への送信（SSRF）を持ち込まないため。
//!
//! 取り込めない鍵は**登録の時点で**失敗させ、`/token` の時刻には持ち込まない。認証の最中に
//! 「保存されているが使えない鍵」が出てくると、失敗の原因がクライアントの署名なのか登録内容なのかを
//! その場で切り分けられない。
//!
//! 鍵ローテーションはこの集合に新旧を並べることで行う（IdP 側に移行期間の概念を持たせない）。

use crate::domain::jwt::{Jwk, Jwks};
use crate::domain::message::MessageKey;

/// 1 つのクライアントが登録できる鍵の本数。ローテーション（新旧の並存）に要るのは 2 本で、
/// 複数の呼び出し元へ別々の鍵を配る運用を見込んでも 8 本あれば足りる。上限を置くのは、
/// 検証時に `kid` 無しの assertion が来たときの走査と、保存する JSON の大きさを抑えるため。
pub const MAX_CLIENT_JWKS_KEYS: usize = 8;

/// 検証済み・正規化済みのクライアント JWK Set（公開鍵のみ）。
///
/// 生成経路は [`parse_registration_jwks`]（管理経路の入力）と [`from_storage`]（DB からの読み戻し）
/// の 2 つだけで、どちらも同じ検証を通る。「検証していない JWK Set」がこの型になることはない。
#[derive(Debug, Clone, PartialEq)]
pub struct ClientJwks {
    keys: Vec<Jwk>,
}

/// 登録された JWK Set が使えない理由。利用者へ返すため翻訳キーを持つ。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientJwksError {
    /// JSON として読めない。
    Malformed,
    /// 鍵が 1 つも無い。
    Empty,
    /// 鍵が多すぎる。
    TooManyKeys,
    /// 対応しない鍵種別（RSA / EC P-256 以外）。
    UnsupportedKeyType,
    /// 必須フィールド（`kid` や鍵成分）が欠けている。
    MissingField,
    /// 秘密鍵成分を含んでいる。
    PrivateKeyMaterial,
    /// 同じ `kid` が 2 つ以上ある。
    DuplicateKid,
}

impl ClientJwksError {
    pub fn message_key(&self) -> MessageKey {
        MessageKey::new(match self {
            Self::Malformed => "api-client-jwks-malformed",
            Self::Empty => "api-client-jwks-empty",
            Self::TooManyKeys => "api-client-jwks-too-many-keys",
            Self::UnsupportedKeyType => "api-client-jwks-unsupported-key-type",
            Self::MissingField => "api-client-jwks-missing-field",
            Self::PrivateKeyMaterial => "api-client-jwks-private-key-material",
            Self::DuplicateKid => "api-client-jwks-duplicate-kid",
        })
    }
}

/// 登録時に受け取る JWK（クライアントが書いたままの形）。
///
/// `use` と `alg` は省く実装が多いため任意で受け、正規化のときに補う。秘密鍵成分
/// （`d` / `p` / `q` / `dp` / `dq` / `qi`）は**受け取らないのではなく明示的に拒否する**ため、
/// フィールドとして持って存在を検査する（黙って捨てると、秘密鍵を貼り付けた登録者に
/// 「登録できた」と伝わってしまう）。
#[derive(Debug, Clone, serde::Deserialize)]
struct SubmittedJwk {
    kty: String,
    kid: Option<String>,
    #[serde(rename = "use")]
    use_: Option<String>,
    // `alg` は受け取っても使わない（未知フィールドとして黙って捨てられる）。検証アルゴリズムは
    // 鍵種別から決めるため、クライアントの自己申告を持ち回らない（ADR-0030 決定 7）。
    n: Option<String>,
    e: Option<String>,
    crv: Option<String>,
    x: Option<String>,
    y: Option<String>,
    d: Option<String>,
    p: Option<String>,
    q: Option<String>,
    dp: Option<String>,
    dq: Option<String>,
    qi: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct SubmittedJwks {
    keys: Vec<SubmittedJwk>,
}

impl SubmittedJwk {
    fn has_private_material(&self) -> bool {
        self.d.is_some()
            || self.p.is_some()
            || self.q.is_some()
            || self.dp.is_some()
            || self.dq.is_some()
            || self.qi.is_some()
    }

    /// 公開鍵成分だけを持つ [`Jwk`] へ正規化する。`use` は `sig`、`alg` は鍵種別から補う。
    fn normalize(self) -> Result<Jwk, ClientJwksError> {
        if self.has_private_material() {
            return Err(ClientJwksError::PrivateKeyMaterial);
        }
        // `kid` は必須。ローテーション中に複数の鍵が並ぶとき、assertion がどれで署名されたかを
        // 決められるのは `kid` だけである（無い鍵が混じると総当たりになる）。
        let kid = self.kid.filter(|k| !k.is_empty());
        let Some(kid) = kid else {
            return Err(ClientJwksError::MissingField);
        };
        match self.kty.as_str() {
            "RSA" => {
                let (Some(n), Some(e)) = (
                    self.n.filter(|v| !v.is_empty()),
                    self.e.filter(|v| !v.is_empty()),
                ) else {
                    return Err(ClientJwksError::MissingField);
                };
                Ok(Jwk {
                    kty: "RSA".to_string(),
                    use_: self.use_.unwrap_or_else(|| "sig".to_string()),
                    kid,
                    // 本 IdP が検証に使う RSA アルゴリズムは RS256 のみ（ADR-0030 決定 7）。
                    // クライアントが別の `alg` を書いていても、検証は登録済み鍵種別から決める。
                    alg: "RS256".to_string(),
                    n: Some(n),
                    e: Some(e),
                    crv: None,
                    x: None,
                    y: None,
                })
            }
            "EC" => {
                // 対応する曲線は P-256 のみ（署名鍵の `SigningAlgorithm` と揃える）。
                if self.crv.as_deref() != Some("P-256") {
                    return Err(ClientJwksError::UnsupportedKeyType);
                }
                let (Some(x), Some(y)) = (
                    self.x.filter(|v| !v.is_empty()),
                    self.y.filter(|v| !v.is_empty()),
                ) else {
                    return Err(ClientJwksError::MissingField);
                };
                Ok(Jwk {
                    kty: "EC".to_string(),
                    use_: self.use_.unwrap_or_else(|| "sig".to_string()),
                    kid,
                    alg: "ES256".to_string(),
                    n: None,
                    e: None,
                    crv: Some("P-256".to_string()),
                    x: Some(x),
                    y: Some(y),
                })
            }
            _ => Err(ClientJwksError::UnsupportedKeyType),
        }
    }
}

/// 管理経路が受け取った JWK Set（JSON 文字列）を検証・正規化する。
pub fn parse_registration_jwks(raw: &str) -> Result<ClientJwks, ClientJwksError> {
    let submitted: SubmittedJwks =
        serde_json::from_str(raw).map_err(|_| ClientJwksError::Malformed)?;
    build(submitted)
}

fn build(submitted: SubmittedJwks) -> Result<ClientJwks, ClientJwksError> {
    if submitted.keys.is_empty() {
        return Err(ClientJwksError::Empty);
    }
    if submitted.keys.len() > MAX_CLIENT_JWKS_KEYS {
        return Err(ClientJwksError::TooManyKeys);
    }
    let keys = submitted
        .keys
        .into_iter()
        .map(SubmittedJwk::normalize)
        .collect::<Result<Vec<_>, _>>()?;

    // `kid` が重複すると「どちらの鍵で検証したか」がリクエストからは決まらない。失効させたはずの
    // 鍵と同じ `kid` で新しい鍵を足す運用を、静かに成立させないため登録時に弾く。
    for (i, key) in keys.iter().enumerate() {
        if keys[i + 1..].iter().any(|other| other.kid == key.kid) {
            return Err(ClientJwksError::DuplicateKid);
        }
    }
    Ok(ClientJwks { keys })
}

impl ClientJwks {
    /// DB に保存された JSON から読み戻す。保存時と同じ検証を通す。
    ///
    /// 保存済みの値を無検査で信じないのは、DB を直接編集された行・古い形式で保存された行が
    /// 検証経路へ素通りしないようにするため（fail-closed）。
    pub fn from_storage(raw: &str) -> Result<Self, ClientJwksError> {
        parse_registration_jwks(raw)
    }

    /// DB へ保存する JSON 文字列（正規化済み）。
    pub fn to_storage_json(&self) -> String {
        // 正規化済みの `Jwk` だけを含むため、シリアライズは失敗しない。
        serde_json::to_string(&Jwks {
            keys: self.keys.clone(),
        })
        .unwrap_or_else(|_| "{\"keys\":[]}".to_string())
    }

    pub fn keys(&self) -> &[Jwk] {
        &self.keys
    }

    /// assertion のヘッダ `kid` に対応する鍵を選ぶ。
    ///
    /// `kid` の無い assertion は、登録鍵が 1 本のときだけその鍵で検証する。複数あるなら
    /// 選びようがないので `None`（＝検証失敗）にする —— 総当たりで通してしまうと、
    /// ローテーションで並べた古い鍵が「まだ有効」であることを黙って隠す。
    pub fn select(&self, kid: Option<&str>) -> Option<&Jwk> {
        match kid {
            Some(kid) => self.keys.iter().find(|k| k.kid == kid),
            None if self.keys.len() == 1 => self.keys.first(),
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RSA_N: &str = "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl\
                         UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre\
                         cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_\
                         7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBI\
                         Y2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU\
                         7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw";

    fn rsa_jwks(kid: &str) -> String {
        format!(r#"{{"keys":[{{"kty":"RSA","kid":"{kid}","n":"{RSA_N}","e":"AQAB"}}]}}"#)
    }

    #[test]
    fn normalizes_a_minimal_rsa_key() {
        let jwks = parse_registration_jwks(&rsa_jwks("k1")).unwrap();
        let key = &jwks.keys()[0];
        assert_eq!(key.kid, "k1");
        // `use` と `alg` は省かれていても補う。
        assert_eq!(key.use_, "sig");
        assert_eq!(key.alg, "RS256");
        assert_eq!(key.e.as_deref(), Some("AQAB"));
    }

    #[test]
    fn a_private_key_is_rejected_rather_than_silently_stripped() {
        let raw = format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"k1","n":"{RSA_N}","e":"AQAB","d":"secret"}}]}}"#
        );
        assert_eq!(
            parse_registration_jwks(&raw),
            Err(ClientJwksError::PrivateKeyMaterial)
        );
    }

    #[test]
    fn keys_need_a_kid_and_their_components() {
        let no_kid = format!(r#"{{"keys":[{{"kty":"RSA","n":"{RSA_N}","e":"AQAB"}}]}}"#);
        assert_eq!(
            parse_registration_jwks(&no_kid),
            Err(ClientJwksError::MissingField)
        );
        assert_eq!(
            parse_registration_jwks(r#"{"keys":[{"kty":"RSA","kid":"k1","e":"AQAB"}]}"#),
            Err(ClientJwksError::MissingField)
        );
    }

    #[test]
    fn unsupported_key_types_and_curves_are_rejected() {
        assert_eq!(
            parse_registration_jwks(r#"{"keys":[{"kty":"oct","kid":"k1","k":"c2VjcmV0"}]}"#),
            Err(ClientJwksError::UnsupportedKeyType)
        );
        assert_eq!(
            parse_registration_jwks(
                r#"{"keys":[{"kty":"EC","kid":"k1","crv":"P-384","x":"a","y":"b"}]}"#
            ),
            Err(ClientJwksError::UnsupportedKeyType)
        );
    }

    #[test]
    fn empty_malformed_and_oversized_sets_are_rejected() {
        assert_eq!(
            parse_registration_jwks(r#"{"keys":[]}"#),
            Err(ClientJwksError::Empty)
        );
        assert_eq!(
            parse_registration_jwks("not json"),
            Err(ClientJwksError::Malformed)
        );
        let many: Vec<String> = (0..=MAX_CLIENT_JWKS_KEYS)
            .map(|i| format!(r#"{{"kty":"RSA","kid":"k{i}","n":"{RSA_N}","e":"AQAB"}}"#))
            .collect();
        assert_eq!(
            parse_registration_jwks(&format!(r#"{{"keys":[{}]}}"#, many.join(","))),
            Err(ClientJwksError::TooManyKeys)
        );
    }

    #[test]
    fn duplicate_kids_are_rejected() {
        let raw = format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"k1","n":"{RSA_N}","e":"AQAB"}},
                         {{"kty":"RSA","kid":"k1","n":"{RSA_N}","e":"AQAB"}}]}}"#
        );
        assert_eq!(
            parse_registration_jwks(&raw),
            Err(ClientJwksError::DuplicateKid)
        );
    }

    #[test]
    fn selecting_without_a_kid_works_only_when_one_key_is_registered() {
        let single = parse_registration_jwks(&rsa_jwks("k1")).unwrap();
        assert_eq!(single.select(None).unwrap().kid, "k1");
        assert_eq!(single.select(Some("k1")).unwrap().kid, "k1");
        assert!(single.select(Some("other")).is_none());

        let raw = format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"k1","n":"{RSA_N}","e":"AQAB"}},
                         {{"kty":"RSA","kid":"k2","n":"{RSA_N}","e":"AQAB"}}]}}"#
        );
        let pair = parse_registration_jwks(&raw).unwrap();
        assert!(pair.select(None).is_none());
        assert_eq!(pair.select(Some("k2")).unwrap().kid, "k2");
    }

    #[test]
    fn storage_round_trip_keeps_the_normalized_form() {
        let jwks = parse_registration_jwks(&rsa_jwks("k1")).unwrap();
        let restored = ClientJwks::from_storage(&jwks.to_storage_json()).unwrap();
        assert_eq!(restored, jwks);
    }
}
