//! `private_key_jwt` の client assertion の検証（ADR-0030 決定 2・5・6・7。RFC 7523・OIDC Core §9）。
//!
//! クライアントは自分の秘密鍵で署名した JWT を提示し、IdP は登録済みの公開鍵
//! （[`crate::domain::client_jwks::ClientJwks`]）で検証する。ここが担うのは**署名とクレームの検証**
//! までで、`jti` の記録（再生防止の永続化）は application 層が行う —— 記録は DB を要し、
//! 「検証は通ったが記録に失敗した」ときの扱いはトランザクション境界の問題だからである。
//!
//! 検証に使うアルゴリズムは**登録済み鍵の種別**から決める。assertion ヘッダの `alg` を信じて
//! 検証方式を選ぶことはしない（`alg` 混同攻撃を成立させないため）。ヘッダが `none` や HMAC 系を
//! 名乗っても、鍵と一致しないので検証は通らない。

use crate::domain::client_jwks::ClientJwks;
use crate::domain::jwt::decoding_key_from_jwk;
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{Algorithm, Validation};
use serde::Deserialize;

/// `client_assertion_type` の唯一の許可値（RFC 7523 §2.2）。
pub const JWT_BEARER_ASSERTION_TYPE: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// assertion の有効期間の上限（ADR-0030 決定 5）。
///
/// `exp` がこれより先を指す assertion は拒否する。再生の窓を短く保つためであると同時に、
/// `jti` を記録しておく期間の上限でもある（記録を `exp` まで持てば再生を防げる）。
pub const MAX_ASSERTION_LIFETIME: Duration = Duration::minutes(5);

/// 時計ずれの許容幅。クライアントと IdP の時刻が完全に一致することは期待できない。
const CLOCK_SKEW_LEEWAY: Duration = Duration::seconds(60);

/// 検証を通った assertion から、再生防止に要る値だけを取り出したもの。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedClientAssertion {
    /// `jti` クレーム。`(tenant_id, client_id, jti)` で一意に記録する。
    pub jti: String,
    /// `exp` クレーム。この時刻まで `jti` を再受理しない。
    pub expires_at: DateTime<Utc>,
}

/// assertion を受け付けられない理由。文字列は監査ログの `reason` にそのまま載せる
/// （クライアントへは一律 `invalid_client` を返し、どれで落ちたかは明かさない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAssertionFailure {
    /// `client_assertion_type` が `jwt-bearer` ではない。
    UnsupportedAssertionType,
    /// JWT として読めない（ヘッダ・区切りの形式不正）。
    Malformed,
    /// ヘッダの `kid` に対応する鍵が登録されていない（`kid` 無しで鍵が複数ある場合を含む）。
    UnknownKey,
    /// 署名検証に失敗した。`exp` 切れ・`aud` 不一致もここではなく個別の理由で返す。
    InvalidSignature,
    /// 期限切れ（`exp` が過去）。
    Expired,
    /// `exp` が遠すぎる（[`MAX_ASSERTION_LIFETIME`] 超過）。
    LifetimeTooLong,
    /// `aud` がこの IdP のテナントを指していない。
    AudienceMismatch,
    /// `iss` または `sub` がクライアント自身ではない。
    SubjectMismatch,
    /// `jti` が無い（本 IdP では必須）。
    MissingJti,
}

impl ClientAssertionFailure {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedAssertionType => "unsupported_assertion_type",
            Self::Malformed => "malformed_client_assertion",
            Self::UnknownKey => "unknown_assertion_key",
            Self::InvalidSignature => "invalid_assertion_signature",
            Self::Expired => "expired_client_assertion",
            Self::LifetimeTooLong => "assertion_lifetime_too_long",
            Self::AudienceMismatch => "assertion_audience_mismatch",
            Self::SubjectMismatch => "assertion_subject_mismatch",
            Self::MissingJti => "missing_assertion_jti",
        }
    }
}

/// `aud` は文字列 1 つでも配列でも書ける（RFC 7519 §4.1.3）。
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn contains(&self, value: &str) -> bool {
        match self {
            Self::One(one) => one == value,
            Self::Many(many) => many.iter().any(|a| a == value),
        }
    }
}

#[derive(Debug, Deserialize)]
struct AssertionClaims {
    iss: String,
    sub: String,
    aud: Audience,
    exp: i64,
    jti: Option<String>,
}

/// 署名を検証せずに `sub`（＝クライアント自身）だけを覗く。
///
/// クライアント認証の前段で「どのクライアントの登録鍵で検証するか」を決めるためだけに使う。
/// RFC 7521 §4.2 は assertion を使う場合の `client_id` の省略を認めており、その場合ここが
/// 唯一の手がかりになる。値が偽られていても、選ばれた鍵で署名が検証できなければ落ちるだけなので
/// 認証の判断には使わない —— **検証後に `iss`/`sub` が client_id と一致することを必ず確かめる**
/// （[`verify_client_assertion`] が行う）。
pub fn unverified_subject(assertion: &str) -> Option<String> {
    // 署名検証をしないため `jsonwebtoken` の decode は通せない。ペイロード部だけを自前で開く。
    let mut parts = assertion.split('.');
    let (_header, payload) = (parts.next()?, parts.next()?);
    // 署名部が無いものは JWT ではない（`header.payload` だけを渡して素通りさせない）。
    parts.next()?;
    let decoded = base64url_decode(payload)?;
    let claims: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    claims
        .get("sub")?
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn base64url_decode(value: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.decode(value).ok()
}

/// assertion を検証する。
///
/// `accepted_audiences` にはテナント issuer とトークンエンドポイント URL の両方を渡す
/// （ADR-0030 決定 6。クライアント実装によってどちらを入れるかが分かれるため）。どちらも
/// テナントを含む値なので、A テナント宛の assertion を B テナントへ持ち込むことはできない。
pub fn verify_client_assertion(
    assertion_type: Option<&str>,
    assertion: &str,
    client_id: &str,
    jwks: &ClientJwks,
    accepted_audiences: &[String],
    now: DateTime<Utc>,
) -> Result<VerifiedClientAssertion, ClientAssertionFailure> {
    if assertion_type != Some(JWT_BEARER_ASSERTION_TYPE) {
        return Err(ClientAssertionFailure::UnsupportedAssertionType);
    }

    let header =
        jsonwebtoken::decode_header(assertion).map_err(|_| ClientAssertionFailure::Malformed)?;
    let jwk = jwks
        .select(header.kid.as_deref())
        .ok_or(ClientAssertionFailure::UnknownKey)?;
    let key = decoding_key_from_jwk(jwk).map_err(|_| ClientAssertionFailure::UnknownKey)?;
    // 検証アルゴリズムは登録済み鍵の種別が決める（ヘッダの `alg` は見ない）。
    let algorithm = match jwk.alg.as_str() {
        "RS256" => Algorithm::RS256,
        "ES256" => Algorithm::ES256,
        // `ClientJwks` は RS256 / ES256 しか作らないため到達しないが、fail-closed にしておく。
        _ => return Err(ClientAssertionFailure::UnknownKey),
    };

    let mut validation = Validation::new(algorithm);
    // クレームの検査は**すべて自前で**行い、`jsonwebtoken` には署名検証だけをさせる。
    // `exp` の検査を任せると内部でシステム時刻を読むため、注入した `now`（`Clock`）が効かず、
    // テストで時刻を固定できない（`CLAUDE.md`「テスト」）。`aud`・`iss` も、候補集合のいずれかとの
    // 一致・「クライアント自身であること」という条件なので単純一致では書けない。
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.set_required_spec_claims(&["exp", "iss", "sub", "aud"]);

    let token = jsonwebtoken::decode::<AssertionClaims>(assertion, &key, &validation).map_err(
        |e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                ClientAssertionFailure::InvalidSignature
            }
            jsonwebtoken::errors::ErrorKind::MissingRequiredClaim(_)
            | jsonwebtoken::errors::ErrorKind::Json(_) => ClientAssertionFailure::Malformed,
            _ => ClientAssertionFailure::InvalidSignature,
        },
    )?;
    let claims = token.claims;

    // RFC 7523 §3: `iss` と `sub` はどちらもクライアント自身でなければならない。
    if claims.iss != client_id || claims.sub != client_id {
        return Err(ClientAssertionFailure::SubjectMismatch);
    }
    if !accepted_audiences.iter().any(|a| claims.aud.contains(a)) {
        return Err(ClientAssertionFailure::AudienceMismatch);
    }

    let expires_at =
        DateTime::from_timestamp(claims.exp, 0).ok_or(ClientAssertionFailure::Malformed)?;
    if expires_at + CLOCK_SKEW_LEEWAY < now {
        return Err(ClientAssertionFailure::Expired);
    }
    if expires_at - now > MAX_ASSERTION_LIFETIME {
        return Err(ClientAssertionFailure::LifetimeTooLong);
    }

    let jti = claims
        .jti
        .filter(|j| !j.is_empty())
        .ok_or(ClientAssertionFailure::MissingJti)?;

    Ok(VerifiedClientAssertion { jti, expires_at })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::client_jwks::parse_registration_jwks;
    use crate::domain::jwt::{generate_ec_keypair, generate_rsa_keypair, public_jwk, sign};
    use serde::Serialize;

    const CLIENT_ID: &str = "machine-client";
    const AUDIENCE: &str = "https://idp.example.com/019700000000700080000000000000001";

    #[derive(Serialize)]
    struct TestClaims {
        iss: String,
        sub: String,
        aud: String,
        exp: i64,
        jti: Option<String>,
    }

    struct Fixture {
        private_pem: String,
        algorithm: &'static str,
        jwks: ClientJwks,
    }

    fn fixture(algorithm: &'static str) -> Fixture {
        let (private_pem, public_pem) = match algorithm {
            "RS256" => generate_rsa_keypair().unwrap(),
            _ => generate_ec_keypair().unwrap(),
        };
        let jwk = public_jwk("k1", algorithm, &public_pem).unwrap();
        let raw = serde_json::to_string(&crate::domain::jwt::Jwks { keys: vec![jwk] }).unwrap();
        Fixture {
            private_pem,
            algorithm,
            jwks: parse_registration_jwks(&raw).unwrap(),
        }
    }

    fn assertion(f: &Fixture, claims: TestClaims) -> String {
        sign(&f.private_pem, "k1", "JWT", f.algorithm, &claims).unwrap()
    }

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000, 0).unwrap()
    }

    fn valid_claims() -> TestClaims {
        TestClaims {
            iss: CLIENT_ID.to_string(),
            sub: CLIENT_ID.to_string(),
            aud: AUDIENCE.to_string(),
            exp: now().timestamp() + 120,
            jti: Some("jti-1".to_string()),
        }
    }

    fn verify(f: &Fixture, token: &str) -> Result<VerifiedClientAssertion, ClientAssertionFailure> {
        verify_client_assertion(
            Some(JWT_BEARER_ASSERTION_TYPE),
            token,
            CLIENT_ID,
            &f.jwks,
            &[AUDIENCE.to_string()],
            now(),
        )
    }

    #[test]
    fn accepts_a_well_formed_assertion_for_both_algorithms() {
        for algorithm in ["RS256", "ES256"] {
            let f = fixture(algorithm);
            let verified = verify(&f, &assertion(&f, valid_claims())).unwrap();
            assert_eq!(verified.jti, "jti-1");
            assert_eq!(verified.expires_at.timestamp(), now().timestamp() + 120);
        }
    }

    #[test]
    fn the_assertion_type_must_be_jwt_bearer() {
        let f = fixture("RS256");
        let token = assertion(&f, valid_claims());
        assert_eq!(
            verify_client_assertion(
                None,
                &token,
                CLIENT_ID,
                &f.jwks,
                &[AUDIENCE.to_string()],
                now()
            ),
            Err(ClientAssertionFailure::UnsupportedAssertionType)
        );
        assert_eq!(
            verify_client_assertion(
                Some("urn:example:other"),
                &token,
                CLIENT_ID,
                &f.jwks,
                &[AUDIENCE.to_string()],
                now()
            ),
            Err(ClientAssertionFailure::UnsupportedAssertionType)
        );
    }

    /// 別の鍵で署名した assertion は通らない（＝登録鍵を差し替えれば失効する）。
    #[test]
    fn a_signature_from_another_key_is_rejected() {
        let registered = fixture("RS256");
        let attacker = fixture("RS256");
        let token = assertion(&attacker, valid_claims());
        assert_eq!(
            verify(&registered, &token),
            Err(ClientAssertionFailure::InvalidSignature)
        );
    }

    #[test]
    fn an_unregistered_kid_is_rejected() {
        let f = fixture("RS256");
        let token = sign(
            &f.private_pem,
            "other-kid",
            "JWT",
            f.algorithm,
            &valid_claims(),
        )
        .unwrap();
        assert_eq!(verify(&f, &token), Err(ClientAssertionFailure::UnknownKey));
    }

    #[test]
    fn iss_and_sub_must_both_be_the_client_itself() {
        let f = fixture("RS256");
        let other_iss = assertion(
            &f,
            TestClaims {
                iss: "someone-else".to_string(),
                ..valid_claims()
            },
        );
        assert_eq!(
            verify(&f, &other_iss),
            Err(ClientAssertionFailure::SubjectMismatch)
        );

        let other_sub = assertion(
            &f,
            TestClaims {
                sub: "someone-else".to_string(),
                ..valid_claims()
            },
        );
        assert_eq!(
            verify(&f, &other_sub),
            Err(ClientAssertionFailure::SubjectMismatch)
        );
    }

    /// 別の宛先向けに署名させた JWT を本 IdP の `/token` へ転送しても通らない。
    #[test]
    fn an_assertion_for_another_audience_is_rejected() {
        let f = fixture("RS256");
        let token = assertion(
            &f,
            TestClaims {
                aud: "https://other.example.com/token".to_string(),
                ..valid_claims()
            },
        );
        assert_eq!(
            verify(&f, &token),
            Err(ClientAssertionFailure::AudienceMismatch)
        );
    }

    /// 別テナントの issuer 宛の assertion は、こちらのテナントでは通らない（ADR-0030 決定 6）。
    #[test]
    fn an_assertion_for_another_tenant_is_rejected() {
        let f = fixture("RS256");
        let token = assertion(
            &f,
            TestClaims {
                aud: "https://idp.example.com/019700000000700080000000000000002".to_string(),
                ..valid_claims()
            },
        );
        assert_eq!(
            verify(&f, &token),
            Err(ClientAssertionFailure::AudienceMismatch)
        );
    }

    /// 期限判定は**注入した `now`** で行う（システム時刻ではない）。固定した `now()` は実時刻より
    /// 先を指しているので、`jsonwebtoken` の `exp` 検査に任せているとこの assertion は通ってしまう。
    #[test]
    fn expired_assertions_are_rejected_against_the_injected_clock() {
        let f = fixture("RS256");
        let token = assertion(
            &f,
            TestClaims {
                // 時計ずれの許容幅（60 秒）より確実に過去へ置く。
                exp: now().timestamp() - 300,
                ..valid_claims()
            },
        );
        assert_eq!(verify(&f, &token), Err(ClientAssertionFailure::Expired));
    }

    #[test]
    fn assertions_valid_for_longer_than_the_cap_are_rejected() {
        let f = fixture("RS256");
        let token = assertion(
            &f,
            TestClaims {
                exp: now().timestamp() + MAX_ASSERTION_LIFETIME.num_seconds() + 60,
                ..valid_claims()
            },
        );
        assert_eq!(
            verify(&f, &token),
            Err(ClientAssertionFailure::LifetimeTooLong)
        );
    }

    #[test]
    fn a_jti_is_required() {
        let f = fixture("RS256");
        let token = assertion(
            &f,
            TestClaims {
                jti: None,
                ..valid_claims()
            },
        );
        assert_eq!(verify(&f, &token), Err(ClientAssertionFailure::MissingJti));

        let empty = assertion(
            &f,
            TestClaims {
                jti: Some(String::new()),
                ..valid_claims()
            },
        );
        assert_eq!(verify(&f, &empty), Err(ClientAssertionFailure::MissingJti));
    }

    #[test]
    fn the_unverified_subject_is_readable_without_the_key() {
        let f = fixture("RS256");
        let token = assertion(&f, valid_claims());
        assert_eq!(unverified_subject(&token).as_deref(), Some(CLIENT_ID));
        // JWT の形をしていないものからは何も取れない。
        assert_eq!(unverified_subject("not-a-jwt"), None);
        assert_eq!(unverified_subject("a.b"), None);
    }

    #[test]
    fn garbage_is_rejected_as_malformed() {
        let f = fixture("RS256");
        assert_eq!(
            verify(&f, "not-a-jwt"),
            Err(ClientAssertionFailure::Malformed)
        );
    }

    /// `aud` は配列でも書ける（RFC 7519 §4.1.3）。候補のいずれかを含めば通す。
    #[test]
    fn an_audience_array_containing_the_tenant_is_accepted() {
        let f = fixture("RS256");
        #[derive(Serialize)]
        struct ArrayAudClaims {
            iss: String,
            sub: String,
            aud: Vec<String>,
            exp: i64,
            jti: String,
        }
        let token = sign(
            &f.private_pem,
            "k1",
            "JWT",
            f.algorithm,
            &ArrayAudClaims {
                iss: CLIENT_ID.to_string(),
                sub: CLIENT_ID.to_string(),
                aud: vec![
                    "https://other.example.com".to_string(),
                    AUDIENCE.to_string(),
                ],
                exp: now().timestamp() + 120,
                jti: "jti-1".to_string(),
            },
        )
        .unwrap();
        assert_eq!(verify(&f, &token).unwrap().jti, "jti-1");
    }
}
