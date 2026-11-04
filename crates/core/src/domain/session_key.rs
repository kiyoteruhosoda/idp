//! SSO セッションを端末の鍵へ結び付ける（DBSC）ときの、鍵と署名の確かめ（task #887。ADR-0074）。
//!
//! Chrome は登録と更新のたびに、TPM の中の鍵で JWT（`typ: dbsc+jwt`）に署名して送ってくる。
//!
//! | | ヘッダー | 中身 |
//! |---|---|---|
//! | 登録 | `alg`（ES256 / RS256）・`typ`・**`jwk`（公開鍵）** | `jti` = challenge |
//! | 更新 | `alg`・`typ`（`jwk` は無い） | `jti` = challenge |
//!
//! 登録では JWT に添えられた公開鍵で署名を確かめ、その鍵を覚える。更新では覚えた鍵で確かめる。
//! challenge がこの SSO セッションのものかは呼び出し側（application）が確かめる。
//!
//! ⚠ 鍵が TPM の中にあるかは、ここからは分からない（DBSC は鍵の証明を運ばない）。

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk, ThumbprintHash};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;

/// RSA の鍵の長さの下限（ビット）。
const MIN_RSA_BITS: usize = 2048;
/// 署名の JWT の長さの上限（バイト）。RSA 4096 の公開鍵を添えても 2KB に満たない。
const MAX_PROOF_LEN: usize = 8 * 1024;

/// 結び付けた公開鍵。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPublicKey {
    /// `ES256` / `RS256`。
    pub algorithm: SessionKeyAlgorithm,
    /// 公開鍵の JWK（JSON）。
    pub jwk_json: String,
    /// RFC 7638 の指紋（SHA-256・base64url）。
    pub thumbprint: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKeyAlgorithm {
    Es256,
    Rs256,
}

impl SessionKeyAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::Rs256 => "RS256",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "ES256" => Some(Self::Es256),
            "RS256" => Some(Self::Rs256),
            _ => None,
        }
    }

    fn jwt(self) -> Algorithm {
        match self {
            Self::Es256 => Algorithm::ES256,
            Self::Rs256 => Algorithm::RS256,
        }
    }

    fn from_jwt(alg: Algorithm) -> Option<Self> {
        match alg {
            Algorithm::ES256 => Some(Self::Es256),
            Algorithm::RS256 => Some(Self::Rs256),
            _ => None,
        }
    }
}

/// SSO セッションと端末の鍵の結び付け（1 つのログイン状態に 1 回だけ）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKeyBinding {
    /// Chrome が更新のときに `Sec-Secure-Session-Id` で送る識別子（32 文字の 16 進）。
    pub session_identifier: String,
    pub key: SessionPublicKey,
    pub bound_at: DateTime<Utc>,
}

/// ログイン状態の結び付けの種類（task #887・#892。ADR-0074・ADR-0075）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionBinding {
    /// 結び付けなし。
    Unbound,
    /// DBSC で端末の鍵に結び付いた（Windows の Chrome）。
    DeviceKey,
    /// 登録した認証アプリで承認して作った（Android の Chrome。持ち主の決定「アプリで認証なら 30 日」）。
    AppApproval,
}

/// ログイン状態の長さを決める。
///
/// 30 日（`bound_ttl`）にするのは、DBSC で結び付き**かつ**そのログイン状態の端末が自分の端末に
/// 登録済みのとき（ADR-0074 §6）と、認証アプリで承認したとき（ADR-0075。承認した鍵そのものが
/// パスキーで登録した端末の鍵なので、ブラウザの端末の登録は問わない）。それ以外は確立したときの
/// 長さ（`absolute_ttl`）。どちらも**作った時刻から**数える。返すのは (idle の期限, absolute の期限)。
pub fn lifetime_for(
    created_at: DateTime<Utc>,
    current_idle: DateTime<Utc>,
    binding: SessionBinding,
    device_registered: bool,
    absolute_ttl: Duration,
    bound_ttl: Duration,
) -> (DateTime<Utc>, DateTime<Utc>) {
    let long = match binding {
        SessionBinding::Unbound => false,
        SessionBinding::DeviceKey => device_registered,
        SessionBinding::AppApproval => true,
    };
    if long && bound_ttl > absolute_ttl {
        let absolute = created_at + bound_ttl;
        // 結び付いたログイン状態は「使わなかった」で切らない（持ち主の決定。idle も同じ長さ）。
        (absolute, absolute)
    } else {
        let absolute = created_at + absolute_ttl;
        (current_idle.min(absolute), absolute)
    }
}

/// 署名を受け付けなかった理由（監査ログに残す。利用者には出さない）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofError {
    /// JWT の形・`typ`・方式が違う、長すぎる。
    Malformed,
    /// 登録なのに公開鍵が無い・使えない鍵（曲線・長さ）。
    UnusableKey,
    /// 署名が合わない。
    BadSignature,
    /// `jti`（challenge）が無い・違う。
    WrongChallenge,
}

impl ProofError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::UnusableKey => "unusable_key",
            Self::BadSignature => "bad_signature",
            Self::WrongChallenge => "wrong_challenge",
        }
    }
}

#[derive(Deserialize)]
struct ProofClaims {
    jti: Option<String>,
}

/// 登録の署名を確かめ、添えられた公開鍵を返す。`challenge` は署名の `jti` と一致しなければならない。
pub fn verify_registration(proof: &str, challenge: &str) -> Result<SessionPublicKey, ProofError> {
    let header = read_header(proof)?;
    let algorithm = SessionKeyAlgorithm::from_jwt(header.alg).ok_or(ProofError::Malformed)?;
    let jwk = header.jwk.ok_or(ProofError::UnusableKey)?;
    let key = usable_key(&jwk, algorithm)?;
    verify_signature(proof, &key, algorithm, challenge)?;
    let thumbprint = jwk
        .thumbprint(ThumbprintHash::SHA256)
        .map_err(|_| ProofError::UnusableKey)?;
    let jwk_json =
        serde_json::to_string(&public_part(&jwk)).map_err(|_| ProofError::UnusableKey)?;
    Ok(SessionPublicKey {
        algorithm,
        jwk_json,
        thumbprint,
    })
}

/// 更新の署名を、結び付けた公開鍵で確かめる。
///
/// 方式が登録と違う・`jwk` が添えられていてそれが登録した鍵と違う、はどちらも [`ProofError::BadSignature`]
/// （別の鍵で作った署名＝持ち出しの疑い）として返す。
pub fn verify_refresh(
    proof: &str,
    bound: &SessionPublicKey,
    challenge: &str,
) -> Result<(), ProofError> {
    let header = read_header(proof)?;
    if SessionKeyAlgorithm::from_jwt(header.alg) != Some(bound.algorithm) {
        return Err(ProofError::BadSignature);
    }
    if let Some(jwk) = &header.jwk {
        if jwk.thumbprint(ThumbprintHash::SHA256).ok().as_deref() != Some(bound.thumbprint.as_str())
        {
            return Err(ProofError::BadSignature);
        }
    }
    let jwk: Jwk = serde_json::from_str(&bound.jwk_json).map_err(|_| ProofError::UnusableKey)?;
    let key = usable_key(&jwk, bound.algorithm)?;
    verify_signature(proof, &key, bound.algorithm, challenge)
}

fn read_header(proof: &str) -> Result<jsonwebtoken::Header, ProofError> {
    if proof.is_empty() || proof.len() > MAX_PROOF_LEN {
        return Err(ProofError::Malformed);
    }
    let header = jsonwebtoken::decode_header(proof).map_err(|_| ProofError::Malformed)?;
    if header.typ.as_deref() != Some(assay_contracts::session_key::PROOF_TYPE) {
        return Err(ProofError::Malformed);
    }
    Ok(header)
}

/// 方式に合った鍵か（ES256 は P-256、RS256 は 2048 ビット以上）。
fn usable_key(jwk: &Jwk, algorithm: SessionKeyAlgorithm) -> Result<DecodingKey, ProofError> {
    match (&jwk.algorithm, algorithm) {
        (AlgorithmParameters::EllipticCurve(ec), SessionKeyAlgorithm::Es256)
            if ec.curve == EllipticCurve::P256 => {}
        (AlgorithmParameters::RSA(rsa), SessionKeyAlgorithm::Rs256)
            if URL_SAFE_NO_PAD
                .decode(&rsa.n)
                .map(|n| n.len() * 8 >= MIN_RSA_BITS)
                .unwrap_or(false) => {}
        _ => return Err(ProofError::UnusableKey),
    }
    DecodingKey::from_jwk(jwk).map_err(|_| ProofError::UnusableKey)
}

fn verify_signature(
    proof: &str,
    key: &DecodingKey,
    algorithm: SessionKeyAlgorithm,
    challenge: &str,
) -> Result<(), ProofError> {
    let mut validation = Validation::new(algorithm.jwt());
    // DBSC の署名に `exp`・`aud` は無い（草案は `jti` だけを定める）。新しさは challenge で測る。
    validation.set_required_spec_claims::<&str>(&[]);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    let claims = jsonwebtoken::decode::<ProofClaims>(proof, key, &validation)
        .map_err(|_| ProofError::BadSignature)?
        .claims;
    match claims.jti {
        Some(jti) if jti == challenge => Ok(()),
        _ => Err(ProofError::WrongChallenge),
    }
}

/// 覚えておく公開鍵（`kid` などの付け足しを落とし、鍵そのものだけにする）。
fn public_part(jwk: &Jwk) -> serde_json::Value {
    match &jwk.algorithm {
        AlgorithmParameters::EllipticCurve(ec) => serde_json::json!({
            "kty": "EC", "crv": "P-256", "x": ec.x, "y": ec.y,
        }),
        AlgorithmParameters::RSA(rsa) => serde_json::json!({
            "kty": "RSA", "n": rsa.n, "e": rsa.e,
        }),
        _ => serde_json::Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::jwt::generate_ec_keypair;
    use jsonwebtoken::{EncodingKey, Header};

    struct DeviceKey {
        private_pem: String,
        jwk: Jwk,
    }

    fn device_key() -> DeviceKey {
        let (private_pem, public_pem) = generate_ec_keypair().unwrap();
        let ours = crate::domain::jwt::ec_public_jwk("k", &public_pem).unwrap();
        let jwk: Jwk = serde_json::from_value(serde_json::json!({
            "kty": "EC", "crv": "P-256", "x": ours.x, "y": ours.y,
        }))
        .unwrap();
        DeviceKey { private_pem, jwk }
    }

    fn proof(key: &DeviceKey, jti: &str, with_jwk: bool, typ: &str) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some(typ.to_string());
        if with_jwk {
            header.jwk = Some(key.jwk.clone());
        }
        jsonwebtoken::encode(
            &header,
            &serde_json::json!({ "jti": jti }),
            &EncodingKey::from_ec_pem(key.private_pem.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn registration_returns_the_key_and_refresh_accepts_the_same_key() {
        let key = device_key();
        let bound = verify_registration(&proof(&key, "c1", true, "dbsc+jwt"), "c1").unwrap();
        assert_eq!(bound.algorithm, SessionKeyAlgorithm::Es256);
        assert_eq!(bound.thumbprint.len(), 43);
        assert!(!bound.jwk_json.contains("\"kid\""));
        assert_eq!(
            verify_refresh(&proof(&key, "c2", false, "dbsc+jwt"), &bound, "c2"),
            Ok(())
        );
    }

    #[test]
    fn registration_needs_the_key_the_type_and_the_challenge() {
        let key = device_key();
        assert_eq!(
            verify_registration(&proof(&key, "c1", false, "dbsc+jwt"), "c1"),
            Err(ProofError::UnusableKey)
        );
        assert_eq!(
            verify_registration(&proof(&key, "c1", true, "JWT"), "c1"),
            Err(ProofError::Malformed)
        );
        assert_eq!(
            verify_registration(&proof(&key, "c1", true, "dbsc+jwt"), "c2"),
            Err(ProofError::WrongChallenge)
        );
        assert_eq!(
            verify_registration("a.b.c", "c1"),
            Err(ProofError::Malformed)
        );
    }

    #[test]
    fn a_registration_signed_by_another_key_than_it_carries_is_rejected() {
        let key = device_key();
        let other = device_key();
        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some("dbsc+jwt".to_string());
        header.jwk = Some(key.jwk.clone());
        let forged = jsonwebtoken::encode(
            &header,
            &serde_json::json!({ "jti": "c1" }),
            &EncodingKey::from_ec_pem(other.private_pem.as_bytes()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            verify_registration(&forged, "c1"),
            Err(ProofError::BadSignature)
        );
    }

    #[test]
    fn a_refresh_signed_by_another_key_is_a_bad_signature() {
        let key = device_key();
        let thief = device_key();
        let bound = verify_registration(&proof(&key, "c1", true, "dbsc+jwt"), "c1").unwrap();
        assert_eq!(
            verify_refresh(&proof(&thief, "c2", false, "dbsc+jwt"), &bound, "c2"),
            Err(ProofError::BadSignature)
        );
        // 別の鍵を添えて差し替えようとしても同じ。
        assert_eq!(
            verify_refresh(&proof(&thief, "c2", true, "dbsc+jwt"), &bound, "c2"),
            Err(ProofError::BadSignature)
        );
        assert_eq!(
            verify_refresh(&proof(&key, "c2", false, "dbsc+jwt"), &bound, "c3"),
            Err(ProofError::WrongChallenge)
        );
    }

    #[test]
    fn only_a_bound_session_on_a_registered_device_gets_the_long_lifetime() {
        use chrono::TimeZone;
        let created = Utc.with_ymd_and_hms(2026, 11, 1, 0, 0, 0).unwrap();
        let idle = created + Duration::hours(30);
        let week = Duration::days(7);
        let month = Duration::days(30);
        use SessionBinding::{AppApproval, DeviceKey, Unbound};
        assert_eq!(
            lifetime_for(created, idle, DeviceKey, true, week, month),
            (created + month, created + month)
        );
        for (binding, registered) in [(DeviceKey, false), (Unbound, true), (Unbound, false)] {
            assert_eq!(
                lifetime_for(created, idle, binding, registered, week, month),
                (idle, created + week),
                "binding={binding:?} registered={registered}"
            );
        }
        // 30 日から 7 日へ戻すとき、idle は absolute を越えない。
        assert_eq!(
            lifetime_for(created, created + month, DeviceKey, false, week, month),
            (created + week, created + week)
        );
        // 組織が長さを短く決めていれば、結び付いても延ばさない。
        assert_eq!(
            lifetime_for(created, idle, DeviceKey, true, month, week),
            (idle, created + month)
        );
    }

    #[test]
    fn an_app_approved_session_gets_the_long_lifetime_without_a_registered_browser() {
        use chrono::TimeZone;
        let created = Utc.with_ymd_and_hms(2026, 11, 1, 0, 0, 0).unwrap();
        let idle = created + Duration::hours(30);
        let week = Duration::days(7);
        let month = Duration::days(30);
        for registered in [true, false] {
            assert_eq!(
                lifetime_for(
                    created,
                    idle,
                    SessionBinding::AppApproval,
                    registered,
                    week,
                    month
                ),
                (created + month, created + month)
            );
        }
    }

    #[test]
    fn algorithms_round_trip() {
        for alg in [SessionKeyAlgorithm::Es256, SessionKeyAlgorithm::Rs256] {
            assert_eq!(SessionKeyAlgorithm::parse(alg.as_str()), Some(alg));
        }
        assert_eq!(SessionKeyAlgorithm::parse("none"), None);
    }
}
