//! 試験データは `scripts/key-attestation-fixtures.py` で作った（自前の根。KeyDescription は KeyMint の定義どおり）。

use super::*;
use base64::Engine;
use sha2::{Digest, Sha256};

const CHALLENGE: &[u8] = b"assay-test-challenge-0123456789ab";
const ROOT: &str = include_str!("fixtures/root.pem");
const ROOT_P384: &str = include_str!("fixtures/root-p384.pem");

fn chain(pem: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut body = String::new();
    for line in pem.lines() {
        match line.trim() {
            "-----BEGIN CERTIFICATE-----" => body.clear(),
            "-----END CERTIFICATE-----" => out.push(
                base64::engine::general_purpose::STANDARD
                    .decode(body.as_bytes())
                    .unwrap(),
            ),
            other => body.push_str(other),
        }
    }
    out
}

fn signer_digest() -> [u8; 32] {
    let digest = Sha256::digest(b"authapp-test-signer");
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn policy() -> AttestationPolicy {
    let mut roots = root_keys_from_pem(ROOT).unwrap();
    roots.extend(root_keys_from_pem(ROOT_P384).unwrap());
    AttestationPolicy {
        trusted_root_keys: roots,
        package_name: "com.nolumia.auth".to_string(),
        signing_cert_digests: vec![signer_digest()],
        allow_software: false,
    }
}

fn verify(name: &str, policy: &AttestationPolicy) -> Result<AttestedKey, AttestationRejection> {
    let pem = match name {
        "good" => include_str!("fixtures/good.pem"),
        "good-p384-root" => include_str!("fixtures/good-p384-root.pem"),
        "software" => include_str!("fixtures/software.pem"),
        "no-auth-required" => include_str!("fixtures/no-auth-required.pem"),
        "auth-timeout" => include_str!("fixtures/auth-timeout.pem"),
        "password-allowed" => include_str!("fixtures/password-allowed.pem"),
        "imported-key" => include_str!("fixtures/imported-key.pem"),
        "rsa-key-claimed" => include_str!("fixtures/rsa-key-claimed.pem"),
        "wrong-package" => include_str!("fixtures/wrong-package.pem"),
        "wrong-signer" => include_str!("fixtures/wrong-signer.pem"),
        "unlocked" => include_str!("fixtures/unlocked.pem"),
        "intermediate-not-ca" => include_str!("fixtures/intermediate-not-ca.pem"),
        "forged-below-attested-key" => include_str!("fixtures/forged-below-attested-key.pem"),
        other => panic!("unknown fixture {other}"),
    };
    verify_attestation(&chain(pem), CHALLENGE, policy)
}

#[test]
fn accepts_a_tee_key_under_an_rsa_root() {
    let key = verify("good", &policy()).unwrap();
    assert_eq!(key.security_level, KeySecurityLevel::TrustedEnvironment);
    let leaf = chain(include_str!("fixtures/good.pem")).remove(0);
    assert!(leaf
        .windows(key.public_key_spki.len())
        .any(|w| w == key.public_key_spki.as_slice()));
}

#[test]
fn accepts_a_strongbox_key_under_a_p384_root() {
    let key = verify("good-p384-root", &policy()).unwrap();
    assert_eq!(key.security_level, KeySecurityLevel::StrongBox);
}

#[test]
fn refuses_a_chain_that_ends_at_an_unknown_root() {
    let only_p384 = AttestationPolicy {
        trusted_root_keys: root_keys_from_pem(ROOT_P384).unwrap(),
        ..policy()
    };
    assert_eq!(
        verify("good", &only_p384),
        Err(AttestationRejection::UntrustedChain)
    );
}

#[test]
fn refuses_a_different_challenge() {
    let result = verify_attestation(
        &chain(include_str!("fixtures/good.pem")),
        b"another-challenge",
        &policy(),
    );
    assert_eq!(result, Err(AttestationRejection::WrongChallenge));
}

#[test]
fn refuses_software_keys_unless_allowed() {
    assert_eq!(
        verify("software", &policy()),
        Err(AttestationRejection::InsecureKeyStore)
    );
    let stg = AttestationPolicy {
        allow_software: true,
        ..policy()
    };
    assert_eq!(
        verify("software", &stg).unwrap().security_level,
        KeySecurityLevel::Software
    );
}

#[test]
fn refuses_keys_usable_without_a_fingerprint_each_time() {
    for name in ["no-auth-required", "auth-timeout", "password-allowed"] {
        assert_eq!(
            verify(name, &policy()),
            Err(AttestationRejection::NoBiometricRequirement),
            "{name}"
        );
    }
}

#[test]
fn refuses_imported_or_non_p256_keys() {
    for name in ["imported-key", "rsa-key-claimed"] {
        assert_eq!(
            verify(name, &policy()),
            Err(AttestationRejection::WrongKeyParameters),
            "{name}"
        );
    }
}

#[test]
fn refuses_another_application() {
    for name in ["wrong-package", "wrong-signer"] {
        assert_eq!(
            verify(name, &policy()),
            Err(AttestationRejection::WrongApplication),
            "{name}"
        );
    }
}

#[test]
fn refuses_unlocked_devices_unless_software_is_allowed() {
    assert_eq!(
        verify("unlocked", &policy()),
        Err(AttestationRejection::UnverifiedDevice)
    );
}

#[test]
fn refuses_a_forged_certificate_signed_by_an_attested_key() {
    // 本物の鍵の証明書の鍵（署名用）で、偽の「鍵の証明書」に署名して先頭へ足した鎖。
    assert_eq!(
        verify("forged-below-attested-key", &policy()),
        Err(AttestationRejection::UntrustedChain)
    );
}

#[test]
fn refuses_an_intermediate_that_is_not_a_ca() {
    assert_eq!(
        verify("intermediate-not-ca", &policy()),
        Err(AttestationRejection::UntrustedChain)
    );
}

#[test]
fn refuses_broken_or_short_chains() {
    let mut good = chain(include_str!("fixtures/good.pem"));
    assert_eq!(
        verify_attestation(&good[..1], CHALLENGE, &policy()),
        Err(AttestationRejection::Malformed)
    );
    let shorter = good[0].len() - 3;
    good[0].truncate(shorter);
    assert_eq!(
        verify_attestation(&good, CHALLENGE, &policy()),
        Err(AttestationRejection::Malformed)
    );
}

#[test]
fn verifies_app_signatures_with_the_attested_key() {
    let key = verify("good", &policy()).unwrap();
    let message = include_bytes!("fixtures/good-signed-message.txt");
    let signature = include_bytes!("fixtures/good-signature.der");
    assert!(verify_p256_signature(
        &key.public_key_spki,
        message,
        signature
    ));
    assert!(!verify_p256_signature(
        &key.public_key_spki,
        b"another message",
        signature
    ));
}

#[test]
fn reads_the_google_roots_shipped_with_assay() {
    let keys = root_keys_from_pem(crate::domain::key_attestation::GOOGLE_ROOTS_PEM).unwrap();
    assert_eq!(keys.len(), 2);
}
