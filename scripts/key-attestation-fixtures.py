#!/usr/bin/env python3
"""Builds certificate chains resembling Android Key Attestation (task #892; for test data and checks on stg).

Real device chains end at Google's root, but tests use a self-made root and verify by passing it to assay's
`AttestationPolicy`. The content of the `KeyDescription` extension (1.3.6.1.4.1.11129.2.1.17) is
built exactly per Android KeyMint's definition.

    python3 scripts/key-attestation-fixtures.py <output dir>    # writes the full set of test data

Imported as a module, `build_chain(...)` is available (the stg check script imports it).
Only `cryptography` is required.
"""

from __future__ import annotations

import datetime
import hashlib
import sys
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

KEY_DESCRIPTION_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")
PACKAGE = b"com.nolumia.auth"
SIGNER_DIGEST = hashlib.sha256(b"authapp-test-signer").digest()
CHALLENGE = b"assay-test-challenge-0123456789ab"


# ── A small DER writer ───────────────────────────────────────────────


def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: bytes, body: bytes) -> bytes:
    return tag + _len(len(body)) + body


def integer(n: int) -> bytes:
    body = n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big")
    return tlv(b"\x02", body)


def enumerated(n: int) -> bytes:
    return tlv(b"\x0a", integer(n)[2:])


def octets(b: bytes) -> bytes:
    return tlv(b"\x04", b)


def boolean(v: bool) -> bytes:
    return tlv(b"\x01", b"\xff" if v else b"\x00")


def null() -> bytes:
    return b"\x05\x00"


def seq(*items: bytes) -> bytes:
    return tlv(b"\x30", b"".join(items))


def set_of(*items: bytes) -> bytes:
    return tlv(b"\x31", b"".join(sorted(items)))


def context(number: int, inner: bytes) -> bytes:
    """[number] EXPLICIT (constructed, context-specific tag). 31 and above use the multi-byte form, 7 bits at a time."""
    if number < 31:
        tag = bytes([0xA0 | number])
    else:
        parts = []
        n = number
        while True:
            parts.insert(0, n & 0x7F)
            n >>= 7
            if n == 0:
                break
        tag = bytes([0xBF]) + bytes(p | 0x80 for p in parts[:-1]) + bytes([parts[-1]])
    return tlv(tag, inner)


# ── KeyDescription ───────────────────────────────────────────────────


@dataclass
class KeyOptions:
    """Values written into the key attestation. Default is "TEE, fingerprint on every use, locked, correct app"."""

    challenge: bytes = CHALLENGE
    security_level: int = 1  # 0 software / 1 TEE / 2 StrongBox
    no_auth_required: bool = False
    user_auth_type: int | None = 2  # 2 = fingerprint (biometric). 3 = biometric + PIN
    auth_timeout: int | None = None
    origin: int = 0
    device_locked: bool = True
    verified_boot_state: int = 0
    package: bytes = PACKAGE
    digests: list[bytes] = field(default_factory=lambda: [SIGNER_DIGEST])
    algorithm: int = 3  # EC
    ec_curve: int = 1  # P-256
    purposes: tuple[int, ...] = (2,)  # SIGN


def authorization_list(items: list[tuple[int, bytes]]) -> bytes:
    return seq(*(context(n, v) for n, v in sorted(items)))


def key_description(o: KeyOptions) -> bytes:
    hw: list[tuple[int, bytes]] = [
        (1, set_of(*(integer(p) for p in o.purposes))),
        (2, integer(o.algorithm)),
        (3, integer(256)),
        (10, integer(o.ec_curve)),
        (702, integer(o.origin)),
        (
            704,
            seq(octets(b"\x11" * 32), boolean(o.device_locked), enumerated(o.verified_boot_state), octets(b"\x22" * 32)),
        ),
    ]
    if o.no_auth_required:
        hw.append((503, null()))
    if o.user_auth_type is not None:
        hw.append((504, integer(o.user_auth_type)))
    if o.auth_timeout is not None:
        hw.append((505, integer(o.auth_timeout)))
    app_id = seq(set_of(seq(octets(o.package), integer(1))), set_of(*(octets(d) for d in o.digests)))
    sw: list[tuple[int, bytes]] = [(709, octets(app_id))]
    if o.security_level == 0:
        # For software keys, the protection conditions are also listed in the software list.
        sw, hw = sw + [x for x in hw if x[0] != 704], [x for x in hw if x[0] == 704]
    return seq(
        integer(300),
        enumerated(o.security_level),
        integer(300),
        enumerated(o.security_level),
        octets(o.challenge),
        octets(b""),
        authorization_list(sw),
        authorization_list(hw),
    )


# ── Certificates ────────────────────────────────────────────────────────────

NOW = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject: str, issuer: str, public_key, signing_key, ca: bool, extra: bytes | None = None, ca_ext: bool = True):
    if isinstance(signing_key, rsa.RSAPrivateKey):
        algorithm = hashes.SHA256()
    elif isinstance(signing_key.curve, ec.SECP384R1):
        algorithm = hashes.SHA384()
    else:
        algorithm = hashes.SHA256()
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW)
        .not_valid_after(NOW + datetime.timedelta(days=3650 * 3))
    )
    if ca_ext:
        builder = builder.add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    if extra is not None:
        builder = builder.add_extension(x509.UnrecognizedExtension(KEY_DESCRIPTION_OID, extra), critical=False)
    return builder.sign(signing_key, algorithm)


@dataclass
class Chain:
    certs: list[x509.Certificate]  # key certificate first
    root: x509.Certificate
    leaf_key: ec.EllipticCurvePrivateKey

    def der_list(self) -> list[bytes]:
        return [c.public_bytes(serialization.Encoding.DER) for c in self.certs]

    def pem(self) -> str:
        return "".join(c.public_bytes(serialization.Encoding.PEM).decode() for c in self.certs)


def make_root(kind: str = "rsa"):
    key = rsa.generate_private_key(65537, 2048) if kind == "rsa" else ec.generate_private_key(ec.SECP384R1())
    cert = _cert("Test Attestation Root", "Test Attestation Root", key.public_key(), key, ca=True)
    return key, cert


def build_chain(options: KeyOptions | None = None, root=None, leaf_key=None, intermediate_ca: bool = True) -> Chain:
    """Root -> intermediate (P-256) -> key certificate (P-256, with KeyDescription)."""
    options = options or KeyOptions()
    root_key, root_cert = root or make_root("rsa")
    inter_key = ec.generate_private_key(ec.SECP256R1())
    root_name = root_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    inter = _cert("Test Attestation Intermediate", root_name, inter_key.public_key(), root_key, ca=intermediate_ca)
    leaf_key = leaf_key or ec.generate_private_key(ec.SECP256R1())
    leaf = _cert(
        "Android Keystore Key", "Test Attestation Intermediate", leaf_key.public_key(), inter_key, ca=False,
        extra=key_description(options), ca_ext=False,
    )
    return Chain([leaf, inter, root_cert], root_cert, leaf_key)


def write_fixtures(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    rsa_root = make_root("rsa")
    ec_root = make_root("ec")
    (out / "root.pem").write_bytes(rsa_root[1].public_bytes(serialization.Encoding.PEM))
    (out / "root-p384.pem").write_bytes(ec_root[1].public_bytes(serialization.Encoding.PEM))
    cases: dict[str, Chain] = {
        "good": build_chain(KeyOptions(), rsa_root),
        "good-p384-root": build_chain(KeyOptions(security_level=2), ec_root),
        "software": build_chain(KeyOptions(security_level=0), rsa_root),
        "no-auth-required": build_chain(KeyOptions(no_auth_required=True, user_auth_type=None), rsa_root),
        "auth-timeout": build_chain(KeyOptions(auth_timeout=30), rsa_root),
        "password-allowed": build_chain(KeyOptions(user_auth_type=3), rsa_root),
        "imported-key": build_chain(KeyOptions(origin=2), rsa_root),
        "rsa-key-claimed": build_chain(KeyOptions(algorithm=1), rsa_root),
        "wrong-package": build_chain(KeyOptions(package=b"com.example.fake"), rsa_root),
        "wrong-signer": build_chain(KeyOptions(digests=[hashlib.sha256(b"someone-else").digest()]), rsa_root),
        "unlocked": build_chain(KeyOptions(device_locked=False), rsa_root),
        "intermediate-not-ca": build_chain(KeyOptions(), rsa_root, intermediate_ca=False),
    }
    # Attack shape: sign a fake "key certificate" with the real key certificate's key and prepend it.
    genuine = build_chain(KeyOptions(), rsa_root)
    fake_key = ec.generate_private_key(ec.SECP256R1())
    fake_leaf = _cert(
        "Android Keystore Key", "Android Keystore Key", fake_key.public_key(), genuine.leaf_key, ca=False,
        extra=key_description(KeyOptions()), ca_ext=False,
    )
    cases["forged-below-attested-key"] = Chain([fake_leaf, *genuine.certs], genuine.root, fake_key)
    for name, chain in cases.items():
        (out / f"{name}.pem").write_text(chain.pem())
    # For signature verification tests (ECDSA P-256, SHA-256, DER): a key and a signature over a fixed message.
    signer = cases["good"].leaf_key
    message = b"assay-app-approver-v1\napprove\ntenant\nrequest\nchallenge"
    signature = signer.sign(message, ec.ECDSA(hashes.SHA256()))
    (out / "good-signature.der").write_bytes(signature)
    (out / "good-signed-message.txt").write_bytes(message)
    print(f"wrote {len(cases)} chains to {out}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    write_fixtures(Path(sys.argv[1]))
