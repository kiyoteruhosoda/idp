# crypto-glue 0.2.2, patched for rsa 0.10.0

Copy of the published crate `crypto-glue` 0.2.2 (https://github.com/kanidm/crypto-glue, MPL-2.0),
used through `[patch.crates-io]` in the workspace `Cargo.toml` (idp ADR-0081, task #1016).

Why: rsa 0.10.0-rc.19 has RUSTSEC-2023-0071 (Marvin attack). The fix is rsa 0.10.0, but crypto-glue 0.2.2
(pulled in by webauthn-rs 0.6) asks for rsa with the `sha2` feature, which 0.10.0 removed, so the lock cannot move.

Changes from the published crate:
- `Cargo.toml`: the `rsa` dependency is `version = "0.10"`, `features = ["pkcs1v15"]` (SHA-2 is always on in 0.10.0;
  PKCS#1 v1.5 became opt-in)
- `src/lib.rs`, `pub mod rsa`: `RsaPrivateKey` / `RsaPublicKey` -> `PrivateKey` / `PublicKey` (0.10.0 renamed them and
  deprecated the old names; the crate denies warnings). The public aliases `RS256PrivateKey` / `RS256PublicKey` are unchanged.

Remove this directory and the patch entry once a crypto-glue release accepts rsa 0.10.
