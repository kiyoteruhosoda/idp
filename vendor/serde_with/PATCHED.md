# serde_with 3.24.0, without its optional chrono dependency

Copy of the published crate `serde_with` 3.24.0 (https://github.com/jonasbb/serde_with, MIT OR Apache-2.0),
used through `[patch.crates-io]` in the workspace `Cargo.toml` (idp ADR-0082, task #1016).

Why: chrono is flagged unmaintained (RUSTSEC-2026-0543). idp does not use chrono, but serde_with (pulled in by
webauthn-rs) names it as an optional dependency with weak features (`chrono_0_4?/alloc` ...). Cargo writes such
optional dependencies into Cargo.lock even when nothing enables them, and the dependency audit reads Cargo.lock.

Changes from the published crate, all in `Cargo.toml`:
- the `chrono_0_4` dependency and the `chrono_0_4?/...` entries of the `alloc` and `std` features are removed
- the `chrono` / `chrono_0_4` features are kept empty so the source's `cfg(feature = ...)` gates stay declared
  (enabling them does not compile)
- the `[[test]]` targets are removed with the `tests/` directory (not copied)

Remove this directory and the patch entry once serde_with no longer names chrono, or webauthn-rs no longer uses it.
