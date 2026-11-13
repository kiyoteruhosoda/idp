# OIDC IdP (Rust) multi-stage build. Follows CLAUDE.md "環境要件" (rust:slim base).
#
# ADR-0007 (API/Web service split): builds 2 binaries from one workspace.
#   - assay   … api service (OIDC protocol, JSON admin API, internal API; direct DB) -> runtime-api
#   - assay-web … web service (HTML screens, API client; no DB)                     -> runtime-web
# Build deps: ring (rustls) needs C/assembler, so a C toolchain + perl. TLS is rustls.
#   webauthn-rs depends on openssl-sys (native OpenSSL), so libssl-dev is needed too.
# Translation resources (i18n/*.ftl) are embedded into assay-web via include_str!, so the runtime image needs no copy.

# ---- builder ----
# To match the glibc ABI with the runtime stage (debian:bookworm-slim), the Rust builder is also
# pinned to bookworm. rust:slim may move to trixie etc. on tag updates, so this prevents
# `GLIBC_2.39 not found` on deploy targets such as the NAS.
FROM rust:slim-bookworm@sha256:f2c004e3d2d8b547e8cf7ffbc29205385f4e71d23e53e4e383065db5e9f822cd AS builder
WORKDIR /build

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential perl pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# To put dependency resolution in the layer cache, copy the manifests first and do a dummy build.
COPY Cargo.toml Cargo.lock ./
COPY crates/core/Cargo.toml crates/core/Cargo.toml
COPY crates/contracts/Cargo.toml crates/contracts/Cargo.toml
COPY crates/api/Cargo.toml crates/api/Cargo.toml
COPY crates/web/Cargo.toml crates/web/Cargo.toml
RUN mkdir -p crates/core/src crates/contracts/src crates/api/src/bin crates/web/src \
    && echo "" > crates/core/src/lib.rs \
    && echo "" > crates/contracts/src/lib.rs \
    && echo "" > crates/api/src/lib.rs \
    && echo "" > crates/web/src/lib.rs \
    && echo "fn main() {}" > crates/api/src/main.rs \
    && echo "fn main() {}" > crates/api/src/bin/rewrap_secrets.rs \
    && echo "fn main() {}" > crates/web/src/main.rs \
    && cargo build --release --locked --bin assay --bin assay-rewrap-secrets --bin assay-web \
    ; rm -rf crates/core/src crates/contracts/src crates/api/src crates/web/src

# Build the real thing. i18n (embedded in assay-web via include_str!) and migrations (embedded in assay via sqlx::migrate!)
# are referenced by paths relative to the crate manifest (../../i18n, ../../migrations), so place them at the root.
COPY crates ./crates
COPY i18n ./i18n
COPY migrations ./migrations
# Version embedding is pushed down to here. Putting per-build values (IDP_BUILD_NUMBER goes up even for the same
# commit) higher up would rebuild the apt install layer and the dependency dummy-build layer every time.
# ⚠ **`COMMIT_HASH` is accepted too.** The production builders (deck and deploy-repo's `build-image.yml`) pass
# the short SHA as `COMMIT_HASH` under the same name to every app. Back when only `IDP_GIT_VERSION` was accepted,
# the production admin console footer stayed at `v0.1.0 (unknown)`. When `IDP_GIT_VERSION` is
# set explicitly (`scripts/build.sh`, docker compose), it wins.
ARG COMMIT_HASH=
ARG IDP_GIT_VERSION=
ENV IDP_GIT_VERSION=${IDP_GIT_VERSION:-${COMMIT_HASH:-unknown}}
# Build number (CI sequence number). It goes up on a rebuild even for the same commit, so "has a new artifact
# been deployed" can be judged from the version alone. Stays empty for local builds (not appended to the version).
ARG IDP_BUILD_NUMBER=
ENV IDP_BUILD_NUMBER=${IDP_BUILD_NUMBER}
# COPY preserves the source files' mtime, so the real sources may have an older mtime than the artifacts
# produced by the dummy build above. Then cargo's freshness check (mtime-based) considers them "unchanged" and skips
# the rebuild, shipping the dummy `fn main() {}` binary (exits 0 immediately, no output) as is. To prevent that,
# touch the source mtime of each workspace crate before rebuilding (dependency crate caches are untouched).
RUN find crates -name '*.rs' -exec touch {} + \
    && cargo build --release --locked --bin assay --bin assay-rewrap-secrets --bin assay-web

# ---- migrate tool builder ----
# Building sqlx-cli needs the Rust toolchain and C build deps, but bringing those into the migrate runtime image
# would bloat assay-migrate.tar. Confine them to a build-only stage, and pass only the sqlx binary and
# migrations to the runtime stage.
FROM rust:slim-bookworm@sha256:f2c004e3d2d8b547e8cf7ffbc29205385f4e71d23e53e4e383065db5e9f822cd AS migrate-tool-builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential perl pkg-config \
    && rm -rf /var/lib/apt/lists/* \
    && cargo install sqlx-cli --version ^0.9 --no-default-features --features mysql,rustls --locked --root /opt/sqlx

# ---- migrate ----
# Dedicated job for applying DDL / master data (sqlx migrate run). Per CLAUDE.md's schema-version policy,
# migrations are not applied at app startup but in this standalone job. Used by Compose's migrate service.
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS migrate
WORKDIR /migrate
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home assay
COPY --from=migrate-tool-builder /opt/sqlx/bin/sqlx /usr/local/bin/sqlx
COPY migrations ./migrations
USER assay
# DATABASE_URL is injected at runtime.
ENTRYPOINT ["sqlx", "migrate", "run", "--source", "/migrate/migrations"]

# ---- Common base for runtime images ----
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS runtime-base
# Root certificates for TLS verification (web->api https calls etc.) and curl for health checks. Runs as non-root.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home assay
USER assay

# ---- runtime: api (OIDC protocol, JSON admin API, internal API; direct DB) ----
FROM runtime-base AS runtime-api
WORKDIR /app
COPY --from=builder /build/target/release/assay /usr/local/bin/assay
# Tool run once when rotating the key (docs/OPERATIONS.md). ENTRYPOINT stays the api.
COPY --from=builder /build/target/release/assay-rewrap-secrets /usr/local/bin/assay-rewrap-secrets
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=5 \
    CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1
# All settings are injected from environment variables (via the config module; see docs/OPERATIONS.md).
ENTRYPOINT ["/usr/local/bin/assay"]

# ---- runtime: web (HTML screens, API client; no DB) ----
FROM runtime-base AS runtime-web
WORKDIR /app
COPY --from=builder /build/target/release/assay-web /usr/local/bin/assay-web
EXPOSE 8081
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=5 \
    CMD curl -fsS http://127.0.0.1:8081/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/assay-web"]
