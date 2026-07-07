# OIDC IdP（Rust）マルチステージビルド。CLAUDE.md「環境要件」準拠（rust:slim ベース）。
#
# ADR-0007（API/Web サービス分割）: 1 つのワークスペースから 2 つのバイナリを作る。
#   - idp     … api サービス（OIDC protocol・JSON 管理 API・内部 API。DB 直結）→ runtime-api
#   - idp-web … web サービス（HTML 画面・API クライアント。DB 非依存）        → runtime-web
# ビルド依存: ring（rustls）が C/アセンブラを要するため C ツールチェイン＋perl。TLS は rustls。
# 翻訳リソース（i18n/*.ftl）は include_str! で idp-web へ埋め込むため実行イメージには同梱不要。

# ---- builder ----
FROM rust:slim AS builder
WORKDIR /build

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential perl pkg-config \
    && rm -rf /var/lib/apt/lists/*

# 依存解決を層キャッシュに乗せるため、マニフェスト類を先にコピーしてダミービルドする。
COPY Cargo.toml Cargo.lock ./
COPY crates/core/Cargo.toml crates/core/Cargo.toml
COPY crates/contracts/Cargo.toml crates/contracts/Cargo.toml
COPY crates/api/Cargo.toml crates/api/Cargo.toml
COPY crates/web/Cargo.toml crates/web/Cargo.toml
RUN mkdir -p crates/core/src crates/contracts/src crates/api/src crates/web/src \
    && echo "" > crates/core/src/lib.rs \
    && echo "" > crates/contracts/src/lib.rs \
    && echo "" > crates/api/src/lib.rs \
    && echo "" > crates/web/src/lib.rs \
    && echo "fn main() {}" > crates/api/src/main.rs \
    && echo "fn main() {}" > crates/web/src/main.rs \
    && cargo build --release --locked --bin idp --bin idp-web \
    ; rm -rf crates/core/src crates/contracts/src crates/api/src crates/web/src

# 本体をビルド。i18n（include_str! で idp-web に埋め込み）と migrations（sqlx::migrate! で idp に埋め込み）は
# crate マニフェスト基準の相対パス（../../i18n・../../migrations）で参照するためルートへ配置する。
COPY crates ./crates
COPY i18n ./i18n
COPY migrations ./migrations
RUN cargo build --release --locked --bin idp --bin idp-web

# ---- migrate ----
# DDL / マスタデータ適用の専用ジョブ（sqlx migrate run）。CLAUDE.md schema-version 方針に従い、
# アプリ起動時には適用せず、この単独ジョブで適用する。Compose の migrate サービスから使う。
FROM rust:slim AS migrate
WORKDIR /migrate
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential perl pkg-config \
    && rm -rf /var/lib/apt/lists/* \
    && cargo install sqlx-cli --version ^0.8 --no-default-features --features mysql,rustls --locked
COPY migrations ./migrations
# DATABASE_URL は実行時に注入する。
ENTRYPOINT ["sqlx", "migrate", "run", "--source", "/migrate/migrations"]

# ---- 実行イメージ共通ベース ----
FROM debian:bookworm-slim AS runtime-base
# TLS 検証用のルート証明書（web→api の https 呼び出し等）と、ヘルスチェック用の curl。非 root 実行。
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home idp
USER idp

# ---- runtime: api（OIDC protocol・JSON 管理 API・内部 API。DB 直結）----
FROM runtime-base AS runtime-api
WORKDIR /app
COPY --from=builder /build/target/release/idp /usr/local/bin/idp
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=5 \
    CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1
# 設定はすべて環境変数から注入する（config モジュール経由。docs/OPERATIONS.md 参照）。
ENTRYPOINT ["/usr/local/bin/idp"]

# ---- runtime: web（HTML 画面・API クライアント。DB 非依存）----
FROM runtime-base AS runtime-web
WORKDIR /app
COPY --from=builder /build/target/release/idp-web /usr/local/bin/idp-web
EXPOSE 8081
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=5 \
    CMD curl -fsS http://127.0.0.1:8081/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/idp-web"]
