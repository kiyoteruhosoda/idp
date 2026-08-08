//! 配置の姿勢（本番相当かどうか）と bootstrap secret の最低要件（SEC11）。
//!
//! api も web も「開発用の既定 secret のままなら本番では起動しない」fail-fast を持つが、判定が
//! ずれると **api は起動して web は起動しない**（またはその逆）という中途半端な状態になる。
//! api ↔ web で一致していないと壊れる導出なので、契約としてここに単一定義する
//! （`CLAUDE.md`「ディレクトリ構成」の contracts の役割）。

/// 公開オリジンが本番相当か（＝開発用の既定 secret での起動を拒否すべきか）。
///
/// 判定は「**ローカルループバック以外を公開している**」。https はもちろん、http でも loopback 以外の
/// ホストを名乗るなら前段で TLS を終端した本番配置とみなす。
///
/// スキームだけで判定していた頃は、TLS をプロキシで終端して `ISSUER=http://id.example.com` と
/// した配置で fail-fast が効かず、ソースに埋まった既知の `INTERNAL_SERVICE_TOKEN` のまま
/// `/internal/*` が開いていた（防御が前段プロキシの `/internal/` 404 一枚だけになる）。
pub fn requires_production_secrets(public_origin: &str) -> bool {
    let Ok(url) = url::Url::parse(public_origin.trim()) else {
        // 解析できない値は起動時に別途弾かれる。ここでは安全側（本番扱い）に倒す。
        return true;
    };
    if url.scheme().eq_ignore_ascii_case("https") {
        return true;
    }
    !host_is_loopback(&url)
}

/// URL のホストがローカルループバック（開発機での自己アクセス）か。
fn host_is_loopback(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(host)) => {
            let host = host.to_ascii_lowercase();
            host == "localhost" || host.ends_with(".localhost")
        }
        None => false,
    }
}

/// `INTERNAL_SERVICE_TOKEN` の最小文字数。
///
/// `openssl rand -base64 32` が 44 文字なので、実運用の生成手順を妨げない下限。
pub const INTERNAL_SERVICE_TOKEN_MIN_LEN: usize = 32;

/// `INTERNAL_SERVICE_TOKEN` の最低要件を検査し、正規化（前後の空白除去）した値を返す。
///
/// このトークンは `/internal/*`（認証・パスワード変更・MFA 検証）を守る唯一の資格情報でありながら、
/// 従来は無検証で 1 文字でも起動できた（`KEY_ENCRYPTION_KEY` / `CSRF_SECRET` は 32 バイト強制）。
/// 形式は問わない（api と web で一致すれば何でもよい）ので、推測可能な短さと
/// `.env` テンプレートのプレースホルダ残りだけを弾く。
pub fn validate_internal_service_token(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.contains("CHANGE-ME") {
        return Err(
            "INTERNAL_SERVICE_TOKEN is still the .env template placeholder \"CHANGE-ME\"; \
             replace it with a real value (generate with `openssl rand -base64 32`)"
                .to_string(),
        );
    }
    if value.chars().count() < INTERNAL_SERVICE_TOKEN_MIN_LEN {
        return Err(format!(
            "INTERNAL_SERVICE_TOKEN must be at least {INTERNAL_SERVICE_TOKEN_MIN_LEN} characters \
             (it is the only credential protecting /internal/*); \
             generate one with `openssl rand -base64 32`"
        ));
    }
    Ok(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_http_is_development() {
        for origin in [
            "http://localhost:8080",
            "http://LOCALHOST:8080",
            "http://127.0.0.1:8070",
            "http://[::1]:8070",
            "http://api.localhost:8070",
        ] {
            assert!(
                !requires_production_secrets(origin),
                "{origin} should be treated as local development"
            );
        }
    }

    #[test]
    fn tls_terminated_upstream_still_counts_as_production() {
        // SEC11 の本体: http でもループバック以外を公開しているなら本番扱いにする。
        for origin in [
            "http://id.example.com",
            "http://id.example.com:8080",
            "http://10.0.0.5:8080",
            "https://localhost:8443",
            "https://identity.example.com",
            "HTTPS://identity.example.com",
        ] {
            assert!(
                requires_production_secrets(origin),
                "{origin} must require production secrets"
            );
        }
    }

    #[test]
    fn unparseable_origins_fail_closed() {
        assert!(requires_production_secrets("not a url"));
        assert!(requires_production_secrets(""));
    }

    #[test]
    fn internal_service_token_must_be_long_enough_and_not_a_placeholder() {
        assert!(validate_internal_service_token("short").is_err());
        assert!(
            validate_internal_service_token("CHANGE-ME-CHANGE-ME-CHANGE-ME-CHANGE-ME").is_err()
        );
        let good = "0123456789abcdef0123456789abcdef";
        assert_eq!(
            validate_internal_service_token(&format!("  {good}  ")).unwrap(),
            good
        );
    }
}
