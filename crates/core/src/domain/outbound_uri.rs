//! IdP がサーバ側から要求を出す宛先の制約（SEC2）。
//!
//! 外向きに POST する URI（現状は `backchannel_logout_uri`）はテナント管理者が登録できるため、
//! 無制限だと認証済み blind SSRF になる（クラウドのインスタンスメタデータ・内部管理 API への到達）。
//!
//! 判定を domain に置くのは、**登録時（`client_management`）と送信時（presentation の logout）の
//! 二箇所が同じ規則を使う**ためである。登録時だけの検査では、本機能の導入前に登録された行や、
//! DB を直接編集された行が素通りしてしまう。
//!
//! 名前解決の結果までは見ない（登録時に解決しても DNS rebinding で覆せるうえ、送信時の解決とも
//! ずれる）。閉じた配置では前段プロキシの egress 制御を併用する。

/// URI が内部（ループバック・プライベート・リンクローカル等）を指すか。
///
/// 解析できない URI は「安全側」に倒して内部扱いにする（送信させない）。
pub fn is_internal_destination(uri: &str) -> bool {
    match url::Url::parse(uri.trim()) {
        Ok(url) => url_is_internal(&url),
        Err(_) => true,
    }
}

fn url_is_internal(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(ip)) => ipv4_is_internal(ip),
        Some(url::Host::Ipv6(ip)) => ipv6_is_internal(ip),
        // 名前で指す宛先は解決結果を見ない。明らかに自ホストを指す名前だけは弾く。
        Some(url::Host::Domain(host)) => {
            let host = host.to_ascii_lowercase();
            host == "localhost" || host.ends_with(".localhost")
        }
        None => true,
    }
}

fn ipv4_is_internal(ip: std::net::Ipv4Addr) -> bool {
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        // CGNAT（100.64.0.0/10）。クラウドのメタデータ・内部 LB が置かれることがある。
        // なおドキュメント用レンジ（192.0.2.0/24 等）は塞がない。経路が無いだけで「内部」ではなく、
        // 検証環境が RP の代用に使うことがあるため。
        || (ip.octets()[0] == 100 && (64..128).contains(&ip.octets()[1]))
}

fn ipv6_is_internal(ip: std::net::Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return ipv4_is_internal(v4);
    }
    ip.is_loopback()
        || ip.is_unspecified()
        // unique local（fc00::/7）と link-local（fe80::/10）。
        || (ip.segments()[0] & 0xfe00) == 0xfc00
        || (ip.segments()[0] & 0xffc0) == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_destinations_are_allowed() {
        assert!(!is_internal_destination("https://rp.example.com/bc"));
        assert!(!is_internal_destination("http://rp.example.com:3000/bc"));
        // 名前で指す内部サービスは（解決結果を見ないため）通す。
        assert!(!is_internal_destination("http://rp:3000/bc"));
        assert!(!is_internal_destination("http://203.0.113.10/bc"));
    }

    #[test]
    fn internal_destinations_are_rejected() {
        for uri in [
            // クラウドのインスタンスメタデータ（link-local）。
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:8080/internal",
            "http://localhost/internal",
            "http://app.LOCALHOST/internal",
            "http://10.0.0.5/admin",
            "http://192.168.1.1/admin",
            "http://172.16.0.1/admin",
            "http://100.64.0.1/admin",
            "http://0.0.0.0/",
            "http://[::1]/internal",
            "http://[fd00::1]/internal",
            "http://[fe80::1]/internal",
            "http://[::ffff:127.0.0.1]/internal",
            // 解析できない値は送信させない。
            "not a url",
            "",
        ] {
            assert!(
                is_internal_destination(uri),
                "{uri} must be treated as internal"
            );
        }
    }
}
