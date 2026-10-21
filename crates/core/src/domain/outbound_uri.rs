//! IdP がサーバ側から要求を出す宛先の制約（SEC2）。
//!
//! 外向きに POST する URI（現状は `backchannel_logout_uri`）はテナント管理者が登録できるため、
//! 無制限だと認証済み blind SSRF になる（クラウドのインスタンスメタデータ・内部管理 API への到達）。
//!
//! 判定を domain に置くのは、**登録時（`client_management`）と送信時（presentation の logout）の
//! 二箇所が同じ規則を使う**ためである。登録時だけの検査では、本機能の導入前に登録された行や、
//! DB を直接編集された行が素通りしてしまう。
//!
//! ここで見るのは URI の字面だけである。**名前を引いた結果**は送る瞬間に見る
//! （`infrastructure::outbound_http` の resolver。登録時に引いても DNS rebinding で覆せるうえ、
//! 送信時の解決ともずれる。task #585）。字面の段では、明らかに内部を指す名前（点の無い名前・
//! クラスタ内の名前）もここで弾く。

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
        Some(url::Host::Domain(host)) => name_is_internal(host),
        None => true,
    }
}

/// 字面だけで内部と分かる名前か（task #585）。
///
/// - `localhost` / `*.localhost`（自ホスト）
/// - **点の無い名前**（`api`・`rp` のような、同じネットワークのサービス名。search ドメインで
///   クラスタ内へ引ける）
/// - クラスタ・社内向けの予約名（`*.svc`・`*.cluster.local`・`*.internal`・`*.local`）
fn name_is_internal(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == "localhost"
        || host.ends_with(".localhost")
        || !host.contains('.')
        || [".svc", ".cluster.local", ".internal", ".local"]
            .iter()
            .any(|suffix| host.ends_with(suffix))
}

/// 名前を引いた結果の住所が内部か（送る瞬間の resolver が使う。task #585）。
pub fn is_internal_address(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => ipv4_is_internal(v4),
        std::net::IpAddr::V6(v6) => ipv6_is_internal(v6),
    }
}

/// 名前を引いた結果が内部の住所でも送ってよい名前（設定 `OUTBOUND_TRUSTED_HOSTS`。task #585）。
///
/// 宅内や社内で、公開名が内側の前段へ引ける配置（split DNS）では、正規の RP の宛先も内部の住所に
/// なる。そこを一律に弾くと、ログアウトの知らせが 1 件も届かなくなる。**運用者が名指しした名前と
/// その下だけ**を例外にする（テナント管理者には触らせない）。字面の検査（点の無い名前など）は
/// 例外にしない。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutboundTrust {
    suffixes: Vec<String>,
}

impl OutboundTrust {
    /// 何も信用しない（既定）。
    pub fn none() -> Self {
        Self::default()
    }

    /// カンマ区切りのドメイン名（`nolumia.com,example.org`）から作る。`nolumia.com` は
    /// `nolumia.com` 自身と `*.nolumia.com` に当たる。空・空白だけの要素は捨てる。
    pub fn parse(list: &str) -> Self {
        Self {
            suffixes: list
                .split(',')
                .map(|s| s.trim().trim_start_matches('.').trim_end_matches('.'))
                .filter(|s| !s.is_empty())
                .map(str::to_ascii_lowercase)
                .collect(),
        }
    }

    /// `host` が信用する名前か。
    pub fn trusts(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.suffixes
            .iter()
            .any(|s| host == *s || host.ends_with(&format!(".{s}")))
    }
}

fn ipv4_is_internal(ip: std::net::Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        // 「この網」（0.0.0.0/8）。
        || a == 0
        // CGNAT（100.64.0.0/10）。クラウドのメタデータ・内部 LB が置かれることがある。
        || (a == 100 && (64..128).contains(&b))
        // IETF プロトコル割り当て（192.0.0.0/24。NAT64 の発見などに使う）。
        || (a == 192 && b == 0 && c == 0)
        // ベンチマーク用（198.18.0.0/15）。閉じた網の中で使われることがある。
        || (a == 198 && (b == 18 || b == 19))
        // 予約（240.0.0.0/4）。
        || a >= 240
    // なおドキュメント用レンジ（192.0.2.0/24 等）は塞がない。経路が無いだけで「内部」ではなく、
    // 検証環境が RP の代用に使うことがあるため。
}

fn ipv6_is_internal(ip: std::net::Ipv6Addr) -> bool {
    if let Some(v4) = embedded_ipv4(ip) {
        return ipv4_is_internal(v4);
    }
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        // unique local（fc00::/7）と link-local（fe80::/10）。
        || (ip.segments()[0] & 0xfe00) == 0xfc00
        || (ip.segments()[0] & 0xffc0) == 0xfe80
}

/// IPv6 の中に IPv4 を埋め込む形（task #585）。埋め込まれた IPv4 で判定する。
///
/// - IPv4 写像（`::ffff:a.b.c.d`）と IPv4 互換（`::a.b.c.d`。`::` と `::1` は除く）
/// - NAT64（`64:ff9b::/96`。変換器を通ると埋め込んだ IPv4 へ届く）
/// - 6to4（`2002::/16`。2〜5 バイト目が IPv4）
fn embedded_ipv4(ip: std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return Some(v4);
    }
    let s = ip.segments();
    let o = ip.octets();
    let tail = std::net::Ipv4Addr::new(o[12], o[13], o[14], o[15]);
    if s[..6] == [0, 0, 0, 0, 0, 0] && !ip.is_unspecified() && !ip.is_loopback() {
        return Some(tail);
    }
    if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return Some(tail);
    }
    if s[0] == 0x2002 {
        return Some(std::net::Ipv4Addr::new(o[2], o[3], o[4], o[5]));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_destinations_are_allowed() {
        assert!(!is_internal_destination("https://rp.example.com/bc"));
        assert!(!is_internal_destination("http://rp.example.com:3000/bc"));
        assert!(!is_internal_destination("http://203.0.113.10/bc"));
        assert!(!is_internal_destination("http://[2001:db8::1]/bc"));
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
            // 字面で内部と分かる名前（task #585）。
            "http://rp:3000/bc",
            "http://api:8080/internal",
            "http://api.idp-prod.svc/internal",
            "http://api.idp-prod.svc.cluster.local:8080/",
            "http://metadata.google.internal/",
            "http://printer.local/",
            // 弾く一覧の漏れ（task #585）。
            "http://198.18.0.1/",
            "http://198.19.255.255/",
            "http://192.0.0.8/",
            "http://240.0.0.1/",
            "http://0.1.2.3/",
            "http://224.0.0.1/",
            "http://[64:ff9b::10.0.0.1]/",
            "http://[::127.0.0.1]/",
            "http://[2002:a9fe:a9fe::]/",
            "http://[ff02::1]/",
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

    #[test]
    fn trusted_names_match_the_name_and_below_only() {
        let trust = OutboundTrust::parse(" nolumia.com, .Example.org ,,");
        assert!(trust.trusts("nolumia.com"));
        assert!(trust.trusts("wiki.nolumia.com"));
        assert!(trust.trusts("WIKI.nolumia.com."));
        assert!(trust.trusts("a.example.org"));
        // 名前の一部が同じだけの別の名前は当たらない。
        assert!(!trust.trusts("evilnolumia.com"));
        assert!(!trust.trusts("nolumia.com.evil.test"));
        assert!(!OutboundTrust::none().trusts("nolumia.com"));
    }

    #[test]
    fn resolved_addresses_are_judged_by_the_same_rules() {
        use std::net::IpAddr;
        for internal in [
            "10.10.2.11",
            "127.0.0.1",
            "169.254.169.254",
            "::1",
            "64:ff9b::a00:1",
        ] {
            assert!(
                is_internal_address(internal.parse::<IpAddr>().unwrap()),
                "{internal}"
            );
        }
        for public in ["104.16.0.1", "2606:4700::1"] {
            assert!(
                !is_internal_address(public.parse::<IpAddr>().unwrap()),
                "{public}"
            );
        }
    }
}
