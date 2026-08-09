//! `X-Forwarded-For` からの接続元 IP の取り出し（api ↔ web 共有。SEC1）。
//!
//! ヘッダの値は**クライアントが自由に付けられる**。リバースプロキシは通常それを消さず、
//! 自分が見た接続元を末尾へ**追記**する（nginx の `$proxy_add_x_forwarded_for` がまさにこれ）。
//! したがって
//!
//! ```text
//! X-Forwarded-For: 198.51.100.9, 203.0.113.7
//!                  ^^^^^^^^^^^^  ^^^^^^^^^^^^
//!                  クライアントが  信頼するプロキシが
//!                  名乗った値      実際に見た接続元
//! ```
//!
//! となり、**先頭の値を採ると攻撃者の申告をそのまま信じることになる**（リクエストごとに変えれば
//! IP 単位のレート制限を素通りでき、監査ログの IP も任意に汚せる）。本モジュールは常に
//! **最右の値**、すなわち信頼境界の直前ホップが観測した接続元を採る。
//!
//! # 信頼するホップは 1 段と仮定する
//!
//! 本 IdP の配置（`docker/nginx.conf`・`docker/nginx.domain-split.conf`）はプロキシ 1 段である。
//! 多段（CDN → プロキシ → api/web）にすると最右は「前段プロキシの IP」になり、利用者の実 IP では
//! なくなる。**精度は落ちるが偽装はされない**方向の失敗なので、安全側として受け入れる
//! （実 IP が要るなら CDN 側で `X-Forwarded-For` を上書きするか、段数を設定化する）。
//!
//! なお同梱の nginx は `X-Forwarded-For` を `$remote_addr` で**上書き**するようにしてあり、
//! そもそも値は 1 つしか載らない。本関数はプロキシ設定を差し替えた配置でも壊れないための
//! 二重目の防御線である。

/// `X-Forwarded-For` ヘッダ（複数ヘッダ可）から接続元 IP を取り出す。
///
/// 信頼境界の直前ホップが追記した**最右の非空値**を返す。値が無い・空白のみなら `None`
/// （呼び出し側は TCP 接続元へフォールバックする）。
///
/// 値の妥当性（IP として parse できるか）は検証しない。監査ログ・レート制限のキーとして
/// 使うだけであり、信頼するプロキシが書いた値を字句的に選ぶことが本関数の責務である。
pub fn client_ip<'a>(raw_headers: impl IntoIterator<Item = &'a str>) -> Option<String> {
    raw_headers
        .into_iter()
        .flat_map(|raw| raw.split(','))
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .last()
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn takes_the_hop_appended_by_the_trusted_proxy() {
        // nginx の `$proxy_add_x_forwarded_for` はクライアント申告を残して自分が見た接続元を
        // 追記する。攻撃者が先頭へ何を書いても、採るのは最右（プロキシが観測した値）。
        assert_eq!(
            client_ip(["198.51.100.9, 203.0.113.7"]).as_deref(),
            Some("203.0.113.7")
        );
        assert_eq!(client_ip(["203.0.113.7"]).as_deref(), Some("203.0.113.7"));
    }

    #[test]
    fn ignores_blank_entries() {
        assert_eq!(
            client_ip(["198.51.100.9, 203.0.113.7, "]).as_deref(),
            Some("203.0.113.7")
        );
        assert_eq!(client_ip(["   "]), None);
        assert_eq!(client_ip([","]), None);
        assert_eq!(client_ip(std::iter::empty::<&str>()), None);
    }

    #[test]
    fn spans_repeated_headers() {
        // ヘッダが複数本に分かれても、全体の最右がプロキシの追記分になる。
        assert_eq!(
            client_ip(["198.51.100.9", "203.0.113.7"]).as_deref(),
            Some("203.0.113.7")
        );
    }
}
