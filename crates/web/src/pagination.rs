//! 一覧画面のページャ（前後リンク）の組み立て（G7）。
//!
//! ページングそのものは api（DB）側が行い、web は「今どこを見ているか」をクエリ文字列で
//! 引き継いで前後リンクを描くだけである。判定規則（次ページの有無・オーバーフロー対策）は
//! 一覧ごとに複製せず本モジュールへ集約する。

/// ページャの前後リンク。該当が無ければ `None`。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PagerLinks {
    pub prev: Option<String>,
    pub next: Option<String>,
}

/// 前後リンクを組み立てる。
///
/// - `base`: クエリ文字列を除いた遷移先（例 `/{tenant}/admin/clients`）
/// - `extra`: `offset` 以外に引き継ぐクエリ（絞り込み語など。値はここでエンコードする）
/// - `offset` / `limit`: **api が実際に適用した**位置と刻み幅
/// - `total`: 絞り込み後の総件数
///
/// 次ページの有無は**総件数**で判定する。受信件数が `limit` に満たないかどうかで判定すると、
/// 最終ページがちょうど埋まったときに空ページへのリンクが出る。
pub fn pager_links(
    base: &str,
    extra: &[(&str, &str)],
    offset: i64,
    limit: i64,
    total: i64,
) -> PagerLinks {
    // limit は api が適用した値。0 以下が返ることは無いが、加算の安全側として弾く。
    let limit = limit.max(1);
    let offset = offset.max(0);
    // `offset` はクエリ由来（`?offset=9223372036854775807` も来る）。素の加算は debug ビルドで
    // オーバーフロー panic、release ビルドでは負の値へ回り込んで不正な「次へ」リンクになるため、
    // 飽和加算にする。飽和した値は `total` 未満にならないので「次へ」は出ない（意図どおり）。
    let next_offset = offset.saturating_add(limit);
    PagerLinks {
        prev: (offset > 0).then(|| href(base, extra, (offset - limit).max(0))),
        next: (next_offset < total).then(|| href(base, extra, next_offset)),
    }
}

fn href(base: &str, extra: &[(&str, &str)], offset: i64) -> String {
    let mut query = format!("offset={offset}");
    for (key, value) in extra {
        if value.is_empty() {
            continue;
        }
        query.push_str(&format!("&{}={}", urlencode(key), urlencode(value)));
    }
    format!("{base}?{query}")
}

/// クエリ文字列へ載せる値のパーセントエンコード（RFC 3986 の unreserved 以外を変換する）。
pub fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// api へ渡すページングクエリ。`offset` は常に載せ、既定で足りる `limit` は載せない
/// （上限・既定値の決定は api 側の責務。web が二重に持たない）。
pub fn page_query(offset: i64) -> Vec<(&'static str, String)> {
    vec![("offset", offset.max(0).to_string())]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_page_has_no_previous_link() {
        let links = pager_links("/t/admin/clients", &[], 0, 50, 120);
        assert_eq!(links.prev, None);
        assert_eq!(links.next.as_deref(), Some("/t/admin/clients?offset=50"));
    }

    /// 最終ページがちょうど `limit` 件で埋まっても「次へ」を出さない（総件数で判定するため）。
    #[test]
    fn a_full_last_page_does_not_offer_a_next_link() {
        let links = pager_links("/t/admin/clients", &[], 50, 50, 100);
        assert_eq!(links.prev.as_deref(), Some("/t/admin/clients?offset=0"));
        assert_eq!(links.next, None);
    }

    /// `offset` は利用者入力である。飽和加算で panic も回り込みも起こさない。
    #[test]
    fn a_saturating_offset_never_produces_a_next_link() {
        let links = pager_links("/t/admin/clients", &[], i64::MAX, 50, 100);
        assert_eq!(links.next, None);
        assert!(links.prev.is_some());
    }

    #[test]
    fn extra_query_values_are_percent_encoded_and_empty_ones_dropped() {
        let links = pager_links(
            "/t/admin/members",
            &[("q", "a b&c"), ("sort", "")],
            0,
            10,
            30,
        );
        assert_eq!(
            links.next.as_deref(),
            Some("/t/admin/members?offset=10&q=a%20b%26c")
        );
    }
}
