//! 一覧の分割取得（ページング）の共通語彙（G7）。
//!
//! 管理 API の一覧は、テナントの規模に比例して応答が膨らまないよう **1 ページ分と総件数**を返す。
//! ここで定義するのは「何件目から何件」（[`PageRequest`]）と「1 ページ分＋総件数」（[`Page`]）の
//! 二つだけで、絞り込み条件は一覧ごとに固有のため各ドメイン型（例
//! [`crate::domain::tenant_membership::TenantMemberFilter`]）が持つ。
//!
//! クランプ（既定値・上限）は Application 層ではなく本型に置く。Presentation 層が上限を
//! 知らずに済み、同じ規則が複数の一覧へ複製されない。

/// 取得範囲。`limit` は 1 以上、`offset` は 0 以上であることを構築時に保証する
/// （フィールドを直接組み立てられないよう [`PageRequest::clamped`] を唯一の入口にする）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageRequest {
    limit: i64,
    offset: i64,
}

impl PageRequest {
    /// 未検証の要求値（クエリ文字列由来）を許容範囲へ収める。
    ///
    /// - `limit`: 未指定・0 以下は `default`、`max` を超えたら `max`
    /// - `offset`: 未指定・負値は 0
    pub fn clamped(limit: Option<i64>, offset: Option<i64>, default: i64, max: i64) -> Self {
        let limit = match limit {
            Some(l) if l > 0 => l.min(max),
            _ => default,
        };
        Self {
            limit,
            offset: offset.unwrap_or(0).max(0),
        }
    }

    /// 実際に適用する取得件数（1 以上）。
    pub fn limit(&self) -> i64 {
        self.limit
    }

    /// 実際に適用する読み飛ばし件数（0 以上）。
    pub fn offset(&self) -> i64 {
        self.offset
    }
}

/// 1 ページ分の要素と、同じ絞り込み条件での総件数。
///
/// 総件数を返すのは、呼び出し側が「次ページの有無」を**受信件数では判定できない**ため
/// （最終ページがちょうど `limit` 件で埋まると、空ページへのリンクが出る）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub total: i64,
}

impl<T> Page<T> {
    pub fn new(items: Vec<T>, total: i64) -> Self {
        Self { items, total }
    }

    /// 全件を持つ `Vec` から 1 ページ分を切り出す。DB 側で `LIMIT`/`OFFSET` を書けない
    /// 実装（インメモリのテスト用フェイク）のための補助で、本番の sqlx 実装は使わない。
    pub fn from_all(all: Vec<T>, request: PageRequest) -> Self {
        let total = all.len() as i64;
        let items = all
            .into_iter()
            .skip(request.offset().max(0) as usize)
            .take(request.limit().max(0) as usize)
            .collect();
        Self { items, total }
    }
}

/// 1 ページ分の結果に、**実際に適用した**取得範囲を添えたもの。
///
/// 呼び出し側（Presentation・web のページャ）は要求値ではなくこちらを使う。クランプ規則を
/// 上位層へ複製せずに済み、「`limit=10000` を要求したが 200 が適用された」ときも
/// ページ送りが破綻しない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PagedResult<T> {
    pub page: Page<T>,
    pub applied: PageRequest,
}

impl<T> PagedResult<T> {
    pub fn new(page: Page<T>, applied: PageRequest) -> Self {
        Self { page, applied }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamps_limit_to_the_allowed_range() {
        assert_eq!(PageRequest::clamped(None, None, 50, 200).limit(), 50);
        assert_eq!(PageRequest::clamped(Some(0), None, 50, 200).limit(), 50);
        assert_eq!(PageRequest::clamped(Some(-1), None, 50, 200).limit(), 50);
        assert_eq!(PageRequest::clamped(Some(10), None, 50, 200).limit(), 10);
        assert_eq!(
            PageRequest::clamped(Some(10_000), None, 50, 200).limit(),
            200
        );
    }

    #[test]
    fn negative_offset_is_treated_as_the_first_page() {
        assert_eq!(PageRequest::clamped(None, Some(-5), 50, 200).offset(), 0);
        assert_eq!(PageRequest::clamped(None, Some(7), 50, 200).offset(), 7);
    }

    #[test]
    fn slicing_all_items_keeps_the_unfiltered_total() {
        let page = Page::from_all(
            vec![1, 2, 3, 4, 5],
            PageRequest::clamped(Some(2), Some(1), 50, 200),
        );
        assert_eq!(page.items, vec![2, 3]);
        assert_eq!(page.total, 5);
    }

    /// 範囲外の `offset` は空ページになるが、総件数は変わらない（画面が「前へ」を出せる）。
    #[test]
    fn offset_past_the_end_yields_an_empty_page() {
        let page = Page::from_all(
            vec![1, 2, 3],
            PageRequest::clamped(Some(2), Some(99), 50, 200),
        );
        assert!(page.items.is_empty());
        assert_eq!(page.total, 3);
    }
}
