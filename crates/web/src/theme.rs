//! 画面の配色設定（ライト / ダーク / OS に合わせる）。
//!
//! 決定順は表示言語（[`crate::display_preferences`]）と揃える。先勝ちで
//! `?theme=` > ユーザー設定（DB の `users.theme`）> Cookie(`theme`) > OS の設定。
//! 不正・非対応値は無視して次順位へ落ちる。
//!
//! **適用するのはブラウザ側**（`assets/theme.js` が `<html data-bs-theme>` を立てる）。
//! サーバが属性を書けないのは、共通レイアウト（`page.html` / `console/layout.html`）が
//! 全画面のテンプレート構造体から値を受け取る形になっておらず、40 近い構造体すべてに
//! 配色のフィールドを足すことになるためである。サーバは Cookie を正しく保つ役に徹する。

/// 利用者が選べる配色。`System` は「OS に合わせる」という**選択**であり、未選択とは区別する
/// （未選択なら端末の Cookie を尊重してよいが、`System` は端末をまたいで OS 追従を貫く）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Theme {
    Light,
    Dark,
    System,
}

impl Theme {
    /// 保存値（`light` / `dark` / `system`）から読む。非対応・不正値は `None`。
    pub fn from_tag(tag: &str) -> Option<Theme> {
        match tag.trim().to_ascii_lowercase().as_str() {
            "light" => Some(Theme::Light),
            "dark" => Some(Theme::Dark),
            "system" => Some(Theme::System),
            _ => None,
        }
    }

    /// Cookie・DB・フォームで使う保存値。
    pub fn as_tag(&self) -> &'static str {
        match self {
            Theme::Light => "light",
            Theme::Dark => "dark",
            Theme::System => "system",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_only_the_three_supported_values() {
        assert_eq!(Theme::from_tag("dark"), Some(Theme::Dark));
        assert_eq!(Theme::from_tag(" Light "), Some(Theme::Light));
        assert_eq!(Theme::from_tag("system"), Some(Theme::System));
        assert_eq!(Theme::from_tag("solarized"), None);
        assert_eq!(Theme::from_tag(""), None);
    }

    #[test]
    fn the_tag_round_trips() {
        for theme in [Theme::Light, Theme::Dark, Theme::System] {
            assert_eq!(Theme::from_tag(theme.as_tag()), Some(theme));
        }
    }
}
