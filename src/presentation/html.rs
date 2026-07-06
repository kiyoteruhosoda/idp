//! サーバレンダリング画面へ値を埋め込む際の HTML エスケープ。
//!
//! 管理コンソール（A2 以降）は利用者・管理者が入力した文字列（アプリ名・redirect URI 等）を HTML へ
//! 差し込む。格納型 XSS を防ぐため、テキストとして埋め込む値は必ず本関数を通す。属性値・要素本文の
//! 双方に安全な最小集合（`& < > " '`）を実体参照へ変換する。

/// HTML のテキスト／属性値へ安全に埋め込めるようエスケープする。
pub fn escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_html_metacharacters() {
        assert_eq!(
            escape("<script>alert(\"x\")&'</script>"),
            "&lt;script&gt;alert(&quot;x&quot;)&amp;&#x27;&lt;/script&gt;"
        );
    }

    #[test]
    fn leaves_plain_text_unchanged() {
        assert_eq!(
            escape("My App 42 https://a.example.com/cb"),
            "My App 42 https://a.example.com/cb"
        );
    }
}
