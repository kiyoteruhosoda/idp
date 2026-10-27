//! quick-xml のイベントから文字列を取り出す共通部品。
//!
//! quick-xml 0.38 から、テキスト中の実体参照（`&amp;`・`&#xD;` など）は `Event::Text` に含まれず、
//! 別のイベント `Event::GeneralRef` に割れて届く。`a &amp; b` は `Text("a ")`・`GeneralRef("amp")`・
//! `Text(" b")` の 3 つになる。テキストを集める側は **両方を同じ入れ物へ足す**——`GeneralRef` を
//! `_ => {}` で読み捨てると、参照の分だけ文字が黙って欠ける（署名の正準形なら別のバイト列になる）。
//!
//! 文字列の正規化は XML 1.0 の構文解析器と同じにする（正準化は「構文解析した後の文書」に対して
//! 定義されているため）:
//!
//! - テキストの改行は `\r\n`・`\r` を `\n` に揃える（XML 1.0 §2.11）。文字参照 `&#xD;` で書かれた
//!   CR は揃えない（参照は別イベントで来るので、ここを通らない）
//! - 属性値は空白（`\t`・`\n`・`\r`）を空白 1 つに置き換え、参照を解決する（XML 1.0 §3.3.3）

use quick_xml::escape::{resolve_predefined_entity, EscapeError};
use quick_xml::events::attributes::Attribute;
use quick_xml::events::{BytesRef, BytesText};
use quick_xml::XmlVersion;
use std::borrow::Cow;

/// テキストイベントの中身（改行を揃えた後）。
pub(crate) fn text<'a>(e: &BytesText<'a>) -> Result<Cow<'a, str>, quick_xml::Error> {
    Ok(e.xml10_content())
}

/// 実体参照イベントが表す文字。定義済みの 5 つ（`lt`・`gt`・`amp`・`apos`・`quot`）と文字参照
/// だけを受け付け、それ以外（DTD で宣言する実体）はエラーにする——DTD は読まないので、
/// 中身の分からない参照を空文字として通さない。
pub(crate) fn general_ref(e: &BytesRef<'_>) -> Result<Cow<'static, str>, quick_xml::Error> {
    if let Some(ch) = e.resolve_char_ref()? {
        return Ok(Cow::Owned(ch.to_string()));
    }
    let name: &str = e;
    match resolve_predefined_entity(name) {
        Some(resolved) => Ok(Cow::Borrowed(resolved)),
        None => Err(EscapeError::UnrecognizedEntity(0..name.len(), name.to_string()).into()),
    }
}

/// 属性値（参照を解決し、空白を正規化した後）。
pub(crate) fn attribute_value<'a>(attr: &Attribute<'a>) -> Result<Cow<'a, str>, quick_xml::Error> {
    attr.normalized_value(XmlVersion::Implicit1_0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;

    /// 要素の中身を、テキストと参照を足し合わせて読む。
    fn element_text(xml: &str) -> Result<String, quick_xml::Error> {
        let mut reader = Reader::from_str(xml);
        let mut out = String::new();
        loop {
            match reader.read_event()? {
                Event::Text(e) => out.push_str(&text(&e)?),
                Event::GeneralRef(e) => out.push_str(&general_ref(&e)?),
                Event::Eof => break,
                _ => {}
            }
        }
        Ok(out)
    }

    #[test]
    fn predefined_and_character_references_are_resolved() {
        assert_eq!(
            element_text("<a>x &amp; &lt;y&gt; &quot;&apos; &#65;&#x42;</a>").unwrap(),
            "x & <y> \"' AB"
        );
    }

    #[test]
    fn line_breaks_are_normalized_but_a_referenced_cr_is_kept() {
        assert_eq!(element_text("<a>1\r\n2\r3&#xD;</a>").unwrap(), "1\n2\n3\r");
    }

    #[test]
    fn an_undeclared_entity_is_rejected() {
        assert!(element_text("<a>&nbsp;</a>").is_err());
    }

    #[test]
    fn attribute_whitespace_is_normalized_and_references_resolved() {
        let mut reader = Reader::from_str("<a v=\"x\ty\nz &amp; &#x9;\"/>");
        let Event::Empty(e) = reader.read_event().unwrap() else {
            panic!("expected an empty element");
        };
        let attr = e.attributes().next().unwrap().unwrap();
        assert_eq!(attribute_value(&attr).unwrap(), "x y z & \t");
    }
}
