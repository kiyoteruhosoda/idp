//! Shared helpers for extracting strings from quick-xml events.
//!
//! Since quick-xml 0.38, entity references in text (`&amp;`, `&#xD;`, etc.) are not part of `Event::Text`
//! but arrive split into a separate `Event::GeneralRef`. `a &amp; b` becomes `Text("a ")`, `GeneralRef("amp")`,
//! `Text(" b")`. Code collecting text must **add both to the same buffer** -- discarding `GeneralRef` with
//! `_ => {}` silently drops the referenced characters (for a signature's canonical form, a different byte sequence).
//!
//! String normalization matches an XML 1.0 parser (canonicalization is defined on "the document after
//! parsing"):
//!
//! - Line breaks in text: `\r\n` and `\r` become `\n` (XML 1.0 §2.11). A CR written as the character reference
//!   `&#xD;` is not normalized (references arrive as separate events and don't pass through here)
//! - Attribute values: whitespace (`\t`, `\n`, `\r`) becomes a single space and references are resolved (XML 1.0 §3.3.3)

use quick_xml::escape::{resolve_predefined_entity, EscapeError};
use quick_xml::events::attributes::Attribute;
use quick_xml::events::{BytesRef, BytesText};
use quick_xml::XmlVersion;
use std::borrow::Cow;

/// Content of a text event (after line-break normalization).
pub(crate) fn text<'a>(e: &BytesText<'a>) -> Result<Cow<'a, str>, quick_xml::Error> {
    Ok(e.xml10_content())
}

/// Character represented by an entity reference event. Accepts only the 5 predefined ones (`lt`, `gt`, `amp`, `apos`, `quot`)
/// and character references; anything else (entities declared in a DTD) is an error -- the DTD is not read, so
/// a reference of unknown content is not let through as an empty string.
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

/// Attribute value (after resolving references and normalizing whitespace).
pub(crate) fn attribute_value<'a>(attr: &Attribute<'a>) -> Result<Cow<'a, str>, quick_xml::Error> {
    attr.normalized_value(XmlVersion::Implicit1_0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;

    /// Reads an element's content, adding up text and references.
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
