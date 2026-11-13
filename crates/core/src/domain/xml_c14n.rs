//! Exclusive canonicalization (Exclusive XML Canonicalization 1.0, `http://www.w3.org/2001/10/xml-exc-c14n#`).
//!
//! XML signatures are made over "the byte sequence of the canonicalized subtree". The side **verifying received XML**
//! cannot check signatures unless it can turn arbitrary XML made by the other party into canonical form (the generating
//! side can just build canonical form from the start, but that only works for XML we make; [`crate::domain::saml_response`]).
//!
//! Only the combinations a SAML SP needs are supported:
//!
//! - Exclusive canonicalization (supports `PrefixList` of `InclusiveNamespaces`)
//! - Comments are not output (the non-`#WithComments` variant)
//! - The enveloped signature transform (removes the `ds:Signature` directly under the target element from the output)
//!
//! # What "exclusive" means
//!
//! Regular canonicalization writes every namespace declared in ancestors at the top of the subtree. Exclusive canonicalization
//! writes only prefixes **actually used in that subtree**. So moving the subtree into another document does not
//! change its bytes -- SAML assertions are carried inside a Response or stored on their own,
//! so this property is needed.
//!
//! "Visibly utilized" means the element's own prefix and the prefixes of its attributes.
//! QNames written inside attribute values or text (e.g. `xsi:type="saml:Foo"`) are **not visible**, so
//! `PrefixList` provides a way to include them explicitly for consumers that use them.
//!
//! # Documents with multiple elements sharing the same `ID` are rejected
//!
//! A document where the signature reference (`Reference URI="#x"`) does not resolve uniquely is itself a foothold for
//! signature wrapping (XSW). Scanning does not stop at finding the target element; **counting over the whole document**,
//! more than one is an error.

use crate::domain::error::{DomainError, Result};
use crate::domain::xml_text;
use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;

/// XML signature namespace.
pub const NS_XMLDSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
/// Algorithm identifier of exclusive canonicalization.
pub const ALGORITHM_EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
/// The `xml` prefix may be used without declaration (XML Namespaces spec). Don't look for a declaration.
const XML_NAMESPACE: &str = "http://www.w3.org/XML/1998/namespace";

/// What to canonicalize. Both start from "the element whose `ID` attribute matches" (an enveloped signature is
/// placed inside the signed target, so once the target element is fixed, so is the signature).
#[derive(Debug, Clone, Copy)]
pub enum Target<'a> {
    /// The element with the matching `ID`. Its **direct child** `ds:Signature` is not output (enveloped transform).
    SignedElement(&'a str),
    /// `ds:SignedInfo` inside the `ds:Signature` directly under the element above.
    SignedInfoOf(&'a str),
}

/// Namespaces already output (the "rendered" set of exclusive canonicalization).
#[derive(Default, Clone)]
struct Rendered(Vec<(String, String)>);

impl Rendered {
    fn get(&self, prefix: &str) -> Option<&str> {
        self.0
            .iter()
            .rev()
            .find(|(p, _)| p == prefix)
            .map(|(_, u)| u.as_str())
    }

    fn set(&mut self, prefix: &str, uri: &str) {
        self.0.push((prefix.to_string(), uri.to_string()));
    }
}

/// Turns the given subtree into exclusive canonical form bytes.
///
/// `inclusive_prefixes` is `InclusiveNamespaces/@PrefixList` (split on whitespace).
/// `#default` stands for the default namespace.
pub fn canonicalize(
    xml: &str,
    target: Target<'_>,
    inclusive_prefixes: &[String],
) -> Result<Vec<u8>> {
    let mut walker = Walker::new(xml, target, inclusive_prefixes);
    walker.run()?;
    if walker.matches == 0 {
        return Err(DomainError::InvalidValue(format!(
            "no element carries the referenced ID `{}`",
            walker.target_id()
        )));
    }
    if walker.matches > 1 {
        return Err(DomainError::InvalidValue(format!(
            "more than one element carries the referenced ID `{}`",
            walker.target_id()
        )));
    }
    if walker.direct_signatures > 1 {
        return Err(DomainError::InvalidValue(
            "the signed element carries more than one enveloped signature".to_string(),
        ));
    }
    if !walker.emitted {
        return Err(DomainError::InvalidValue(
            "the element to canonicalize was not found".to_string(),
        ));
    }
    Ok(walker.out)
}

struct Walker<'a> {
    reader: Reader<&'a [u8]>,
    target: Target<'a>,
    inclusive_prefixes: &'a [String],
    /// Namespace stack for the whole document (1 entry = (prefix, URI) pairs declared on that element).
    scopes: Vec<Vec<(String, String)>>,
    /// Rendered stack during output (only inside the subtree).
    rendered: Vec<Rendered>,
    /// Element name stack during output (for writing end tags).
    open_names: Vec<String>,
    out: Vec<u8>,
    /// Depth entered into the output subtree (`None` if not yet entered or already left).
    emitting_from: Option<usize>,
    /// Depth entered into a subtree removed from the output.
    skipping_from: Option<usize>,
    /// Depth of the `ID`-matching element (the first one).
    matched_depth: Option<usize>,
    /// Depth of the `ds:Signature` directly under the target element.
    signature_depth: Option<usize>,
    /// Number of elements whose `ID` matched (whole document).
    matches: usize,
    /// Number of `ds:Signature` found directly under the target element.
    direct_signatures: usize,
    depth: usize,
    /// Whether anything was ever output (whether the target was found).
    emitted: bool,
}

impl<'a> Walker<'a> {
    fn new(xml: &'a str, target: Target<'a>, inclusive_prefixes: &'a [String]) -> Self {
        let mut reader = Reader::from_reader(xml.as_bytes());
        reader.config_mut().trim_text(false);
        reader.config_mut().check_end_names = true;
        Self {
            reader,
            target,
            inclusive_prefixes,
            scopes: Vec::new(),
            rendered: Vec::new(),
            open_names: Vec::new(),
            out: Vec::new(),
            emitting_from: None,
            skipping_from: None,
            matched_depth: None,
            signature_depth: None,
            matches: 0,
            direct_signatures: 0,
            depth: 0,
            emitted: false,
        }
    }

    fn target_id(&self) -> &str {
        match self.target {
            Target::SignedElement(id) | Target::SignedInfoOf(id) => id,
        }
    }

    fn run(&mut self) -> Result<()> {
        let mut buf = Vec::new();
        loop {
            let event = self
                .reader
                .read_event_into(&mut buf)
                .map_err(|e| DomainError::InvalidValue(format!("malformed XML: {e}")))?;
            match event {
                Event::Eof => break,
                Event::Start(e) => {
                    let owned = e.into_owned();
                    self.on_start(&owned)?;
                }
                Event::Empty(e) => {
                    // An empty-element tag becomes a start/end tag pair in canonical form.
                    let owned = e.into_owned();
                    self.on_start(&owned)?;
                    self.on_end();
                }
                Event::End(_) => self.on_end(),
                Event::Text(e) => {
                    if self.is_emitting() {
                        let text = xml_text::text(&e)
                            .map_err(|err| DomainError::InvalidValue(format!("bad text: {err}")))?;
                        escape_text(&text, &mut self.out);
                    }
                }
                // Entity references are written as the resolved characters (canonical form keeps no references).
                Event::GeneralRef(e) => {
                    if self.is_emitting() {
                        let text = xml_text::general_ref(&e)
                            .map_err(|err| DomainError::InvalidValue(format!("bad text: {err}")))?;
                        escape_text(&text, &mut self.out);
                    }
                }
                Event::CData(e) => {
                    if self.is_emitting() {
                        // CDATA is written as regular text in canonical form.
                        escape_text(&e.into_inner(), &mut self.out);
                    }
                }
                // Comments are not output (not `#WithComments`). Same for declarations and DOCTYPE.
                Event::Comment(_) | Event::Decl(_) | Event::DocType(_) => {}
                Event::PI(e) => {
                    if self.is_emitting() {
                        self.out.extend_from_slice(b"<?");
                        self.out.extend_from_slice(e.into_inner().as_bytes());
                        self.out.extend_from_slice(b"?>");
                    }
                }
            }
            buf.clear();
        }
        Ok(())
    }

    fn is_emitting(&self) -> bool {
        self.emitting_from.is_some() && self.skipping_from.is_none()
    }

    fn on_start(&mut self, e: &BytesStart<'_>) -> Result<()> {
        self.scopes.push(collect_namespace_declarations(e)?);
        self.depth += 1;
        let depth = self.depth;

        let (prefix, local) = split_name(e.name().as_ref())?;
        let in_dsig = self.resolve(&prefix).as_deref() == Some(NS_XMLDSIG);

        // Target element (`ID` match). Scanning continues after finding it, counting over the whole document.
        if let Some(id) = element_id(e)? {
            if id == self.target_id() {
                self.matches += 1;
                if self.matched_depth.is_none() {
                    self.matched_depth = Some(depth);
                    if matches!(self.target, Target::SignedElement(_)) {
                        self.begin_emitting();
                    }
                }
            }
        }

        // The `ds:Signature` directly under the target element (enveloped signature).
        if in_dsig && local == "Signature" && self.matched_depth == Some(depth - 1) {
            self.direct_signatures += 1;
            if self.signature_depth.is_none() {
                self.signature_depth = Some(depth);
            }
            if matches!(self.target, Target::SignedElement(_))
                && self.skipping_from.is_none()
                && self.emitting_from.is_some()
            {
                self.skipping_from = Some(depth);
            }
        }

        // The `ds:SignedInfo` directly under that `ds:Signature`.
        if in_dsig
            && local == "SignedInfo"
            && matches!(self.target, Target::SignedInfoOf(_))
            && self.signature_depth == Some(depth - 1)
            && self.emitting_from.is_none()
            && !self.emitted
        {
            self.begin_emitting();
        }

        if self.is_emitting() {
            self.emit_start(e, &prefix)?;
        }
        Ok(())
    }

    fn begin_emitting(&mut self) {
        self.emitting_from = Some(self.depth);
        self.emitted = true;
        self.rendered.clear();
        self.rendered.push(Rendered::default());
        self.open_names.clear();
    }

    fn on_end(&mut self) {
        let depth = self.depth;
        if self.is_emitting() {
            if let Some(name) = self.open_names.pop() {
                self.rendered.pop();
                self.out.extend_from_slice(b"</");
                self.out.extend_from_slice(name.as_bytes());
                self.out.push(b'>');
            }
        }
        if self.skipping_from == Some(depth) {
            self.skipping_from = None;
        }
        if self.emitting_from == Some(depth) {
            self.emitting_from = None;
        }
        self.scopes.pop();
        self.depth -= 1;
    }

    /// Resolves a prefix (`""` = default namespace) to a URI. Undeclaring the default namespace (`xmlns=""`)
    /// is treated as `None`, not `Some("")`.
    fn resolve(&self, prefix: &str) -> Option<String> {
        if prefix == "xml" {
            return Some(XML_NAMESPACE.to_string());
        }
        for scope in self.scopes.iter().rev() {
            for (p, uri) in scope.iter().rev() {
                if p == prefix {
                    return if uri.is_empty() {
                        None
                    } else {
                        Some(uri.clone())
                    };
                }
            }
        }
        None
    }

    fn emit_start(&mut self, e: &BytesStart<'_>, prefix: &str) -> Result<()> {
        let qname = e.name().as_ref().to_string();
        let mut rendered = self.rendered.last().cloned().unwrap_or_default();

        // 1. Namespace declarations to output (visibly utilized prefixes + PrefixList).
        //    `xml` can be used without declaration, so it is not output.
        let mut wanted: Vec<String> = Vec::new();
        if prefix != "xml" {
            wanted.push(prefix.to_string());
        }
        for attr in e.attributes() {
            let attr =
                attr.map_err(|err| DomainError::InvalidValue(format!("bad attribute: {err}")))?;
            let (ap, al) = split_name(attr.key.as_ref())?;
            if ap == "xmlns" || (ap.is_empty() && al == "xmlns") || ap == "xml" {
                continue;
            }
            if !ap.is_empty() {
                wanted.push(ap);
            }
        }
        let default_is_inclusive = self.inclusive_prefixes.iter().any(|v| v == "#default");
        for p in self.inclusive_prefixes {
            if p == "#default" {
                wanted.push(String::new());
            } else if p != "xml" {
                wanted.push(p.clone());
            }
        }

        let mut declarations: Vec<(String, String)> = Vec::new();
        for p in &wanted {
            if p.is_empty() {
                // The default namespace is "used" only when the element itself has no prefix.
                if !prefix.is_empty() && !default_is_inclusive {
                    continue;
                }
                let uri = self.resolve("").unwrap_or_default();
                if rendered.get("").unwrap_or("") != uri {
                    declarations.push((String::new(), uri.clone()));
                    rendered.set("", &uri);
                }
                continue;
            }
            let Some(uri) = self.resolve(p) else {
                // It is normal for PrefixList to list prefixes not declared in this subtree, so
                // skip them. Undeclared prefixes actually used by elements/attributes are rejected below.
                if self.inclusive_prefixes.iter().any(|v| v == p) && p != prefix {
                    continue;
                }
                return Err(DomainError::InvalidValue(format!(
                    "namespace prefix `{p}` is not declared"
                )));
            };
            if rendered.get(p) != Some(uri.as_str()) {
                declarations.push((p.clone(), uri.clone()));
                rendered.set(p, &uri);
            }
        }
        declarations.sort_by(|a, b| a.0.cmp(&b.0));
        declarations.dedup_by(|a, b| a.0 == b.0);

        // 2. Attributes in lexicographic order of (namespace URI, local name). Unprefixed attributes belong to no namespace
        //    (empty URI), so they come first.
        let mut attributes: Vec<(String, String, String, String)> = Vec::new();
        for attr in e.attributes() {
            let attr =
                attr.map_err(|err| DomainError::InvalidValue(format!("bad attribute: {err}")))?;
            let (ap, al) = split_name(attr.key.as_ref())?;
            if ap == "xmlns" || (ap.is_empty() && al == "xmlns") {
                continue;
            }
            let uri = if ap.is_empty() {
                String::new()
            } else {
                self.resolve(&ap).ok_or_else(|| {
                    DomainError::InvalidValue(format!("namespace prefix `{ap}` is not declared"))
                })?
            };
            let key = attr.key.as_ref().to_string();
            let value = xml_text::attribute_value(&attr)
                .map_err(|err| DomainError::InvalidValue(format!("bad attribute value: {err}")))?
                .into_owned();
            attributes.push((uri, al, key, value));
        }
        attributes.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

        // 3. Write out.
        self.out.push(b'<');
        self.out.extend_from_slice(qname.as_bytes());
        for (p, uri) in &declarations {
            self.out.extend_from_slice(b" xmlns");
            if !p.is_empty() {
                self.out.push(b':');
                self.out.extend_from_slice(p.as_bytes());
            }
            self.out.extend_from_slice(b"=\"");
            escape_attribute(uri, &mut self.out);
            self.out.push(b'"');
        }
        for (_, _, key, value) in &attributes {
            self.out.push(b' ');
            self.out.extend_from_slice(key.as_bytes());
            self.out.extend_from_slice(b"=\"");
            escape_attribute(value, &mut self.out);
            self.out.push(b'"');
        }
        self.out.push(b'>');

        self.rendered.push(rendered);
        self.open_names.push(qname);
        Ok(())
    }
}

/// Canonical escaping of attribute values (C14N 1.0 §Attribute Nodes).
fn escape_attribute(value: &str, out: &mut Vec<u8>) {
    for ch in value.chars() {
        match ch {
            '&' => out.extend_from_slice(b"&amp;"),
            '<' => out.extend_from_slice(b"&lt;"),
            '"' => out.extend_from_slice(b"&quot;"),
            '\t' => out.extend_from_slice(b"&#x9;"),
            '\n' => out.extend_from_slice(b"&#xA;"),
            '\r' => out.extend_from_slice(b"&#xD;"),
            other => push_char(other, out),
        }
    }
}

/// Canonical escaping of text nodes (C14N 1.0 §Text Nodes).
fn escape_text(value: &str, out: &mut Vec<u8>) {
    for ch in value.chars() {
        match ch {
            '&' => out.extend_from_slice(b"&amp;"),
            '<' => out.extend_from_slice(b"&lt;"),
            '>' => out.extend_from_slice(b"&gt;"),
            '\r' => out.extend_from_slice(b"&#xD;"),
            other => push_char(other, out),
        }
    }
}

fn push_char(ch: char, out: &mut Vec<u8>) {
    let mut buf = [0u8; 4];
    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
}

/// Collects namespaces declared on an element.
fn collect_namespace_declarations(e: &BytesStart<'_>) -> Result<Vec<(String, String)>> {
    let mut declared = Vec::new();
    for attr in e.attributes() {
        let attr =
            attr.map_err(|err| DomainError::InvalidValue(format!("bad attribute: {err}")))?;
        let (prefix, local) = split_name(attr.key.as_ref())?;
        let is_declaration = (prefix.is_empty() && local == "xmlns") || prefix == "xmlns";
        if !is_declaration {
            continue;
        }
        let value = xml_text::attribute_value(&attr)
            .map_err(|err| DomainError::InvalidValue(format!("bad attribute value: {err}")))?
            .into_owned();
        if prefix.is_empty() {
            declared.push((String::new(), value));
        } else {
            declared.push((local, value));
        }
    }
    Ok(declared)
}

/// `ID`-typed attribute value (SAML uses `ID`, XMLDSIG `Id`). Prefixed attributes are ignored.
fn element_id(e: &BytesStart<'_>) -> Result<Option<String>> {
    for attr in e.attributes() {
        let attr =
            attr.map_err(|err| DomainError::InvalidValue(format!("bad attribute: {err}")))?;
        let (prefix, local) = split_name(attr.key.as_ref())?;
        if !prefix.is_empty() {
            continue;
        }
        if local == "ID" || local == "Id" || local == "id" {
            let value = xml_text::attribute_value(&attr)
                .map_err(|err| DomainError::InvalidValue(format!("bad attribute value: {err}")))?;
            return Ok(Some(value.into_owned()));
        }
    }
    Ok(None)
}

/// Splits `prefix:local` (empty string if there is no prefix).
fn split_name(name: &str) -> Result<(String, String)> {
    Ok(match name.split_once(':') {
        Some((p, l)) => (p.to_string(), l.to_string()),
        None => (String::new(), name.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c14n(xml: &str, target: Target<'_>) -> String {
        String::from_utf8(canonicalize(xml, target, &[]).expect("canonicalize")).unwrap()
    }

    /// Of the namespaces declared in ancestors, writes **only those used** in the subtree.
    #[test]
    fn only_visibly_utilized_namespaces_are_rendered() {
        let xml = r#"<r xmlns:a="urn:a" xmlns:b="urn:b"><a:e ID="x"><a:c/></a:e></r>"#;
        assert_eq!(
            c14n(xml, Target::SignedElement("x")),
            r#"<a:e xmlns:a="urn:a" ID="x"><a:c></a:c></a:e>"#
        );
    }

    /// Entity and character references are resolved, then rewritten per canonical-form rules. No referenced characters are dropped.
    /// `\r\n` line breaks become `\n` at parse time; only CRs written as references remain as `&#xD;`.
    #[test]
    fn references_are_resolved_and_re_escaped() {
        let xml =
            "<e ID=\"x\" a=\"1&#9;2&#10;3 &quot;&amp;\">p &amp; q &lt; r &gt; &#x41;&#xD;\r\ns</e>";
        assert_eq!(
            c14n(xml, Target::SignedElement("x")),
            "<e ID=\"x\" a=\"1&#x9;2&#xA;3 &quot;&amp;\">p &amp; q &lt; r &gt; A&#xD;\ns</e>"
        );
    }

    /// An empty-element tag becomes a start/end tag pair. Attributes in (namespace, local name) order.
    #[test]
    fn empty_tags_expand_and_attributes_are_sorted() {
        let xml = r#"<e ID="x" xmlns:z="urn:z" b="2" a="1" z:k="3"/>"#;
        assert_eq!(
            c14n(xml, Target::SignedElement("x")),
            r#"<e xmlns:z="urn:z" ID="x" a="1" b="2" z:k="3"></e>"#
        );
    }

    /// The default namespace is written only on unprefixed elements. `xmlns=""` if undeclared in an ancestor.
    #[test]
    fn the_default_namespace_follows_the_element_prefix() {
        let xml = r#"<r xmlns="urn:d"><e ID="x"><f xmlns=""><g/></f></e></r>"#;
        assert_eq!(
            c14n(xml, Target::SignedElement("x")),
            r#"<e xmlns="urn:d" ID="x"><f xmlns=""><g></g></f></e>"#
        );
    }

    /// Enveloped transform: the `ds:Signature` directly under the target element is not output.
    #[test]
    fn the_enveloped_signature_is_removed_from_the_signed_element() {
        let xml = concat!(
            r#"<e xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="x">"#,
            r#"<ds:Signature><ds:SignedInfo>si</ds:SignedInfo></ds:Signature><d>keep</d></e>"#
        );
        let out = c14n(xml, Target::SignedElement("x"));
        assert!(!out.contains("Signature"), "{out}");
        assert!(out.contains("<d>keep</d>"), "{out}");
    }

    /// `SignedInfo` is taken only from inside the `ds:Signature` directly under the target element.
    #[test]
    fn signed_info_is_taken_from_the_enveloped_signature() {
        let xml = concat!(
            r#"<e xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="x"><ds:Signature>"#,
            r##"<ds:SignedInfo><ds:Reference URI="#x"></ds:Reference></ds:SignedInfo>"##,
            r#"</ds:Signature></e>"#
        );
        assert_eq!(
            c14n(xml, Target::SignedInfoOf("x")),
            r##"<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:Reference URI="#x"></ds:Reference></ds:SignedInfo>"##
        );
    }

    /// Documents with 2 elements sharing the same `ID` are rejected (reference not unique = XSW foothold).
    #[test]
    fn duplicate_ids_are_rejected() {
        let xml = r#"<r><e ID="x"><q/></e><e ID="x"><q/></e></r>"#;
        assert!(canonicalize(xml, Target::SignedElement("x"), &[]).is_err());
    }

    /// Escaping of text and attribute values follows canonical-form rules (`>` only in text, `"` only in attributes).
    #[test]
    fn escaping_follows_the_canonical_rules() {
        let xml = r#"<e ID="x" a="&quot;&amp;&lt;&#9;">a &amp; b &gt; c</e>"#;
        assert_eq!(
            c14n(xml, Target::SignedElement("x")),
            "<e ID=\"x\" a=\"&quot;&amp;&lt;&#x9;\">a &amp; b &gt; c</e>"
        );
    }

    /// Prefixes listed in `PrefixList` are written even if not visibly used.
    #[test]
    fn inclusive_prefixes_are_rendered_even_when_not_visibly_utilized() {
        let xml = r#"<r xmlns:xs="urn:xs"><e ID="x">v</e></r>"#;
        let out = canonicalize(
            xml,
            Target::SignedElement("x"),
            &["xs".to_string(), "missing".to_string()],
        )
        .expect("canonicalize");
        assert_eq!(
            String::from_utf8(out).unwrap(),
            r#"<e xmlns:xs="urn:xs" ID="x">v</e>"#
        );
    }
}
