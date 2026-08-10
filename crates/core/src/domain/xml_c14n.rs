//! 排他的正準化（Exclusive XML Canonicalization 1.0。`http://www.w3.org/2001/10/xml-exc-c14n#`）。
//!
//! XML 署名は「正準化した部分木のバイト列」に対して行う。**受け取った XML を検証する**側では、
//! 相手が作った任意の XML を正準形へ直せなければ署名を確かめられない（生成側は最初から正準形で
//! 組み立てれば済むが、それは自分が作る XML にしか使えない。[`crate::domain::saml_response`]）。
//!
//! 対応するのは SAML の SP に要る組み合わせだけ:
//!
//! - 排他的正準化（`InclusiveNamespaces` の `PrefixList` に対応）
//! - コメントは出力しない（`#WithComments` ではない方）
//! - enveloped signature 変換（対象要素の直下にある `ds:Signature` を出力から取り除く）
//!
//! # 排他的である、とは
//!
//! 通常の正準化は、祖先で宣言された名前空間をすべて部分木の先頭へ書き出す。排他的正準化は
//! **その部分木で実際に使われている**接頭辞だけを書き出す。だから部分木を別の文書へ移しても
//! バイト列が変わらない——SAML のアサーションは Response ごと運ばれたり単体で保存されたりする
//! ので、この性質が要る。
//!
//! 「実際に使われている（visibly utilized）」のは、要素自身の接頭辞と、その属性の接頭辞である。
//! 属性値やテキストの中に書かれた QName（例 `xsi:type="saml:Foo"`）は**見えない**ため、それを
//! 使う相手のために `PrefixList` で明示的に含める道が用意されている。
//!
//! # 同じ `ID` を持つ要素が複数ある文書は拒否する
//!
//! 署名参照（`Reference URI="#x"`）の解決先が一意でない文書は、署名ラッピング（XSW）の
//! 足がかりそのものである。対象要素を見つけても走査を止めず、**文書全体で数えて**複数なら
//! エラーにする。

use crate::domain::error::{DomainError, Result};
use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;

/// XML 署名の名前空間。
pub const NS_XMLDSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
/// 排他的正準化のアルゴリズム識別子。
pub const ALGORITHM_EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
/// `xml` 接頭辞は宣言せずに使える（XML 名前空間仕様）。宣言を探しにいかない。
const XML_NAMESPACE: &str = "http://www.w3.org/XML/1998/namespace";

/// 何を正準化するか。どちらも「`ID` 属性が一致する要素」を起点にする（enveloped signature は
/// 署名対象の中に置かれるため、対象要素が決まれば署名も決まる）。
#[derive(Debug, Clone, Copy)]
pub enum Target<'a> {
    /// `ID` が一致する要素。その**直下の** `ds:Signature` は出力しない（enveloped 変換）。
    SignedElement(&'a str),
    /// 上記要素の直下 `ds:Signature` の中の `ds:SignedInfo`。
    SignedInfoOf(&'a str),
}

/// 出力済みの名前空間（排他的正準化の「rendered」集合）。
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

/// 指定した部分木を排他的正準形のバイト列にする。
///
/// `inclusive_prefixes` は `InclusiveNamespaces/@PrefixList`（空白区切りを分解したもの）。
/// `#default` は既定名前空間を表す。
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
    /// 文書全体の名前空間スタック（1 要素 = その要素で宣言された (接頭辞, URI)）。
    scopes: Vec<Vec<(String, String)>>,
    /// 出力中の rendered スタック（部分木の中だけ）。
    rendered: Vec<Rendered>,
    /// 出力中の要素名スタック（終了タグを書くため）。
    open_names: Vec<String>,
    out: Vec<u8>,
    /// 出力対象の部分木に入った深さ（`None` なら未突入・脱出済み）。
    emitting_from: Option<usize>,
    /// 出力から取り除く部分木に入った深さ。
    skipping_from: Option<usize>,
    /// `ID` 一致要素の深さ（最初の 1 つ）。
    matched_depth: Option<usize>,
    /// 対象要素の直下 `ds:Signature` の深さ。
    signature_depth: Option<usize>,
    /// `ID` が一致した要素の数（文書全体）。
    matches: usize,
    /// 対象要素の直下で見つけた `ds:Signature` の数。
    direct_signatures: usize,
    depth: usize,
    /// 一度でも出力したか（対象が見つかったか）。
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
                    // 空要素タグは正準形では開始・終了タグの対になる。
                    let owned = e.into_owned();
                    self.on_start(&owned)?;
                    self.on_end();
                }
                Event::End(_) => self.on_end(),
                Event::Text(e) => {
                    if self.is_emitting() {
                        let text = e
                            .unescape()
                            .map_err(|err| DomainError::InvalidValue(format!("bad text: {err}")))?;
                        escape_text(&text, &mut self.out);
                    }
                }
                Event::CData(e) => {
                    if self.is_emitting() {
                        // CDATA は正準形では通常のテキストとして書き出す。
                        let text =
                            String::from_utf8(e.into_inner().into_owned()).map_err(|err| {
                                DomainError::InvalidValue(format!("non-UTF-8 CDATA: {err}"))
                            })?;
                        escape_text(&text, &mut self.out);
                    }
                }
                // コメントは出力しない（`#WithComments` ではないため）。宣言・DOCTYPE も同様。
                Event::Comment(_) | Event::Decl(_) | Event::DocType(_) => {}
                Event::PI(e) => {
                    if self.is_emitting() {
                        self.out.extend_from_slice(b"<?");
                        self.out.extend_from_slice(e.into_inner().as_ref());
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

        // 対象要素（`ID` 一致）。見つけても走査は止めず、文書全体で数える。
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

        // 対象要素の直下 `ds:Signature`（enveloped signature）。
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

        // その `ds:Signature` の直下 `ds:SignedInfo`。
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

    /// 接頭辞（`""` は既定名前空間）を URI へ解決する。既定名前空間の解除（`xmlns=""`）は
    /// `Some("")` ではなく `None` として扱う。
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
        let qname = String::from_utf8(e.name().as_ref().to_vec())
            .map_err(|err| DomainError::InvalidValue(format!("bad element name: {err}")))?;
        let mut rendered = self.rendered.last().cloned().unwrap_or_default();

        // 1. 出力する名前空間宣言（visibly utilized な接頭辞 + PrefixList）。
        //    `xml` は宣言せずに使えるので出力しない。
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
                // 既定名前空間は、要素自身が接頭辞を持たないときだけ「使われている」。
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
                // PrefixList に「この部分木では宣言されていない接頭辞」が並ぶのは普通なので
                // 読み飛ばす。要素・属性で実際に使われている未宣言の接頭辞は下で弾かれる。
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

        // 2. 属性は (名前空間 URI, ローカル名) の辞書順。接頭辞の無い属性は名前空間に属さない
        //    （URI は空）ので先に来る。
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
            let key = String::from_utf8(attr.key.as_ref().to_vec())
                .map_err(|err| DomainError::InvalidValue(format!("bad attribute name: {err}")))?;
            let value = attr
                .unescape_value()
                .map_err(|err| DomainError::InvalidValue(format!("bad attribute value: {err}")))?
                .into_owned();
            attributes.push((uri, al, key, value));
        }
        attributes.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

        // 3. 書き出す。
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

/// 属性値の正準化エスケープ（C14N 1.0 §Attribute Nodes）。
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

/// テキストノードの正準化エスケープ（C14N 1.0 §Text Nodes）。
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

/// 要素で宣言された名前空間を集める。
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
        let value = attr
            .unescape_value()
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

/// `ID` 型の属性値（SAML は `ID`、XMLDSIG は `Id`）。接頭辞付きの属性は見ない。
fn element_id(e: &BytesStart<'_>) -> Result<Option<String>> {
    for attr in e.attributes() {
        let attr =
            attr.map_err(|err| DomainError::InvalidValue(format!("bad attribute: {err}")))?;
        let (prefix, local) = split_name(attr.key.as_ref())?;
        if !prefix.is_empty() {
            continue;
        }
        if local == "ID" || local == "Id" || local == "id" {
            let value = attr
                .unescape_value()
                .map_err(|err| DomainError::InvalidValue(format!("bad attribute value: {err}")))?;
            return Ok(Some(value.into_owned()));
        }
    }
    Ok(None)
}

/// `prefix:local` を分ける（接頭辞が無ければ空文字）。
fn split_name(name: &[u8]) -> Result<(String, String)> {
    let name = std::str::from_utf8(name)
        .map_err(|e| DomainError::InvalidValue(format!("non-UTF-8 name: {e}")))?;
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

    /// 祖先で宣言された名前空間のうち、部分木で**使われているものだけ**を書き出す。
    #[test]
    fn only_visibly_utilized_namespaces_are_rendered() {
        let xml = r#"<r xmlns:a="urn:a" xmlns:b="urn:b"><a:e ID="x"><a:c/></a:e></r>"#;
        assert_eq!(
            c14n(xml, Target::SignedElement("x")),
            r#"<a:e xmlns:a="urn:a" ID="x"><a:c></a:c></a:e>"#
        );
    }

    /// 空要素タグは開始・終了タグの対になる。属性は (名前空間, ローカル名) 順。
    #[test]
    fn empty_tags_expand_and_attributes_are_sorted() {
        let xml = r#"<e ID="x" xmlns:z="urn:z" b="2" a="1" z:k="3"/>"#;
        assert_eq!(
            c14n(xml, Target::SignedElement("x")),
            r#"<e xmlns:z="urn:z" ID="x" a="1" b="2" z:k="3"></e>"#
        );
    }

    /// 既定名前空間は、接頭辞の無い要素でだけ書き出す。祖先で外されていれば `xmlns=""`。
    #[test]
    fn the_default_namespace_follows_the_element_prefix() {
        let xml = r#"<r xmlns="urn:d"><e ID="x"><f xmlns=""><g/></f></e></r>"#;
        assert_eq!(
            c14n(xml, Target::SignedElement("x")),
            r#"<e xmlns="urn:d" ID="x"><f xmlns=""><g></g></f></e>"#
        );
    }

    /// enveloped 変換: 対象要素の直下の `ds:Signature` は出力しない。
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

    /// `SignedInfo` は、対象要素の直下 `ds:Signature` の中のものだけを取る。
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

    /// 同じ `ID` の要素が 2 つある文書は拒否する（参照の解決先が一意でない = XSW の足がかり）。
    #[test]
    fn duplicate_ids_are_rejected() {
        let xml = r#"<r><e ID="x"><q/></e><e ID="x"><q/></e></r>"#;
        assert!(canonicalize(xml, Target::SignedElement("x"), &[]).is_err());
    }

    /// テキスト・属性値のエスケープは正準形の規則に従う（`>` はテキストだけ、`"` は属性だけ）。
    #[test]
    fn escaping_follows_the_canonical_rules() {
        let xml = r#"<e ID="x" a="&quot;&amp;&lt;&#9;">a &amp; b &gt; c</e>"#;
        assert_eq!(
            c14n(xml, Target::SignedElement("x")),
            "<e ID=\"x\" a=\"&quot;&amp;&lt;&#x9;\">a &amp; b &gt; c</e>"
        );
    }

    /// `PrefixList` に挙げた接頭辞は、見た目に使われていなくても書き出す。
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
