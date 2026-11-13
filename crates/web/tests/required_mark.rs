//! The required marker (`templates/required_mark.html`) matches the `required` attribute on every screen.
//!
//! The marker is **only for the eye**; what decides whether a field is required is the input's `required`
//! (assistive technology reads that; the marker is `aria-hidden`). If the two drift, the screen lies in two ways:
//!
//! - **Required fields without the marker** -- sent back with "please fill in" after submitting. Which is required
//!   is only learned by being rejected.
//! - **Optional fields with only the marker** -- makes users fill in what they need not. Also a reason to give up.
//!
//! There are nearly 60 screens and more forms will be added. ⚠ **Even once aligned, the next one
//! added drifts**, so the alignment itself is held by a test.
//!
//! Only one exception: **forms whose label is hidden with `visually-hidden`** get no marker
//! (a visible marker cannot be put inside an invisible label). All are single-field inline edits, and
//! their button submits only that field.

mod support;

use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use support::{body_text, get, send, setup};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const INCLUDE: &str = r#"{% include "required_mark.html" %}"#;

/// The marker appears in actually rendered HTML.
///
/// The two above only read template **strings**, so they are green even if `{% include %}` cannot be
/// resolved at render time (e.g. placed in a template without `messages`).
/// Fetch one screen through the router and check the marker really appears.
#[tokio::test]
async fn the_mark_is_rendered_into_the_page() {
    let env = setup().await;
    // Fetching external IdP buttons (needed to render the login screen; the password field appears even on failure).
    Mock::given(method("POST"))
        .and(path("/internal/external/providers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "ok",
            "providers": []
        })))
        .mount(&env.api)
        .await;

    let response = send(&env.app, get(&format!("{}/login", env.prefix()))).await;
    let html = body_text(response).await;

    // Both username and password fields are required.
    let marks = html.matches(r#"<span class="form-required""#).count();
    assert_eq!(marks, 2, "rendered markers are not 2: {marks}");
    assert!(
        html.contains(r#"<span class="form-required" aria-hidden="true" title="必須">*</span>"#),
        "marker shape changed (keep aria-hidden hiding it from screen readers and the title carrying the meaning)",
    );
}

#[test]
fn every_required_field_shows_the_mark() {
    let mut checked = 0usize;
    for (name, text) in templates() {
        for tag in control_tags(&text) {
            if !has_attribute(tag, "required") {
                continue;
            }
            let Some(id) = attribute(tag, "id") else {
                panic!("{name}: `required` field has no id and is not tied to a label: {tag}");
            };
            let Some(label) = label_for(&text, id) else {
                panic!("{name}: `required` field `{id}` has no <label for>");
            };
            if label.hidden {
                continue;
            }
            assert!(
                label.inner.contains(INCLUDE),
                "{name}: label of `required` field `{id}` has no required marker; \
                 put {INCLUDE} right after the label text",
            );
            checked += 1;
        }
    }
    // Prevents the scan from breaking into "green because nothing was found". 53 as of 2026-09-21.
    assert!(checked >= 50, "only {checked} required fields found");
}

#[test]
fn the_mark_is_never_shown_on_an_optional_field() {
    for (name, text) in templates() {
        for (at, _) in text.match_indices(INCLUDE) {
            let Some(label) = label_around(&text, at) else {
                panic!("{name}: required marker is outside <label> (put it right after the label text)");
            };
            let Some(id) = attribute(label.open_tag, "for") else {
                panic!(
                    "{name}: label with a required marker has no for: {}",
                    label.open_tag
                );
            };
            let control = control_tags(&text)
                .into_iter()
                .find(|tag| attribute(tag, "id") == Some(id));
            let Some(control) = control else {
                panic!("{name}: label `{id}` with a required marker has no matching input");
            };
            assert!(
                has_attribute(control, "required"),
                "{name}: `{id}` has a required marker but no `required`",
            );
        }
    }
}

// ── Scan (templates are Askama, so a plain HTML parser cannot be used) ──────────

/// All templates under `templates/` (`(display name, content)`). Excludes the marker's own definition.
fn templates() -> Vec<(String, String)> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("templates");
    let mut files = Vec::new();
    collect(&root, &mut files);
    assert!(!files.is_empty(), "no templates found");
    files.sort();
    files
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|n| n != "required_mark.html"))
        .map(|path| {
            let name = path
                .strip_prefix(&root)
                .unwrap_or(&path)
                .to_string_lossy()
                .into_owned();
            let text = fs::read_to_string(&path).expect("cannot read template");
            (name, text)
        })
        .collect()
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("cannot read templates/") {
        let path = entry.expect("cannot read directory entry").path();
        if path.is_dir() {
            collect(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "html") {
            out.push(path);
        }
    }
}

/// Opening tags of `<input …>` `<select …>` `<textarea …>`.
///
/// ⚠ Templates with `>` in attribute values cannot be split this way. Hence the premise that they are written as `&gt;`
/// (`placeholder="&lt;EntityDescriptor …&gt;"`).
fn control_tags(text: &str) -> Vec<&str> {
    let mut tags = Vec::new();
    for (start, _) in text.match_indices('<') {
        let rest = &text[start + 1..];
        let is_control = ["input", "select", "textarea"].iter().any(|name| {
            rest.strip_prefix(name)
                .is_some_and(|after| after.starts_with(char::is_whitespace))
        });
        if !is_control {
            continue;
        }
        if let Some(end) = rest.find('>') {
            tags.push(&text[start..start + 1 + end + 1]);
        }
    }
    tags
}

struct Label<'a> {
    open_tag: &'a str,
    inner: &'a str,
    /// Invisible labels (single-field inline edit forms). There is nowhere to put the marker.
    hidden: bool,
}

fn label_for<'a>(text: &'a str, id: &str) -> Option<Label<'a>> {
    let at = text.find(&format!(r#"for="{id}""#))?;
    label_around(text, at)
}

/// The `<label>…</label>` containing `at`.
fn label_around(text: &str, at: usize) -> Option<Label<'_>> {
    let start = text[..at].rfind("<label")?;
    let open_end = text[start..].find('>')? + start + 1;
    let end = text[open_end..].find("</label>")? + open_end;
    Some(Label {
        open_tag: &text[start..open_end],
        inner: &text[open_end..end],
        hidden: text[start..open_end].contains("visually-hidden"),
    })
}

/// Whether the tag has the (valueless) attribute. Does not match `data-required` or `placeholder="required"`.
fn has_attribute(tag: &str, name: &str) -> bool {
    tag.match_indices(name).any(|(at, _)| {
        let before = tag[..at].chars().next_back();
        let after = tag[at + name.len()..].chars().next();
        !before.is_some_and(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '"')
            && !after.is_some_and(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '=')
    })
}

/// Value of `name="…"`.
fn attribute<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!(r#"{name}=""#);
    let at = tag.match_indices(&needle).find(|(at, _)| {
        let before = tag[..*at].chars().next_back();
        !before.is_some_and(|c| c.is_alphanumeric() || c == '-' || c == '_')
    })?;
    let value = &tag[at.0 + needle.len()..];
    value.find('"').map(|end| &value[..end])
}
