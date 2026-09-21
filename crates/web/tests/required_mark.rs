//! 必須の印（`templates/required_mark.html`）が、全画面で `required` 属性と表裏で一致していること。
//!
//! 印は**目で拾うためだけ**のもので、必須かどうかを決めているのは入力欄の `required` である
//! （支援技術はそちらを読む。印は `aria-hidden`）。この 2 つがずれると、画面は 2 通りの嘘をつく:
//!
//! - **印が無い必須欄** —— 送ってから「入力してください」で戻される。どれが必須かは、
//!   弾かれて初めて分かる。
//! - **印だけの任意欄** —— 埋めなくてよいものを埋めさせる。入力を諦める理由にもなる。
//!
//! 画面は 60 近くあり、新しいフォームは今後も増える。⚠ **一度そろえても、次に足される
//! 1 つがずれる**ので、そろっていること自体を試験で持つ。
//!
//! 例外は 1 つだけ:**ラベルを `visually-hidden` で伏せているフォーム**には印を出さない
//! （見えないラベルの中に見える印は置けない）。いずれも項目が 1 つだけの行内編集で、
//! そのボタンが送るのはその欄だけである。

mod support;

use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use support::{body_text, get, send, setup};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const INCLUDE: &str = r#"{% include "required_mark.html" %}"#;

/// 実際に描かれた HTML に印が出ること。
///
/// 上の 2 つはテンプレートの**文字列**を読むだけなので、`{% include %}` が描画時に
/// 解決できなくても緑になる（`messages` を持たないテンプレートへ置いたときなど）。
/// ルータ越しに 1 画面だけ引いて、印が本当に出ることを見る。
#[tokio::test]
async fn the_mark_is_rendered_into_the_page() {
    let env = setup().await;
    // 外部 IdP ボタンの取得（ログイン画面の描画に要る。失敗してもパスワード欄は出る）。
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

    // ユーザー名・パスワードの 2 欄とも必須。
    let marks = html.matches(r#"<span class="form-required""#).count();
    assert_eq!(marks, 2, "描かれた印が 2 つではない: {marks}");
    assert!(
        html.contains(r#"<span class="form-required" aria-hidden="true" title="必須">*</span>"#),
        "印の形が変わっている（読み上げから伏せる aria-hidden と、意味を伝える title を落とさない）",
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
                panic!("{name}: `required` の欄に id が無く、ラベルと結び付いていない: {tag}");
            };
            let Some(label) = label_for(&text, id) else {
                panic!("{name}: `required` の欄 `{id}` に <label for> が無い");
            };
            if label.hidden {
                continue;
            }
            assert!(
                label.inner.contains(INCLUDE),
                "{name}: `required` の欄 `{id}` のラベルに必須の印が無い。\
                 ラベルの文言の直後に {INCLUDE} を置く",
            );
            checked += 1;
        }
    }
    // 走査が壊れて「1 件も見つからないから緑」になるのを防ぐ。2026-09-21 時点で 53 件。
    assert!(checked >= 50, "必須の欄が {checked} 件しか見つからない");
}

#[test]
fn the_mark_is_never_shown_on_an_optional_field() {
    for (name, text) in templates() {
        for (at, _) in text.match_indices(INCLUDE) {
            let Some(label) = label_around(&text, at) else {
                panic!("{name}: 必須の印が <label> の外にある（印はラベルの文言の直後に置く）");
            };
            let Some(id) = attribute(label.open_tag, "for") else {
                panic!(
                    "{name}: 必須の印を持つラベルに for が無い: {}",
                    label.open_tag
                );
            };
            let control = control_tags(&text)
                .into_iter()
                .find(|tag| attribute(tag, "id") == Some(id));
            let Some(control) = control else {
                panic!("{name}: 必須の印を持つラベル `{id}` に対応する入力欄が無い");
            };
            assert!(
                has_attribute(control, "required"),
                "{name}: `{id}` は必須の印が付いているのに `required` が無い",
            );
        }
    }
}

// ── 走査（テンプレートは Askama なので、素の HTML パーサには掛けられない） ──────────

/// `templates/` 以下の全テンプレート（`(表示用の名前, 中身)`）。印そのものの定義は除く。
fn templates() -> Vec<(String, String)> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("templates");
    let mut files = Vec::new();
    collect(&root, &mut files);
    assert!(!files.is_empty(), "テンプレートが 1 つも見つからない");
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
            let text = fs::read_to_string(&path).expect("テンプレートを読めない");
            (name, text)
        })
        .collect()
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("templates/ を読めない") {
        let path = entry.expect("ディレクトリ項目を読めない").path();
        if path.is_dir() {
            collect(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "html") {
            out.push(path);
        }
    }
}

/// `<input …>` `<select …>` `<textarea …>` の開始タグ。
///
/// ⚠ 属性値に `>` を含むテンプレートはこのやり方で切れない。そのため `&gt;` で書く
/// （`placeholder="&lt;EntityDescriptor …&gt;"`）ことが前提になっている。
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
    /// 目に見えないラベル（行内編集の 1 項目フォーム）。印を出す場所が無い。
    hidden: bool,
}

fn label_for<'a>(text: &'a str, id: &str) -> Option<Label<'a>> {
    let at = text.find(&format!(r#"for="{id}""#))?;
    label_around(text, at)
}

/// `at` を含む `<label>…</label>`。
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

/// タグに（値の無い）属性が書かれているか。`data-required` や `placeholder="required"` には当たらない。
fn has_attribute(tag: &str, name: &str) -> bool {
    tag.match_indices(name).any(|(at, _)| {
        let before = tag[..at].chars().next_back();
        let after = tag[at + name.len()..].chars().next();
        !before.is_some_and(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '"')
            && !after.is_some_and(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '=')
    })
}

/// `name="…"` の値。
fn attribute<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!(r#"{name}=""#);
    let at = tag.match_indices(&needle).find(|(at, _)| {
        let before = tag[..*at].chars().next_back();
        !before.is_some_and(|c| c.is_alphanumeric() || c == '-' || c == '_')
    })?;
    let value = &tag[at.0 + needle.len()..];
    value.find('"').map(|end| &value[..end])
}
