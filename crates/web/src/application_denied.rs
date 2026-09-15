//! 「このアプリの利用が許可されていません」の画面（ADR-0054 の決定 2）。
//!
//! 判定は **code 発行の 1 か所**（api の `CodeIssuanceService`）で行われるが、そこへ辿り着く
//! 経路はログイン・MFA・パスキー・外部 IdP・パスワード変更・同意・SSO 復元の 7 本ある。
//! どの経路から来ても利用者が見る画面は同じものなので、描画はここに 1 つだけ置く。
//!
//! ⚠ **RP へリダイレクトしない。** 断りは assay の画面で伝える。RP へ戻すと、利用者には
//! 「ログインしたのにアプリのエラー画面へ飛ばされた」としか見えず、次に何をすればよいかが
//! どこにも出ない。

use crate::i18n::Messages;
use crate::templates::{render, ApplicationNotPermittedPage};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};

/// 断りの画面を描く。
///
/// `tenant_prefix` は戻り先（自分のアカウント画面）を組み立てるための `/{tenant_id}`。
/// 空文字ならリンクを出さない ——出口の無いエラー画面にはしないが、行けない場所へのリンクも
/// 置かない。
pub fn page(messages: &Messages, tenant_prefix: &str, application_name: &str) -> Response {
    let body = render(&ApplicationNotPermittedPage {
        title: messages.get("application-not-permitted-title"),
        signed_in: messages.get_arg(
            "application-not-permitted-signed-in",
            "application",
            application_name,
        ),
        next_step: messages.get_arg(
            "application-not-permitted-next-step",
            "application",
            application_name,
        ),
        back_href: if tenant_prefix.is_empty() {
            String::new()
        } else {
            format!("{tenant_prefix}/settings")
        },
        back_label: messages.get("application-not-permitted-back"),
    });
    // 403。認証は通っているので 401 ではない ——「誰であるかは分かっているが、ここは使えない」。
    (StatusCode::FORBIDDEN, Html(body)).into_response()
}
