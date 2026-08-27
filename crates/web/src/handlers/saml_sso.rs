//! SAML SSO の継続画面（`GET /{tenant_id}/saml/continue`）。
//!
//! api の `/{tenant_id}/saml/sso` からのハンドオフを受ける（OIDC の `/login?auth_session=` と
//! 同方式。ADR-0018 決定 2）。ハンドル（初回）または `saml_request_id` Cookie（ログイン後の復帰）と
//! 自ドメインの host-only `sso_session_id` Cookie を `/internal/saml/resume` へ転送し、
//!
//! - SSO 有効なら署名済み `SAMLResponse` を SP の ACS へ自動 POST するフォームを描画する
//!   （送信先が外部オリジンのため、ACS オリジンだけ `form-action` に許可した CSP を付ける）
//! - 認証が必要なら `saml_request_id` を host-only Cookie 化してポータルログインへ 303 する
//!   （ログイン成功時は [`super::portal`] が本画面へ戻す）

use super::{internal_call_status, locale};
use crate::client_ip::ClientIp;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::dto::SamlContinueQuery;
use crate::handlers::{forwarded_context, see_other};
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, MessagePage, SamlPostPage};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Query, State};
use axum::http::header::CONTENT_SECURITY_POLICY;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use idp_contracts::auth::{InternalSamlResumeRequest, InternalSamlResumeResponse};

pub async fn continue_sso(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<SamlContinueQuery>,
) -> Response {
    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let handle = query.handle.filter(|h| !h.is_empty());
    let saml_request_id = cookies::get(
        &headers,
        &state.origin_bound_cookie(cookies::SAML_REQUEST_COOKIE),
    );
    if handle.is_none() && saml_request_id.is_none() {
        // ハンドオフ経由でも復帰経由でもない直接アクセス。
        let messages = Messages::new(locale(&headers));
        return expired_page(&messages);
    }

    let request = InternalSamlResumeRequest {
        tenant_id: Some(tenant.0.clone()),
        handle,
        saml_request_id,
        sso_session_id: cookies::get(&headers, cookies::SSO_SESSION_COOKIE),
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let outcome = match state.api.saml_resume(&ctx.correlation_id, &request).await {
        Ok(outcome) => outcome,
        Err(e) => {
            tracing::error!(error = %e, "SAML resume call to api failed");
            return internal_call_status(&e).into_response();
        }
    };

    // FluentBundle は Send でないため、api の await 後に生成する。
    let messages = Messages::new(locale(&headers));
    match outcome {
        InternalSamlResumeResponse::Completed {
            acs_url,
            saml_response,
            relay_state,
        } => {
            let body = render(&SamlPostPage {
                messages: &messages,
                acs_url: &acs_url,
                saml_response: &saml_response,
                relay_state: relay_state.as_deref(),
            });
            (
                StatusCode::OK,
                [(CONTENT_SECURITY_POLICY, acs_form_action_csp(&acs_url))],
                state
                    .set_cookies()
                    .expire_local(&state.origin_bound_cookie(cookies::SAML_REQUEST_COOKIE))
                    .into_headers(),
                Html(body),
            )
                .into_response()
        }
        InternalSamlResumeResponse::LoginRequired { saml_request_id } => {
            // 進行状態 id を Cookie 化してポータルログインへ。TTL は api 側の進行状態と同じ
            // auth_session TTL に合わせる。303 でハンドルを URL・履歴から除去する。
            let set_cookies = state.set_cookies().set_local(
                &state.origin_bound_cookie(cookies::SAML_REQUEST_COOKIE),
                &saml_request_id,
                state.config.auth_session_ttl_secs(),
            );
            (
                set_cookies.into_headers(),
                see_other(&format!("{}/login", tenant.prefix())),
            )
                .into_response()
        }
        InternalSamlResumeResponse::Expired => {
            let set_cookies = state
                .set_cookies()
                .expire_local(&state.origin_bound_cookie(cookies::SAML_REQUEST_COOKIE));
            (set_cookies.into_headers(), expired_page(&messages)).into_response()
        }
        InternalSamlResumeResponse::Internal => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// SP の ACS へフォーム送信するための CSP。既定 CSP（`form-action 'self'`）のままでは外部
/// オリジンへの POST がブラウザに遮断されるため、ACS のオリジンだけを追加で許可する。
///
/// 組み立ては [`crate::security_headers::form_action_csp_for`] に委ねる。ここで方針を書き写して
/// いたときは既定 CSP と別々に育ってしまい、SEC12 で `script-src` から外したはずの
/// `'unsafe-inline'` がこのページにだけ残っていた（`saml_post.html` のスクリプトは
/// `/assets/auto-submit.js` の外部参照で、インラインは使っていない）。
fn acs_form_action_csp(acs_url: &str) -> String {
    crate::security_headers::form_action_csp_for(acs_url)
}

fn expired_page(messages: &Messages) -> Response {
    let body = render(&MessagePage {
        title: messages.get("saml-continue-title"),
        message: messages.get("saml-error-expired"),
    });
    (StatusCode::BAD_REQUEST, Html(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csp_allows_only_the_acs_origin_as_an_extra_form_action() {
        let csp = acs_form_action_csp("https://sp.example.test/acs?x=1");
        assert!(
            csp.contains("form-action 'self' https://sp.example.test;"),
            "{csp}"
        );
        assert!(csp.contains("frame-ancestors 'none'"), "{csp}");

        let csp = acs_form_action_csp("http://localhost:8080/acs");
        assert!(
            csp.contains("form-action 'self' http://localhost:8080;"),
            "{csp}"
        );
    }
}
