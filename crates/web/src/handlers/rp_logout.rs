//! RP-initiated Logout（`GET /{tenant_id}/logout`、OIDC RP-initiated Logout 1.0、ADR-0018 決定 2）。
//!
//! `end_session_endpoint` は web が受ける（api はブラウザ Cookie を読まない）。web は自ドメインの
//! host-only `sso_session_id` Cookie とクエリパラメータを api の `POST /internal/logout/rp` へ
//! 転送する。SSO セッションの失効・back-channel 通知・`post_logout_redirect_uri` の検証と
//! `state` 付与は api が担い、web は **SSO Cookie の破棄**と、front-channel logout がある場合の
//! iframe ページ描画を担う。
//!
//! `id_token_hint` は api へそのまま転送する（G12）。署名・issuer の検証と、`aud` による
//! `post_logout_redirect_uri` の照合・`sub` の突き合わせは api が行う（web は鍵を持たない）。
//! hint が**別の利用者**を指していた場合、api は何も変更せず `SubjectMismatch` を返す。このとき
//! web は SSO Cookie を破棄しない（破棄すると DB にだけセッションが残り、ブラウザから戻れなくなる）。

use super::{internal_call_status, locale};
use crate::client_ip::ClientIp;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::dto::RpLogoutQuery;
use crate::handlers::{forwarded_context, found};
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, MessagePage, RpLogoutPage};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Query, State};
use axum::http::header::CONTENT_SECURITY_POLICY;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use idp_contracts::auth::{InternalRpLogoutRequest, InternalRpLogoutResponse};

/// RP-initiated logout エンドポイント。
pub async fn logout(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<RpLogoutQuery>,
) -> Response {
    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let request = InternalRpLogoutRequest {
        tenant_id: Some(tenant.0.clone()),
        sso_session_id: cookies::get(&headers, cookies::SSO_SESSION_COOKIE),
        client_id: query.client_id,
        id_token_hint: query.id_token_hint,
        post_logout_redirect_uri: query.post_logout_redirect_uri,
        state: query.state,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let outcome = match state.api.rp_logout(&ctx.correlation_id, &request).await {
        Ok(outcome) => outcome,
        Err(e) => {
            tracing::error!(error = %e, "rp logout call to api failed");
            return internal_call_status(&e).into_response();
        }
    };
    let messages = Messages::new(locale(&headers));

    match outcome {
        InternalRpLogoutResponse::Ok {
            frontchannel_uris,
            redirect_to,
        } => {
            // SSO Cookie の破棄は web が自ドメインで行う（ADR-0018 決定 2）。
            let set_cookies = state
                .set_cookies()
                .expire_session(cookies::SSO_SESSION_COOKIE);

            // Front-channel logout がある場合は iframe ページを返す。外部 RP の URI を iframe で
            // 読み込むため、既定 CSP（frame-src が default-src 'self' に落ちる）を通知先オリジンを
            // 許可した CSP で上書きする（security_headers は設定済みの CSP を尊重する）。
            if !frontchannel_uris.is_empty() {
                let body = render(&RpLogoutPage {
                    messages: &messages,
                    frontchannel_uris: &frontchannel_uris,
                    redirect_to: redirect_to.as_deref(),
                });
                return (
                    StatusCode::OK,
                    [(
                        CONTENT_SECURITY_POLICY,
                        frontchannel_csp(&frontchannel_uris),
                    )],
                    set_cookies.into_headers(),
                    Html(body),
                )
                    .into_response();
            }

            // Front-channel なし: redirect または完了ページ。
            if let Some(uri) = redirect_to {
                (set_cookies.into_headers(), found(&uri)).into_response()
            } else {
                let body = render(&MessagePage {
                    title: messages.get("logout-title"),
                    message: messages.get("logout-done-message"),
                });
                (set_cookies.into_headers(), Html(body)).into_response()
            }
        }
        // `id_token_hint` が別の利用者を指していた（G12）。api は何も変更していないので、
        // **Cookie も消さない** —— 消すと DB にセッションが生きたままブラウザから戻れなくなり、
        // 守ろうとした別利用者のログイン状態を結局は壊してしまう。
        InternalRpLogoutResponse::SubjectMismatch => {
            let body = render(&MessagePage {
                title: messages.get("logout-title"),
                message: messages.get("logout-subject-mismatch-message"),
            });
            (StatusCode::BAD_REQUEST, Html(body)).into_response()
        }
        InternalRpLogoutResponse::Internal => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// front-channel 通知先のオリジンだけを `frame-src` に許可した CSP を組み立てる
/// （それ以外は `security_headers::CONTENT_SECURITY_POLICY` と同じ方針）。
fn frontchannel_csp(frontchannel_uris: &[String]) -> String {
    let mut origins: Vec<String> = frontchannel_uris
        .iter()
        .map(|uri| crate::security_headers::origin_of(uri))
        // 解釈できない URI は許可を足さない（fail-closed）。
        .filter(|origin| !origin.is_empty())
        .collect();
    origins.sort();
    origins.dedup();
    format!(
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
         img-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self'; \
         frame-ancestors 'none'; frame-src {}",
        origins.join(" ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frontchannel_csp_allows_only_the_notified_origins() {
        let csp = frontchannel_csp(&[
            "https://rp.example.com/logout?iss=x".to_string(),
            "https://rp.example.com/other".to_string(),
            "http://localhost:3000/fc".to_string(),
        ]);
        assert!(
            csp.ends_with("frame-src http://localhost:3000 https://rp.example.com"),
            "{csp}"
        );
        assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
    }
}
