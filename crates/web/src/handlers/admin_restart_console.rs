//! 管理コンソールからの再起動（web。`POST /{tenant_id}/admin/restart`。ADR-0017）。
//!
//! ランタイム設定の DB 上書きは起動時にしか読まれない（ADR-0014）。反映のためだけに運用者を
//! シェルへ行かせないよう、設定画面から **api → web の順**で再起動できるようにする。
//!
//! 順序は逆にできない。web は起動時に api から共有ランタイム設定を受け取る（ADR-0013）ので、
//! web が先に立ち上がると再起動前の api が配る古い値を掴んでしまう。そのため
//!
//! 1. api へ再起動を要求し、**受理されたことを確認してから**
//! 2. 再起動中の画面を返し、
//! 3. その応答を返し切ったあとに web 自身を停止する
//!
//! という順に進める。api の要求が失敗したら web は止めない（web だけ落ちると、api は動いている
//! のに画面が消えて、再起動を指示する手段そのものが無くなる）。
//!
//! 新しいプロセスを起こすのは配置側の再起動ポリシーである（`service_restart` 参照）。ポリシーが
//! 無い環境ではサービスが停止したままになるため、画面には実行前に必ずその前提を出す。

use super::locale;
use crate::api_client::AdminApiError;
use crate::correlation::CorrelationId;
use crate::csrf::console_csrf_token;
use crate::dto::AdminRestartForm;
use crate::handlers::admin_console::{
    forbidden_response, redirect_to_login, resolve_admin, AdminResolution,
};
use crate::handlers::found;
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, Restarting};
use crate::tenant::WebTenant;
use crate::{cookies, service_restart::ServiceRestart};
use axum::extract::{Extension, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use std::time::Duration;

const SETTINGS_SEGMENT: &str = "/admin/settings";

/// 待機画面を返してから web を停止するまでの猶予。
///
/// api は受理から約 0.5 秒で停止に入る。web がそれより先に落ちると、待機画面を描き切れないうえ、
/// 先に起動し直して古い共有設定を掴む恐れがある。api の停止を追い越さない程度に置く。
const WEB_SHUTDOWN_DELAY: Duration = Duration::from_secs(2);

/// 待機画面が設定画面へ自動で戻るまでの秒数。両サービスの起動（web は api への再試行を含む）が
/// 終わる程度に取る。早すぎると「戻ったのにエラー」になり、再起動の失敗と区別が付かない。
const RETRY_AFTER_SECONDS: u64 = 20;

/// api と web を再起動する。
pub async fn restart(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<AdminRestartForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}{SETTINGS_SEGMENT}", tenant.prefix());
    let sso = cookies::get(&headers, cookies::SSO_SESSION_COOKIE).unwrap_or_default();
    if !idp_contracts::csrf::verify(
        &console_csrf_token(&sso, state.config.csrf_secret()),
        &form.csrf_token,
    ) {
        return found(&format!("{base}?error=csrf"));
    }

    // 1. api を先に停止させる（受理されるまで web は止めない）。
    if let Err(e) = state
        .api
        .request_restart(&correlation.0, &tenant.0, &sso)
        .await
    {
        return match e {
            AdminApiError::Unauthorized => redirect_to_login(&tenant),
            AdminApiError::Forbidden => forbidden_response(&headers),
            other => {
                tracing::error!(error = %other, "failed to request an api restart");
                found(&format!("{base}?error=restart#runtime-settings"))
            }
        };
    }

    // 2. web 自身の停止を予約する。応答を返し切る前に止めると待機画面が届かない。
    schedule_web_shutdown(state.restart.clone());

    // 3. 待機画面（自動で設定画面へ戻る）。
    let messages = Messages::new(locale(&headers));
    Html(render(&Restarting {
        messages: &messages,
        settings_href: &base,
        retry_after_seconds: RETRY_AFTER_SECONDS,
    }))
    .into_response()
}

fn schedule_web_shutdown(restart: ServiceRestart) {
    tokio::spawn(async move {
        tokio::time::sleep(WEB_SHUTDOWN_DELAY).await;
        tracing::warn!("restarting the web service after the api restart request");
        restart.request();
    });
}
