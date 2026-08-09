//! 表示言語の決定（MT20。`CLAUDE.md`「国際化」の責務分離）。
//!
//! **表示言語を決めるのは web** で、api は `Accept-Language` しか見ない。決定順は先勝ちで
//! `?lang=` > ユーザー設定（DB の `users.language`）> Cookie(`lang`) > 認可要求の `ui_locales`
//! （G12）> ブラウザの `Accept-Language` > 既定 `ja`。不正・非対応値は無視して次順位へ落ちる。
//!
//! `ui_locales` が Cookie より下・ブラウザ言語より上なのは、これが **RP の希望**であって利用者
//! 自身の選択ではないため。一度でも言語を選んだ利用者（`lang` Cookie がある）の画面を RP の
//! 都合で切り替えないが、何も選んでいない利用者にはブラウザ既定より RP の指定を優先する。
//!
//! 実装は middleware 1 本に集約する。ハンドラごとに 4 つの入力を集め直すと、画面が増えるたびに
//! 優先順位が食い違う（実際に MT20 前は画面によって `?lang=` を見る／見ないが分かれていた）。
//!
//! 決定結果は**リクエストの `lang` Cookie ヘッダを書き換えて**下流へ渡す。ハンドラは従来どおり
//! `handlers::locale`（Cookie > `Accept-Language` > 既定）を呼ぶだけで決定順に従える。
//! 応答では、明示的な選択（有効な `?lang=`）があったときだけ Cookie を保存し、ログイン中なら
//! ユーザー設定（DB）へも永続化する。
//!
//! ユーザー設定の取得には api への 1 リクエスト（`/internal/account/profile`）が必要で、
//! **ログイン中の HTML 画面表示ごとに 1 回**発生する。`?lang=` で既に決まっている場合と SSO Cookie が
//! 無い場合は呼ばない。ローカルホップであり、管理コンソールは 1 画面あたり既に複数回 api を呼ぶため
//! 相対的な増分は小さい。Cookie を正とするキャッシュは、別端末で言語を変えたときに追随できなくなるため採らない。

use crate::cookies;
use crate::i18n::Locale;
use crate::login_context::RpLoginContext;
use crate::state::WebState;
use axum::extract::{Request, State};
use axum::http::header::{HeaderValue, COOKIE};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use idp_contracts::auth::{
    InternalAccountProfileRequest, InternalAccountProfileResponse,
    InternalAccountUpdateLanguageRequest, InternalAccountUpdateLanguageResponse,
};

/// URL クエリから `lang` の値を取り出す（`?a=1&lang=en` → `Some("en")`）。
/// 値のデコードは行わない（言語タグは `ja` / `en` のみで、パーセントエンコードされる文字を含まない）。
fn query_lang(query: Option<&str>) -> Option<&str> {
    query?
        .split('&')
        .find_map(|pair| pair.strip_prefix("lang="))
}

/// 表示言語を決めてリクエストへ反映する middleware。
///
/// 決定した言語を下流のハンドラへ伝えるため、リクエストの `Cookie` ヘッダの `lang` を決定値へ
/// 差し替える（`handlers::locale` が読む入力を 1 つに正規化する）。他の Cookie（SSO 等）は保つ。
pub async fn resolve_language(
    State(state): State<WebState>,
    mut request: Request,
    next: Next,
) -> Response {
    let explicit = query_lang(request.uri().query()).and_then(Locale::from_tag);
    let sso = cookies::get(request.headers(), cookies::SSO_SESSION_COOKIE);

    // 決定順 1: 有効な `?lang=`。2: ユーザー設定（ログイン中のみ api へ問い合わせる）。
    // 3: Cookie（下流の `handlers::locale` がそのまま読む）。4: 認可要求の `ui_locales`。
    // いずれも無ければ `Accept-Language` を下流がそのまま使う。
    let decided = match explicit {
        Some(locale) => Some(locale),
        None => match &sso {
            Some(sso) => user_language(&state, sso).await,
            None => None,
        },
    };
    let decided = decided.or_else(|| requested_locale(&request));
    if let Some(locale) = decided {
        overwrite_lang_cookie(&mut request, locale);
    }

    let response = next.run(request).await;

    // 明示的な選択のみ永続化する（ブラウザ言語やユーザー設定の反映で Cookie を書き換えない。
    // 書き換えると、別端末でユーザー設定を変えたときに古い Cookie が上書き返しされ続ける）。
    let Some(locale) = explicit else {
        return response;
    };
    if let Some(sso) = sso {
        persist_user_language(&state, &sso, locale).await;
    }
    (
        state
            .set_cookies()
            .set_local(
                cookies::LANG_COOKIE,
                locale.as_tag(),
                cookies::LANG_COOKIE_MAX_AGE_SECS,
            )
            .into_headers(),
        response,
    )
        .into_response()
}

/// リクエストの `lang` Cookie が示す有効なロケール（未設定・非対応値は `None`）。
fn cookie_locale(request: &Request) -> Option<Locale> {
    cookies::get(request.headers(), cookies::LANG_COOKIE).and_then(|tag| Locale::from_tag(&tag))
}

/// 決定順 4: 進行中の認可要求が `ui_locales` で要求した表示ロケール（G12）。
/// OIDC フロー外・非対応値は `None`。文脈の取得は [`crate::login_context`] の middleware が済ませてある。
///
/// 利用者が選んだ言語（有効な `lang` Cookie）が残っているときは決めない（決定順 3 が勝つ）。
fn requested_locale(request: &Request) -> Option<Locale> {
    if cookie_locale(request).is_some() {
        return None;
    }
    request
        .extensions()
        .get::<RpLoginContext>()?
        .ui_locales
        .as_deref()
        .and_then(Locale::from_ui_locales)
}

/// ログイン中ユーザーの保存済み表示言語（未設定・非対応値・取得失敗は `None`）。
/// 取得失敗で画面を落とさない（言語は表示の都合であり、Cookie / ブラウザ言語へ落ちれば足りる）。
async fn user_language(state: &WebState, sso: &str) -> Option<Locale> {
    let request = InternalAccountProfileRequest {
        sso_session_id: sso.to_string(),
    };
    match state.api.account_profile(&request).await {
        Ok(InternalAccountProfileResponse::Ok { language, .. }) => {
            language.as_deref().and_then(Locale::from_tag)
        }
        Ok(_) => None,
        Err(e) => {
            tracing::warn!(error = %e, "could not read the user's language setting; falling back to the cookie");
            None
        }
    }
}

/// 明示的に選択された言語をユーザー設定（DB）へ保存する。失敗は Cookie 側の保存を妨げない。
async fn persist_user_language(state: &WebState, sso: &str, locale: Locale) {
    let request = InternalAccountUpdateLanguageRequest {
        sso_session_id: sso.to_string(),
        language: locale.as_tag().to_string(),
    };
    match state.api.account_update_language(&request).await {
        Ok(InternalAccountUpdateLanguageResponse::Ok) => {}
        Ok(InternalAccountUpdateLanguageResponse::SessionExpired) => {
            tracing::debug!("SSO session expired while persisting the language choice");
        }
        Ok(other) => tracing::warn!(?other, "unexpected outcome from update-language"),
        Err(e) => tracing::warn!(error = %e, "could not persist the language choice"),
    }
}

/// リクエストの `Cookie` ヘッダを、`lang` だけ `locale` へ差し替えた 1 本に組み替える。
///
/// `lang` を消して付け直すのは、複数の `Cookie` ヘッダ／同名 Cookie の重複があっても
/// 下流が読む値を一意にするため（`cookies::get` は先に見つかった値を返す）。
fn overwrite_lang_cookie(request: &mut Request, locale: Locale) {
    let mut pairs: Vec<String> = request
        .headers()
        .get_all(COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .map(str::trim)
        .filter(|pair| !pair.is_empty())
        .filter(|pair| {
            let name = pair.split('=').next().unwrap_or("").trim();
            name != cookies::LANG_COOKIE
        })
        .map(str::to_string)
        .collect();
    pairs.push(format!("{}={}", cookies::LANG_COOKIE, locale.as_tag()));

    let joined = pairs.join("; ");
    let Ok(value) = HeaderValue::from_str(&joined) else {
        // 元の Cookie に非 ASCII が混ざっている等。言語の上書きを諦め、元のヘッダを保つ。
        tracing::warn!("could not rebuild the cookie header while resolving the language");
        return;
    };
    request.headers_mut().remove(COOKIE);
    request.headers_mut().insert(COOKIE, value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    #[test]
    fn extracts_lang_from_the_query_string() {
        assert_eq!(query_lang(None), None);
        assert_eq!(query_lang(Some("lang=en")), Some("en"));
        assert_eq!(query_lang(Some("error=csrf&lang=ja")), Some("ja"));
        assert_eq!(query_lang(Some("q=lang=en")), None, "only a whole pair");
        // 未知・不正値は `Locale::from_tag` 側で捨てられる（ここでは素の値を返す）。
        assert_eq!(query_lang(Some("lang=fr")), Some("fr"));
        assert_eq!(query_lang(Some("lang=")), Some(""));
    }

    fn request_with_cookies(cookies: &[&str]) -> Request {
        let mut builder = Request::builder().uri("/");
        for cookie in cookies {
            builder = builder.header(COOKIE, *cookie);
        }
        builder.body(Body::empty()).unwrap()
    }

    #[test]
    fn overwrite_keeps_other_cookies_and_replaces_lang() {
        let mut request = request_with_cookies(&["sso_session_id=sess; lang=ja; other=x"]);
        overwrite_lang_cookie(&mut request, Locale::En);
        assert_eq!(
            cookies::get(request.headers(), cookies::SSO_SESSION_COOKIE),
            Some("sess".to_string())
        );
        assert_eq!(
            cookies::get(request.headers(), cookies::LANG_COOKIE),
            Some("en".to_string())
        );
        assert_eq!(
            cookies::get(request.headers(), "other"),
            Some("x".to_string())
        );
    }

    /// `lang` が複数ヘッダ・重複していても、下流が読む値は決定値ひとつになる。
    #[test]
    fn overwrite_collapses_duplicate_lang_cookies() {
        let mut request = request_with_cookies(&["lang=ja", "lang=fr; sso_session_id=sess"]);
        overwrite_lang_cookie(&mut request, Locale::En);
        let header = request
            .headers()
            .get(COOKIE)
            .and_then(|v| v.to_str().ok())
            .expect("cookie header");
        assert_eq!(header.matches("lang=").count(), 1, "{header}");
        assert_eq!(
            cookies::get(request.headers(), cookies::LANG_COOKIE),
            Some("en".to_string())
        );
        assert_eq!(
            cookies::get(request.headers(), cookies::SSO_SESSION_COOKIE),
            Some("sess".to_string())
        );
    }

    fn request_with_ui_locales(cookies: &[&str], ui_locales: &str) -> Request {
        let mut request = request_with_cookies(cookies);
        request.extensions_mut().insert(RpLoginContext {
            login_hint: None,
            ui_locales: Some(ui_locales.to_string()),
        });
        request
    }

    /// 決定順 4（G12）: `ui_locales` は利用者が選んだ言語より弱く、ブラウザ言語より強い。
    /// Cookie に有効な選択が残っている間は RP の要求で切り替えない。
    #[test]
    fn ui_locales_yields_to_the_language_the_user_chose() {
        assert_eq!(
            requested_locale(&request_with_ui_locales(&["lang=ja"], "en")),
            None,
            "the user's own choice wins"
        );
        // 保存されている値が非対応（＝選択として無効）なら RP の要求を採る。
        assert_eq!(
            requested_locale(&request_with_ui_locales(&["lang=fr"], "en")),
            Some(Locale::En)
        );
        assert_eq!(
            requested_locale(&request_with_ui_locales(&[], "fr en-GB")),
            Some(Locale::En)
        );
        // 対応言語を含まない要求は決めない（下流が `Accept-Language` を使う）。
        assert_eq!(requested_locale(&request_with_ui_locales(&[], "fr")), None);
    }

    /// OIDC フロー外（文脈が載っていない）リクエストでは何も決まらない。
    #[test]
    fn ui_locales_is_absent_outside_the_authorization_flow() {
        assert_eq!(requested_locale(&request_with_cookies(&[])), None);
        let mut request = request_with_cookies(&[]);
        request.extensions_mut().insert(RpLoginContext::default());
        assert_eq!(requested_locale(&request), None);
    }

    #[test]
    fn overwrite_adds_the_cookie_when_none_was_sent() {
        let mut request = request_with_cookies(&[]);
        overwrite_lang_cookie(&mut request, Locale::Ja);
        assert_eq!(
            cookies::get(request.headers(), cookies::LANG_COOKIE),
            Some("ja".to_string())
        );
    }
}
