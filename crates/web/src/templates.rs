//! サーバレンダリング画面の Askama テンプレート定義（`templates/` 配下の `.html` に対応）。
//!
//! 旧来の `format!` による HTML 組み立てを置き換える。テンプレートは `.html` 拡張子のため
//! `{{ }}` の出力は **自動的に HTML エスケープ**され、格納型 XSS を既定で防ぐ（旧 `html::escape` の
//! 手動呼び出しは不要になった）。翻訳文言は各テンプレートが `messages.get("key")` を直接呼び出す。
//!
//! 各テンプレート構造体は対応する `.html` を `#[template(path = ...)]` で束ね、コンパイル時に
//! 型検証される（sqlx のコンパイル時クエリ検証と同じ思想）。

use crate::admin_dto::{
    AuditLogView, ClientView, SamlServiceProviderView, SigningKeyView, TenantCreatedView,
    TenantView,
};
use crate::i18n::Messages;
use askama::Template;
use idp_contracts::admin::AuthenticationPolicyResponse;
use idp_contracts::admin::{ClientStatusResponse, UserSummaryResponse};
use idp_contracts::application_log::ApplicationLogEntryResponse;
use idp_contracts::auth::PasskeyCredentialInfo;
use idp_contracts::version::{
    BuildTimeVersionInfoProvider, SchemaVersionInfo, VersionInfo, VersionInfoProvider,
};

/// フッタなどの共通 UI に表示する Cargo パッケージバージョン。
pub fn app_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// フッタに表示するバージョン表記。Git バージョン（`git describe`。ビルド時に埋め込み）が
/// 取得できていれば `v{package} ({git})`、なければパッケージ版のみ（`v{package}`）。
pub fn footer_version() -> String {
    let info = BuildTimeVersionInfoProvider::new(app_version()).version_info();
    // git 版が埋め込まれていない（ビルド引数の渡し忘れ）ときも `unknown` と出す。黙って省くと、
    // 「そもそも出ない画面」なのか「渡し忘れ」なのかが運用者に区別できない。
    format!("{} ({})", info.display_version(), info.git_version)
}

/// アセット URL に付与するキャッシュバスティング用バージョン（`/assets/app.css?v=...`）。
///
/// アセットはバイナリ同梱でデプロイ単位でしか変わらないが、URL が安定だと中間キャッシュ
/// （CDN・ブラウザ）の TTL が尽きるまで旧アセットが配られ続ける（実際に Cloudflare が
/// origin の `max-age=0` を上書きして 4 時間キャッシュさせる）。デプロイごとに URL 自体を
/// 変えることで、キャッシュ TTL に依存せず必ず新しいアセットを取得させる。
///
/// 値は「パッケージ版-同梱アセットの内容ダイジェスト」。**git 版は載せない**（ADR-0034）。
/// この URL は無認証のログイン画面（`page.html`）にも出るため、git 版を混ぜると稼働中の
/// コミットを外から読めてしまい、フッタから版数を外した意味が無くなる。アセット内容が
/// 変われば必ずダイジェストが変わるので、キャッシュバスティングには digest だけで足りる。
/// クエリ値として安全な文字（英数・`.` `-` `_`）以外は `-` へ置換する。
pub fn asset_version() -> &'static str {
    static VERSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VERSION.get_or_init(|| {
        let digest = embedded_assets_digest();
        format!("{}-{digest:016x}", app_version())
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                    c
                } else {
                    '-'
                }
            })
            .collect()
    })
}

/// `?v=` 付き URL で参照される同梱アセットの内容ダイジェスト。キャッシュバスティング用途のため
/// 暗号強度は不要（FNV-1a 64bit）。webfont は安定 URL（FA CSS 内の相対参照）でクエリを付けられず
/// ダイジェストを変えても配信 URL が変わらないため対象外。
fn embedded_assets_digest() -> u64 {
    [
        crate::handlers::stylesheet::APP_CSS,
        crate::handlers::console_script::CONSOLE_JS,
        crate::handlers::submit_feedback_script::SUBMIT_FEEDBACK_JS,
        crate::handlers::react_assets::APP_JS,
        crate::handlers::vendor_assets::BOOTSTRAP_CSS,
        crate::handlers::vendor_assets::BOOTSTRAP_JS,
        crate::handlers::vendor_assets::FONTAWESOME_CSS,
        // 画面固有スクリプト（SEC12）も `?v=` 付き・`immutable` で配信するため、内容を digest に
        // 含める。含め忘れると、JS だけを直した配置（git 版が `unknown` のビルド）で URL が
        // 変わらず、ブラウザが古いスクリプトを持ち続ける。
        crate::handlers::page_scripts::PASSKEY_LOGIN_JS,
        crate::handlers::page_scripts::PASSKEY_REGISTER_JS,
        crate::handlers::page_scripts::PASSWORD_VISIBILITY_JS,
        crate::handlers::page_scripts::RP_LOGOUT_JS,
        crate::handlers::page_scripts::AUTO_SUBMIT_JS,
        crate::handlers::page_scripts::CLIENT_FORM_JS,
    ]
    .into_iter()
    .fold(0xcbf2_9ce4_8422_2325, |hash, asset| {
        fnv1a64(hash, asset.as_bytes())
    })
}

/// FNV-1a 64bit ハッシュ（`hash` を初期値として `bytes` を畳み込む）。
fn fnv1a64(mut hash: u64, bytes: &[u8]) -> u64 {
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::{Locale, Messages};

    /// フォームが送る入力欄と、ハンドラが要求する項目の食い違いを検出する（ADR-0032）。
    ///
    /// `usage` は `NewClientForm` / `EditClientForm` の**必須**項目なので、テンプレートが描画を
    /// やめると登録が 400 になる。実際、この欄を足したとき E2E スクリプトだけが送っておらず
    /// CI で落ちた —— 描画側と受け取り側の対応は、遅い経路ではなくここで固定しておく。
    #[test]
    fn the_client_form_renders_the_controls_the_handler_requires() {
        let messages = Messages::new(Locale::Ja);
        let values = ClientFormValues::default_new();
        let form = ClientForm {
            messages: &messages,
            tenant: "/019f6514-08ea-7138-ad71-838a7bdd3575",
            admin: None,
            csrf: &"0".repeat(64),
            error: None,
            heading: "新規クライアント",
            action: "/x/admin/clients/new",
            is_new: true,
            values: &values,
            list_href: "/x/admin/clients".to_string(),
        };
        let html = render(&form);
        for control in [
            r#"name="app_name""#,
            r#"name="usage""#,
            r#"name="client_type""#,
            r#"name="redirect_uris""#,
            r#"name="scope_profile""#,
            r#"name="scope_email""#,
            r#"name="scope_offline_access""#,
            r#"name="csrf_token""#,
        ] {
            assert!(html.contains(control), "{control} が描画されていない");
        }
        // 用途は入口が決めるので、フォームは選択肢を出さず hidden で持ち回る（ADR-0038）。
        // `usage` は handler の必須項目なので、hidden が消えると登録が 400 になる。
        assert!(
            html.contains(
                r#"<input type="hidden" id="client-usage" name="usage" value="user_login">"#
            ),
            "{html}"
        );
        assert!(
            !html.contains(r#"<select class="form-select" id="client-usage""#),
            "用途の select は出さない: {html}"
        );
        // `openid` は外せない（入力欄を持たず、ハンドラが必ず付ける）。
        assert!(html.contains(r#"id="client-scope-openid""#), "{html}");
        assert!(
            !html.contains(r#"name="scope_openid""#),
            "openid を送信対象の入力欄にしない: {html}"
        );
    }

    /// ADR-0032: 用途は `client_credentials` の有無で決まる。
    #[test]
    fn usage_reflects_what_the_client_can_actually_do() {
        let login = vec!["authorization_code".to_string()];
        let system = vec!["client_credentials".to_string()];
        let uris = vec!["https://a.example.com/cb".to_string()];
        assert_eq!(
            usage_from_registration(&login, &uris),
            client_usage::USER_LOGIN
        );
        assert_eq!(usage_from_registration(&system, &[]), client_usage::SYSTEM);
        // grant が 1 つも無い（あり得ないが）ときも、システム用として扱わない。
        assert_eq!(usage_from_registration(&[], &[]), client_usage::USER_LOGIN);
        // 「両方」の姿（api は作らせない）。システム用と読むと redirect_uri の欄が隠れ、
        // 保存しただけで登録済みリダイレクト先が消える。URI を残す側へ寄せる。
        let both = vec![
            "authorization_code".to_string(),
            "client_credentials".to_string(),
        ];
        assert_eq!(
            usage_from_registration(&both, &uris),
            client_usage::USER_LOGIN
        );
    }

    #[test]
    fn asset_version_is_url_safe_and_non_empty() {
        let v = asset_version();
        assert!(!v.is_empty());
        assert!(v
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')));
    }

    /// git バージョンが注入されないビルドでもアセット内容の変化で URL が変わるよう、
    /// バージョンは必ず内容ダイジェストを含む。
    #[test]
    fn asset_version_includes_content_digest() {
        let digest = format!("{:016x}", embedded_assets_digest());
        assert!(asset_version().ends_with(&digest));
    }

    #[test]
    fn content_digest_changes_when_asset_bytes_change() {
        let base = 0xcbf2_9ce4_8422_2325;
        assert_ne!(
            fnv1a64(base, b"body { color: red }"),
            fnv1a64(base, b"body { color: blue }")
        );
        assert_ne!(fnv1a64(base, b""), fnv1a64(fnv1a64(base, b"a"), b""));
    }

    /// 再起動待機画面は「自力で設定画面へ戻る」ことと「押せる導線を持たない」ことが要件
    /// （ADR-0017）。この画面を返した直後に web が止まるため、ナビゲーションを載せるとどのリンクも
    /// 数秒間つながらず、壊れたように見える。
    #[test]
    fn the_restarting_page_reloads_itself_and_offers_no_console_navigation() {
        let messages = Messages::new(Locale::Ja);
        let html = render(&Restarting {
            messages: &messages,
            settings_href: "/t/admin/settings",
            retry_after_seconds: 20,
        });
        assert!(
            html.contains(r#"<meta http-equiv="refresh" content="20;url=/t/admin/settings">"#),
            "{html}"
        );
        assert!(
            !html.contains("<nav"),
            "no navigation while both are down: {html}"
        );
        assert!(!html.contains("/admin/logout"), "{html}");
    }

    /// ログイン画面は認可要求の `login_hint` をユーザー名欄の初期値にする（G12）。値は RP が
    /// 指定した任意の文字列なので、属性値として HTML エスケープされていることまで確かめる。
    #[test]
    fn the_login_form_prefills_the_username_from_the_login_hint() {
        let messages = Messages::new(Locale::Ja);
        let render_with = |login_hint| {
            render(&LoginTemplate {
                messages: &messages,
                tenant_prefix: "/t",
                csrf: "csrf-token",
                error_key: None,
                login_hint,
                client_name: None,
                tenant_name: None,
            })
        };

        /// ユーザー名欄の `<input>` タグだけを切り出す（他の入力欄と取り違えないため）。
        fn username_input(html: &str) -> String {
            let start = html.find(r#"id="login-username""#).expect("username input");
            let end = html[start..].find('>').expect("tag end");
            html[start..start + end].to_string()
        }

        let html = render_with(Some("alice@example.com"));
        assert!(
            username_input(&html).contains(r#"value="alice@example.com""#),
            "{html}"
        );

        // ヒントが無ければ初期値を持たない（空の value も置かない）。
        let html = render_with(None);
        assert!(!username_input(&html).contains("value="), "{html}");

        // 属性を閉じて別の属性を差し込む値は、引用符ごとエスケープされて value の中に留まる。
        let html = render_with(Some(r#"" autofocus onfocus="alert(1)"#));
        let tag = username_input(&html);
        assert!(tag.contains("alert(1)"), "the value is kept: {html}");
        // 引用符がエスケープされるので value 属性は閉じられず、`onfocus="..."` は生えない。
        assert!(
            !tag.contains(r#"onfocus=""#),
            "but never as an attribute: {html}"
        );
    }

    /// `idp.system.admin` を要する画面（エラー警告ログ・テナント管理）は、その権限を持たない
    /// 管理者のメニューに出さない。出していた頃は押すと api が 403 を返す行き止まりだった。
    #[test]
    fn the_console_hides_the_screens_this_admin_cannot_open() {
        let messages = Messages::new(Locale::Ja);
        let render_as = |permissions: &[String]| {
            render(&ConsoleHome {
                messages: &messages,
                tenant: "/t",
                admin: Some(ConsoleAdmin {
                    label: "admin",
                    tenant_name: Some("Acme"),
                    permissions,
                }),
            })
        };

        let tenant_admin = render_as(&["idp.members:read".to_string()]);
        assert!(!tenant_admin.contains("/t/admin/logs"), "{tenant_admin}");
        assert!(!tenant_admin.contains("/t/admin/tenants"), "{tenant_admin}");
        // 権限に関わらず開ける画面は残る（隠しすぎていないことの確認）。
        assert!(tenant_admin.contains("/t/admin/members"), "{tenant_admin}");

        let system_admin = render_as(&["idp.system.admin".to_string()]);
        assert!(system_admin.contains("/t/admin/logs"), "{system_admin}");
        assert!(system_admin.contains("/t/admin/tenants"), "{system_admin}");

        // 一覧が空なのは「api が古くて絞り込めない」場合なので、従来どおり全部出す
        // （権限なしと読んでメニューを消すと、新旧が混在する数秒間だけ画面が別物になる）。
        let unknown = render_as(&[]);
        assert!(unknown.contains("/t/admin/logs"), "{unknown}");
        assert!(unknown.contains("/t/admin/tenants"), "{unknown}");
    }

    /// SSO で飛ばされてきた利用者は「どこへサインインするのか」を画面からしか知れない。
    /// 見出しにアプリ名を、左上の名乗りにテナント名を出す。**引けなかったときは既定へ戻る**
    /// （api が古い・表示名が空、のどちらでもフォームは出し続ける）。
    #[test]
    fn the_login_form_names_the_application_and_the_tenant() {
        let messages = Messages::new(Locale::Ja);
        let render_with = |client_name, tenant_name| {
            render(&LoginTemplate {
                messages: &messages,
                tenant_prefix: "/t",
                csrf: "csrf-token",
                error_key: None,
                login_hint: None,
                client_name,
                tenant_name,
            })
        };

        let html = render_with(Some("PhotoNest"), Some("Acme Corp"));
        assert!(html.contains("PhotoNest にサインイン"), "{html}");
        assert!(
            html.contains(r#"<span class="navbar-brand mb-0 h1">Acme Corp</span>"#),
            "{html}"
        );

        // 名前が無いときは、名乗りも見出しも変更前の既定に戻る。
        let html = render_with(None, None);
        assert!(
            html.contains(r#"<span class="navbar-brand mb-0 h1">IdP</span>"#),
            "{html}"
        );
        assert!(html.contains(">サインイン<"), "{html}");

        // 表示名は登録値なので RP の申告ではないが、管理画面から任意の文字列が入る。
        // テンプレートのエスケープを通ることを確かめる。
        let html = render_with(Some("<script>alert(1)</script>"), None);
        assert!(!html.contains("<script>alert(1)</script>"), "{html}");
        assert!(html.contains("&#60;script&#62;"), "{html}");
    }

    /// パスキーの画面は画面内に戻る導線を持たない枝葉なので、左上の名乗りをアカウントの
    /// ホームへのリンクにする（行き止まりを作らない）。
    #[test]
    fn the_passkey_screens_offer_a_way_back_from_the_navbar() {
        let messages = Messages::new(Locale::Ja);
        let list = render(&PasskeyListTemplate {
            messages: &messages,
            tenant_prefix: "/t",
            credentials: &[],
        });
        let register = render(&PasskeyRegisterTemplate {
            messages: &messages,
            tenant_prefix: "/t",
            error_key: None,
        });
        for html in [&list, &register] {
            assert!(
                html.contains(
                    r#"<a class="navbar-brand mb-0 h1 text-decoration-none" href="/t/settings""#
                ),
                "{html}"
            );
        }
    }

    /// アセット参照はデプロイごとに URL が変わるよう `?v={asset_version}` を必ず付ける
    /// （中間キャッシュ（CDN・ブラウザ）が旧 CSS/JS を配り続けるのを防ぐ）。
    #[test]
    fn rendered_pages_reference_versioned_asset_urls() {
        let messages = Messages::new(Locale::Ja);
        let console = render(&ConsoleHome {
            messages: &messages,
            tenant: "/t",
            admin: None,
        });
        let auth = render(&ConsoleLogin {
            messages: &messages,
            tenant_prefix: "/t",
            csrf: "csrf",
            error_key: None,
        });
        let v = asset_version();
        for html in [&console, &auth] {
            assert!(html.contains(&format!("/assets/app.css?v={v}")));
            assert!(html.contains(&format!("/assets/vendor/bootstrap.min.css?v={v}")));
            assert!(html.contains(&format!("/assets/vendor/bootstrap.bundle.min.js?v={v}")));
            assert!(html.contains(&format!("/assets/react/app.js?v={v}")));
            assert!(!html.contains("/assets/app.css\""));
        }
        // 確認ダイアログの共通スクリプトは管理コンソールのレイアウト（`console/layout.html`）が
        // 読み込む。ログイン画面は `page.html` を使い、`data-confirm` を持つフォームも無いため対象外。
        assert!(console.contains(&format!("/assets/console.js?v={v}")));
        // 送信中の目印はどの画面のフォームにも要るので、両方のレイアウトが読み込む。
        for html in [&console, &auth] {
            assert!(html.contains(&format!("/assets/submit-feedback.js?v={v}")));
        }
        // 取り消された送信へ印を付けないため、確認ダイアログより後に読み込む（登録順に走る）。
        assert!(
            console.find("/assets/console.js") < console.find("/assets/submit-feedback.js"),
            "submit-feedback.js must load after console.js: {console}"
        );
        // 印を付ける DOM 操作は共有なので、それを呼ぶスクリプトより先に読み込む。
        for html in [&console, &auth] {
            assert!(html.contains(&format!("/assets/button-pending.js?v={v}")));
            assert!(
                html.find("/assets/button-pending.js") < html.find("/assets/submit-feedback.js"),
                "button-pending.js must load first: {html}"
            );
        }
        // 配色は最初の描画より前に確定させる必要があるため、スタイルシートより先に読み込む。
        for html in [&console, &auth] {
            assert!(html.contains(&format!("/assets/theme.js?v={v}")));
            assert!(
                html.find("/assets/theme.js") < html.find("/assets/vendor/bootstrap.min.css"),
                "theme.js must load before the stylesheet: {html}"
            );
            // `defer` を付けると、白い画面が描かれてから黒へ塗り替わる。
            let tag_start = html
                .find("/assets/theme.js")
                .expect("theme.js is referenced");
            let tag_end = tag_start + html[tag_start..].find('>').expect("tag end");
            assert!(
                !html[tag_start..tag_end].contains("defer"),
                "theme.js must not be deferred: {html}"
            );
        }
    }

    /// MT20: 管理コンソールの共通レイアウトに言語切替 UI がある（未ログイン画面にも出す。
    /// ログイン前に言語を変えられないと、読めない言語のままログインを強いられる）。
    /// `action` を持たない GET フォームなので、レイアウトを継承する全画面で現在のパスへ送信される。
    #[test]
    fn console_layout_offers_a_language_switcher() {
        let messages = Messages::new(Locale::Ja);
        for admin in [
            Some(ConsoleAdmin {
                label: "admin-1",
                tenant_name: None,
                permissions: &[],
            }),
            None,
        ] {
            let html = render(&ConsoleHome {
                messages: &messages,
                tenant: "/t",
                admin,
            });
            assert!(
                html.contains(&messages.get("admin-language-switch")),
                "admin={admin:?}: {html}"
            );
            assert!(html.contains(r#"name="lang" value="ja""#), "{html}");
            assert!(html.contains(r#"name="lang" value="en""#), "{html}");
            // 送信先は現在のパス（`action` を持たない）。
            assert!(!html.contains(r#"<form method="get" action"#), "{html}");
        }
    }

    /// 操作中のテナントは管理コンソールの全画面で見えていること（共通レイアウトのヘッダに出す）。
    /// テナントを取り違えた操作を防ぐための表示なので、ホームだけでなくレイアウト側に置く。
    #[test]
    fn console_layout_always_shows_the_current_tenant_for_signed_in_admins() {
        let messages = Messages::new(Locale::Ja);
        let html = render(&ConsoleHome {
            messages: &messages,
            tenant: "/t",
            admin: Some(ConsoleAdmin {
                label: "admin-1",
                tenant_name: Some("Acme Inc."),
                permissions: &[],
            }),
        });
        assert!(html.contains("Acme Inc."), "{html}");
        assert!(
            html.contains(&messages.get("admin-current-tenant")),
            "{html}"
        );
        // ヘッダのテナント表示はそのまま切り替え画面への導線を兼ねる。
        assert!(html.contains(r#"href="/t/admin/switch-tenant""#), "{html}");

        // 名前が取得できないとき（旧 api）は名前の表示だけを省き、画面は壊さない。
        let html = render(&ConsoleHome {
            messages: &messages,
            tenant: "/t",
            admin: Some(ConsoleAdmin {
                label: "admin-1",
                tenant_name: None,
                permissions: &[],
            }),
        });
        assert!(html.contains("admin-1"), "{html}");
        assert!(!html.contains("navbar-tenant-label"), "{html}");
    }

    /// IdP メタデータのダウンロード導線は api への直接リンクではなく、web のルートであること。
    #[test]
    fn saml_console_links_idp_metadata_on_the_web_origin() {
        let messages = Messages::new(Locale::Ja);
        let html = render(&SamlServiceProvidersConsole {
            messages: &messages,
            tenant: "/t",
            idp_metadata_url: "/t/admin/saml-clients/idp-metadata",
            admin: Some(ConsoleAdmin {
                label: "admin-1",
                tenant_name: None,
                permissions: &[],
            }),
            csrf: "csrf",
            saved: false,
            updated: false,
            deleted: false,
            imported: false,
            error_key: None,
            providers: &[],
            values: &SamlServiceProviderFormValues::default(),
        });
        assert!(
            html.contains(r#"href="/t/admin/saml-clients/idp-metadata""#),
            "{html}"
        );
        assert!(!html.contains("api.idp.example.com"), "{html}");
    }

    /// テンプレートに直書きする `href` / `action` のパスは、必ず **web 自身のルート**であること。
    ///
    /// api だけが提供するパスを web オリジン相対で書かない。ブラウザ向け導線が必要なら、web に
    /// 明示的なユースケースのルートを設ける（値まるごとがテンプレート式のものは静的判定の対象外）。
    #[test]
    fn template_link_targets_are_routes_this_service_serves() {
        let routes = crate::router::declared_route_paths();
        let mut checked = 0;
        for (template, raw) in template_link_targets() {
            let Some(path) = normalize_template_path(&raw) else {
                continue;
            };
            checked += 1;
            assert!(
                routes.contains(&path),
                "{template} links `{raw}` but web serves no route `{path}`; \
                 api のエンドポイントならハンドラで issuer 基点の絶対 URL を渡すこと"
            );
        }
        assert!(checked > 0, "expected link targets to check");
    }

    /// テンプレートの `href="…"` / `action="…"` / `src="…"` を (ファイル名, 値) で列挙する。
    ///
    /// `src` も見るのは、`<script src="/assets/…">` の配信ルートを足し忘れると 404 になり、
    /// 画面は描画されたまま挙動だけが黙って消えるため（実際に `client-form.js` で起きた）。
    fn template_link_targets() -> Vec<(String, String)> {
        fn walk(dir: &std::path::Path, out: &mut Vec<(String, String)>) {
            for entry in std::fs::read_dir(dir).expect("read templates dir") {
                let path = entry.expect("dir entry").path();
                if path.is_dir() {
                    walk(&path, out);
                    continue;
                }
                if path.extension().and_then(|e| e.to_str()) != Some("html") {
                    continue;
                }
                let name = path.display().to_string();
                let source = std::fs::read_to_string(&path).expect("read template");
                for attr in ["href=\"", "action=\"", "src=\""] {
                    for after in source.split(attr).skip(1) {
                        if let Some(len) = after.find('"') {
                            out.push((name.clone(), after[..len].to_string()));
                        }
                    }
                }
            }
        }
        let mut out = Vec::new();
        walk(
            std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/templates")),
            &mut out,
        );
        out
    }

    /// テンプレートの値を `router.rs` のパスと比較できる形へ正規化する。判定できない値は `None`。
    fn normalize_template_path(raw: &str) -> Option<String> {
        let raw = raw.trim();
        // 外部 URL・アンカー・空値は経路の対象外。
        if raw.is_empty()
            || raw.starts_with("http://")
            || raw.starts_with("https://")
            || raw.starts_with('#')
            || raw.starts_with("mailto:")
        {
            return None;
        }
        // 値まるごとがテンプレート式（= ハンドラが組み立てた URL。絶対 URL でありうる）。
        if raw.starts_with("{{") && raw.ends_with("}}") && raw.matches("{{").count() == 1 {
            return None;
        }
        let path = crate::router::collapse_params(raw);
        // クエリ・フラグメントは経路の同定に関係しない。
        let path = path.split(['?', '#']).next().unwrap_or_default();
        // 先頭のテナントプレフィクス（`{{ tenant }}…` / `/{{ t.id }}…`）を落とす。
        let path = path.strip_prefix("{}").unwrap_or(path);
        let path = path.strip_prefix("/{}").unwrap_or(path);
        path.starts_with('/').then(|| path.to_string())
    }

    /// `data-confirm` を持つテンプレートは、必ず共通スクリプトを読み込むレイアウトを継承していること。
    /// 継承していないと確認ダイアログが黙って出ないまま破壊的操作が送信される。
    #[test]
    fn templates_using_data_confirm_load_the_confirm_handler() {
        // `data-confirm` は `assets/console.js` のハンドラが読む属性。属性だけ書いてスクリプトを
        // 読み込み忘れると、確認ダイアログが出ないまま破壊的操作が通る（画面上は何も変わらないので
        // 気付けない）。共通レイアウト経由でも直接読み込みでもよいが、どちらかは必須とする。
        let roots = [
            concat!(env!("CARGO_MANIFEST_DIR"), "/templates"),
            concat!(env!("CARGO_MANIFEST_DIR"), "/templates/console"),
        ];
        let mut checked = 0;
        for dir in roots {
            for entry in std::fs::read_dir(dir).expect("read templates dir") {
                let path = entry.expect("dir entry").path();
                if path.extension().and_then(|e| e.to_str()) != Some("html") {
                    continue;
                }
                let source = std::fs::read_to_string(&path).expect("read template");
                if !source.contains("data-confirm=") {
                    continue;
                }
                checked += 1;
                let loads_handler = source.contains(r#"{% extends "console/layout.html" %}"#)
                    || source.contains("/assets/console.js");
                assert!(
                    loads_handler,
                    "{} uses data-confirm but never loads assets/console.js",
                    path.display()
                );
            }
        }
        assert!(checked > 0, "expected templates using data-confirm");
    }
}

/// テンプレートを描画して HTML 文字列を返す。描画エラー（実質 fmt エラーのみ）は握りつぶさず
/// ログに残し、最小限のエラーページへフォールバックする（フェイルソフト）。
pub fn render<T: Template>(template: &T) -> String {
    template.render().unwrap_or_else(|error| {
        tracing::error!(%error, "failed to render template");
        "<!DOCTYPE html><html><body><p>Internal Server Error</p></body></html>".to_string()
    })
}

/// TOTP セットアップ画面（`GET /account/mfa/totp/setup`）。
/// QR コード SVG と生シークレット（base32）を両方表示する（QR が使えないユーザー向け）。
#[derive(Template)]
#[template(path = "mfa_totp_setup.html")]
pub struct TotpSetupTemplate<'a> {
    pub messages: &'a Messages,
    /// QR コードの SVG 文字列（インライン埋め込み）。
    pub qr_svg: &'a str,
    /// base32 エンコードされた生シークレット（QR が使えないユーザー向けに直接表示）。
    pub secret_base32: &'a str,
    pub error_key: Option<&'a str>,
}

/// ログインフロー TOTP 入力ページ（`GET /mfa/totp`）。
#[derive(Template)]
#[template(path = "mfa_totp_verify.html")]
pub struct TotpVerifyTemplate<'a> {
    pub messages: &'a Messages,
    pub csrf: &'a str,
    pub error_key: Option<&'a str>,
    /// 「メールでコードを送る」導線を出すか（AP9）。
    pub email_otp_available: bool,
    /// その導線の送信先（テナントごとに変わるため呼び出し側が組み立てる）。
    pub email_otp_action: &'a str,
    /// SMS OTP の送信フォームの送信先（AP13）。導線は常に出し、未設定・未登録は送信結果で案内する。
    pub sms_otp_action: &'a str,
}
/// RP-initiated logout の front-channel 通知ページ（`GET /{tenant_id}/logout`。ADR-0018 決定 2 で
/// api から移設）。各 RP の `frontchannel_logout_uri` を不可視 iframe で読み込み、全 iframe の
/// ロード後（またはタイムアウト後）に post-logout リダイレクト先へ遷移する。
#[derive(Template)]
#[template(path = "rp_logout.html")]
pub struct RpLogoutPage<'a> {
    pub messages: &'a Messages,
    pub frontchannel_uris: &'a [String],
    pub redirect_to: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate<'a> {
    pub messages: &'a Messages,
    /// `/{tenant_id}` プレフィクス（Passkey JSON API の絶対パス組み立てに使う。ADR-0009 §6）。
    pub tenant_prefix: &'a str,
    pub csrf: &'a str,
    pub error_key: Option<&'a str>,
    /// 認可要求の `login_hint`（G12）。ログイン欄の初期値にするだけの**表示上のヒント**で、
    /// 実在するアカウントを意味しない（RP が指定した任意の文字列。テンプレートがエスケープする）。
    pub login_hint: Option<&'a str>,
    /// 認可要求を出したクライアントの表示名（api が登録済みの値から引いたもの）。見出しを
    /// 「〇〇 にサインイン」にする。`None` なら既定の見出しを出す。
    pub client_name: Option<&'a str>,
    /// フローのテナントの表示名。ナビバーの名乗りに出す。`None` なら `IdP` を出す。
    pub tenant_name: Option<&'a str>,
}

/// エンドユーザー・ポータルのログイン画面（`GET /{tenant_id}/login`。OIDC の `auth_session` を持たない
/// 直接ログイン）。IdP 自身のアカウント画面へ入るための画面で、共通レイアウトには載せない。
#[derive(Template)]
#[template(path = "portal_login.html")]
pub struct PortalLogin<'a> {
    pub messages: &'a Messages,
    /// `/{tenant_id}` プレフィクス（フォーム送信先・リンクの組み立てに使う。ADR-0009 §6）。
    pub tenant_prefix: &'a str,
    pub csrf: &'a str,
    pub error_key: Option<&'a str>,
    /// 有効な外部 IdP（AP10）。空ならボタン領域ごと出さない。
    pub external_providers: &'a [idp_contracts::auth::ExternalIdpButton],
}

/// ポータルの TOTP 入力画面（`GET /{tenant_id}/login/mfa`）。`mfa_ticket` Cookie を保持した状態で表示する。
#[derive(Template)]
#[template(path = "portal_mfa.html")]
pub struct PortalMfa<'a> {
    pub messages: &'a Messages,
    pub tenant_prefix: &'a str,
    pub csrf: &'a str,
    pub error_key: Option<&'a str>,
}

/// 同意画面（`GET /consent`、F3）。
#[derive(Template)]
#[template(path = "consent.html")]
pub struct ConsentTemplate<'a> {
    pub messages: &'a Messages,
    pub csrf: &'a str,
    pub auth_session_id: &'a str,
    pub client_name: &'a str,
    pub requested_scopes: &'a [String],
}

/// SAML SSO の自動 POST ページ（`GET /{tenant_id}/saml/continue`）。署名済み `SAMLResponse` を
/// SP の ACS へ POST するフォームを描画し、インライン JS で即時送信する（JS 無効時は送信ボタン）。
/// 送信先が外部オリジンのため、ハンドラは ACS オリジンを `form-action` に許可した CSP を付ける。
#[derive(Template)]
#[template(path = "saml_post.html")]
pub struct SamlPostPage<'a> {
    pub messages: &'a Messages,
    pub acs_url: &'a str,
    /// base64 済みの SAML Response（テンプレートが hidden input へエスケープして埋め込む）。
    pub saml_response: &'a str,
    pub relay_state: Option<&'a str>,
}

/// タイトルと本文のみの最小ページ（ログインのエラー・権限不足など、共通レイアウトに載せない画面）。
#[derive(Template)]
#[template(path = "message_page.html")]
pub struct MessagePage {
    pub title: String,
    pub message: String,
}

/// HTTP エラーページ（全ステータスコード対応。403 / 404 / 500 等）。ステータスコードを大きく表示し、
/// タイトルと説明文を添える。テナント文脈を持たない未マッチ経路（fallback）でも描画できるよう、
/// 翻訳済みの文字列だけを受け取る（`Messages` へは依存しない）。
/// 描画の入口は `crate::error_pages`（ハンドラから直接呼ぶ `page()` と、全エラー応答を揃える
/// ミドルウェア）に集約する。
#[derive(Template)]
#[template(path = "error_page.html")]
pub struct ErrorPage {
    /// 表示するステータスコード（例 `"404"`）。
    pub code: String,
    pub title: String,
    pub message: String,
}

/// バージョン情報ページ（`GET /{tenant_id}/admin/version`）。
///
/// **管理コンソールの内側にある**（ADR-0034）。稼働中のコミットが分かると、どの既知の不具合が
/// 塞がっていないかを外から判断できるため、無認証の面には出さない。
#[derive(Template)]
#[template(path = "console/version.html")]
pub struct VersionTemplate<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub info: VersionInfo,
    /// DB スキーマ（マイグレーション）の適用状態。api から取得できなければ `None`（画面は
    /// 「取得できません」を表示）。web は DB を持たないため api 経由で受け取る。
    pub schema: Option<SchemaVersionInfo>,
}

/// 強制パスワード変更画面（`GET /{tenant_id}/password-change`、ADR-0009 §5）。ログインフロー中
/// （パスワード検証済み・SSO 未発行）に表示する。共通レイアウトには載せない。
#[derive(Template)]
#[template(path = "password_change.html")]
pub struct PasswordChangeTemplate<'a> {
    pub messages: &'a Messages,
    pub csrf: &'a str,
    pub error_key: Option<&'a str>,
}

/// 強制パスワード変更画面（初回ログイン時。ADR-0009 §5）。管理コンソールログイン
/// （`POST /{tenant_id}/admin/password-change`）とポータル（一般）ログイン
/// （`POST /{tenant_id}/login/password-change`）で共有する。どちらも一時状態を持たないため、
/// `username`（ログイン識別子）を隠しフィールドで維持し、フォーム送信先は `action` で切り替える。
/// OIDC ログインの強制変更（[`PasswordChangeTemplate`]）は `auth_session_id` で本人を識別するため別画面。
#[derive(Template)]
#[template(path = "password_change_forced.html")]
pub struct ForcedPasswordChange<'a> {
    pub messages: &'a Messages,
    /// フォーム送信先の絶対パス（例 `/{tenant_id}/admin/password-change`）。
    pub action: &'a str,
    pub csrf: &'a str,
    pub username: &'a str,
    pub error_key: Option<&'a str>,
}

/// 管理コンソール共通レイアウトのヘッダに載せる管理セッションの文脈。
///
/// 「いま誰として・どのテナントを操作しているか」はコンソール全画面で常に見えている必要がある
/// （テナントを取り違えた操作を防ぐ）。両方とも api の whoami 応答から一度に得られるため、
/// 画面ごとの追加取得はしない。
#[derive(Debug, Clone, Copy)]
pub struct ConsoleAdmin<'a> {
    /// 管理者の表示ラベル（表示名 → ログイン識別子 → 内部 ID）。
    pub label: &'a str,
    /// 操作中テナントの表示名。api が返さなかった場合のみ `None`（名前の表示だけを省く）。
    pub tenant_name: Option<&'a str>,
    /// この管理者が行使できる権限コード（api が含意を展開済み）。メニューの出し分けに使う。
    pub permissions: &'a [String],
}

impl ConsoleAdmin<'_> {
    /// 指定の権限を要する画面へのリンクを出すか（メニューを出すかの判定）。
    ///
    /// **一覧が空のときは `true` を返す。** 空になるのは api が古くこのフィールドを返さないとき
    /// （ローリングデプロイの数秒間）で、そこを「権限なし」と読むとメニューがごっそり消える。
    /// 管理コンソールに入れている時点で最低でも `idp.tenant.admin` は保有しており、空は
    /// 「絞り込めない」を意味する。押した先で api が 403 を返すのは従来どおり。
    pub fn can(&self, permission_code: &str) -> bool {
        self.permissions.is_empty() || self.permissions.iter().any(|code| code == permission_code)
    }
}

/// 共通レイアウトのヘッダ文脈（未認証時は `None`）。
/// 各コンソール画面テンプレートが持ち、`console/layout.html` から参照される。
pub type Admin<'a> = Option<ConsoleAdmin<'a>>;

/// 管理コンソールのホーム（`GET /{tenant_id}/admin`）。
#[derive(Template)]
#[template(path = "console/home.html")]
pub struct ConsoleHome<'a> {
    pub messages: &'a Messages,
    /// `/{tenant_id}` プレフィクス（ADR-0009 §6）。
    pub tenant: &'a str,
    pub admin: Admin<'a>,
}

/// 管理コンソールのログイン画面（`GET /{tenant_id}/admin/login`）。共通レイアウトには載せない。
#[derive(Template)]
#[template(path = "console/login.html")]
pub struct ConsoleLogin<'a> {
    pub messages: &'a Messages,
    /// `/{tenant_id}` プレフィクス。パスワード忘れの導線（`/forgot-password`）の組み立てに使う。
    pub tenant_prefix: &'a str,
    pub csrf: &'a str,
    pub error_key: Option<&'a str>,
}

/// 共通レイアウト上の告知（エラーバナー・404・戻るリンク付きメッセージ）。各コンソール画面の
/// エラー系レスポンスで再利用する。`is_error` で `role="alert"` の付いたエラーバナー表示を切り替える。
#[derive(Template)]
#[template(path = "console/notice.html")]
pub struct ConsoleNotice<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub heading: Option<&'a str>,
    pub message: &'a str,
    pub is_error: bool,
    pub back_href: Option<&'a str>,
    pub back_label: &'a str,
}

/// 監査ログ一覧（`GET /{tenant_id}/admin/audit-logs`）。フィルタ値は再入力用に展開済み文字列で渡す。
/// ページャの前後リンク（クエリ文字列を組み立て済み）は該当がなければ `None`。
#[derive(Template)]
#[template(path = "console/audit_logs.html")]
pub struct AuditLogs<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub date_error: bool,
    pub event_type: &'a str,
    pub result: &'a str,
    pub client_id: &'a str,
    pub correlation_id: &'a str,
    pub from: &'a str,
    pub to: &'a str,
    pub entries: &'a [AuditLogView],
    pub prev_href: Option<String>,
    pub next_href: Option<String>,
}

/// エラー・警告ログ一覧（`GET /{tenant_id}/admin/logs`）。フィルタ値は再入力用に展開済み文字列で渡す。
/// ページャの前後リンク（クエリ文字列を組み立て済み）は該当がなければ `None`。
#[derive(Template)]
#[template(path = "console/application_logs.html")]
pub struct ApplicationLogs<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub date_error: bool,
    pub level: &'a str,
    pub service: &'a str,
    pub target: &'a str,
    pub correlation_id: &'a str,
    pub from: &'a str,
    pub to: &'a str,
    pub entries: &'a [ApplicationLogEntryResponse],
    pub prev_href: Option<String>,
    pub next_href: Option<String>,
}

/// クライアント状況一覧（`GET /{tenant_id}/admin/status`）。
#[derive(Template)]
#[template(path = "console/client_status.html")]
pub struct ClientStatus<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub views: &'a [ClientStatusResponse],
}

/// 利用者の権限画面（`GET /{tenant_id}/admin/users/{id}/permissions`）。
#[derive(Template)]
#[template(path = "console/users_permissions.html")]
pub struct UsersPermissions<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub user: &'a UserSummaryResponse,
    /// この利用者が現在保有している権限コード。
    pub codes: &'a [String],
    /// いま付与できる権限コード（付与可能コードから保有済みを除いたもの）。選択肢として出す。
    pub grantable: &'a [String],
    /// 付与可能コードの一覧を api から取得できなかったか。`true` のときは選択肢を出せないため、
    /// 「候補が無い」との取り違えを避けて取得失敗であることを伝える。
    pub available_load_failed: bool,
    pub csrf: &'a str,
    pub error_key: Option<&'a str>,
    /// プロフィール保存の完了通知（Post/Redirect/Get で戻ったときに成功バナーを出す。MT25）。
    pub saved: bool,
}

/// 利用者作成フォーム（`GET/POST /{tenant_id}/admin/users/new`、ADR-0009 §5・§6）。
#[derive(Template)]
#[template(path = "console/user_form.html")]
pub struct UserForm<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub csrf: &'a str,
    pub error: Option<&'a str>,
    pub email: &'a str,
    pub preferred_username: &'a str,
    pub name: &'a str,
}

/// 利用者作成結果（`POST /{tenant_id}/admin/users/new` 成功時）。`generated_password` を一度だけ表示する。
#[derive(Template)]
#[template(path = "console/user_created.html")]
pub struct UserCreated<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub email: &'a str,
    pub generated_password: &'a str,
}

/// メンバー一覧（`GET /{tenant_id}/admin/members`。HOME / GUEST を問わない。ADR-0009 §3）。
#[derive(Template)]
#[template(path = "console/members_list.html")]
pub struct MembersList<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    /// 現在のページに含まれるメンバー（MT22 でページングを導入。全件ではない）。
    pub members: &'a [crate::admin_dto::MemberView],
    /// 絞り込み後の総件数（ページング前）。「全 N 件」の表示に使う。
    pub total: i64,
    /// 現在の絞り込み語（検索ボックスの再表示用。空なら未絞り込み）。
    pub query: &'a str,
    pub csrf: &'a str,
    pub error_key: Option<&'a str>,
    /// 完了通知の翻訳キー（Post/Redirect/Get で戻ったときの操作結果。MT21 の MFA 解除など）。
    pub notice_key: Option<&'a str>,
    /// ページャの前後リンク（クエリ文字列を組み立て済み）。該当がなければ `None`。
    pub prev_href: Option<String>,
    pub next_href: Option<String>,
}

/// 管理者によるパスワード再発行の結果画面（一度限りの生成パスワード表示。ADR-0009 §5）。
/// メンバー一覧（HOME 利用者）とテナント管理（子テナント管理者）の双方から使う。
#[derive(Template)]
#[template(path = "console/password_reset_result.html")]
pub struct PasswordResetResult<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    /// 対象の表示（メールアドレス等）。
    pub subject: &'a str,
    /// 生成パスワード（平文。一度限り表示）。
    pub generated_password: &'a str,
    pub back_href: &'a str,
    /// 戻りリンクの文言キー。
    pub back_label_key: &'a str,
}

/// ゲスト招待フォーム（`GET/POST /{tenant_id}/admin/invitations`、ADR-0009 §3）。
#[derive(Template)]
#[template(path = "console/invitation_form.html")]
pub struct InvitationForm<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub csrf: &'a str,
    pub error: Option<&'a str>,
    pub user_id: &'a str,
}

/// ゲスト招待作成結果（`POST /{tenant_id}/admin/invitations` 成功時）。招待トークンを一度だけ表示する。
#[derive(Template)]
#[template(path = "console/invitation_created.html")]
pub struct InvitationCreated<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub token: &'a str,
    pub expires_at: &'a str,
    /// 招待メール（承諾リンク）を送信できたか（MT17）。false ならトークンの手動伝達を促す。
    pub email_sent: bool,
    pub invitee_email: &'a str,
}

/// パスワードリセット要求画面（`GET/POST /{tenant_id}/forgot-password`。MT18）。未ログイン経路。
/// 要求受理後はアカウントの有無を問わず同じ完了文言を表示する（列挙防止）。
#[derive(Template)]
#[template(path = "forgot_password.html")]
pub struct ForgotPassword<'a> {
    pub messages: &'a Messages,
    /// 要求を受理した後の完了表示。
    pub accepted: bool,
    pub error_key: Option<&'a str>,
}

/// パスワード再設定画面（`GET/POST /{tenant_id}/password-reset?token=...`。MT18）。
/// リセットメールのリンクから開く。
#[derive(Template)]
#[template(path = "password_reset.html")]
pub struct PasswordReset<'a> {
    pub messages: &'a Messages,
    pub tenant_prefix: &'a str,
    pub show_form: bool,
    pub token: &'a str,
    pub success: bool,
    pub error_key: Option<&'a str>,
}

/// 招待承諾画面（`GET/POST /{tenant_id}/invitations/accept`。MT17）。被招待者本人が招待メールの
/// リンクから開く。共通レイアウト（管理コンソール）には載せない。
#[derive(Template)]
#[template(path = "invitation_accept.html")]
pub struct InvitationAccept<'a> {
    pub messages: &'a Messages,
    /// 承諾フォームを表示するか（SSO ログイン済みのときのみ true）。
    pub show_form: bool,
    pub token: &'a str,
    pub csrf: &'a str,
    /// 承諾に成功したか（成功画面表示）。
    pub success: bool,
    pub error_key: Option<&'a str>,
}

/// メール検証画面（`GET/POST /{tenant_id}/verify-email?token=...`。SEC6b）。自己登録の確認メールの
/// リンクから開く。GET は確認ボタン（POST でトークンを消費）を表示し、リンクのプリフェッチで
/// トークンを消費しないようにする。未ログイン経路（SSO 不要）。
#[derive(Template)]
#[template(path = "verify_email.html")]
pub struct VerifyEmail<'a> {
    pub messages: &'a Messages,
    /// 確認フォーム（POST ボタン）を表示するか（トークンがあるとき true）。
    pub show_form: bool,
    pub token: &'a str,
    /// 検証に成功したか（成功画面表示）。
    pub success: bool,
    pub error_key: Option<&'a str>,
}

/// クライアント登録・編集フォームの入力値（新規/再表示の両方で使う）。テンプレートの再入力欄へ
/// そのまま流し込む。`redirect_uris` は 1 行 1 URI、`scopes` は空白区切りの生文字列。
pub struct ClientFormValues {
    pub app_name: String,
    pub client_type: String,
    pub redirect_uris: String,
    pub scopes: String,
    pub client_status: String,
    /// クライアントの用途（`client_usage` のいずれか）。画面ではこれを最初に選ばせ、以降の入力欄を
    /// 切り替える。api はこの値を持たず、`redirect_uris` の有無と `client_credentials` の可否という
    /// 2 つの値で同じことを表す（ADR-0032）。
    pub usage: String,
    /// クライアント認証方式（G3）。confidential のみ選択でき、public は常に `none`。
    pub token_endpoint_auth_method: String,
    /// `private_key_jwt` の検証鍵（JWK Set の JSON。ADR-0030）。公開鍵しか含まないため、
    /// 編集フォームへ現在値を出して差し支えない（ローテーション中の確認に要る）。
    pub jwks: String,
}

/// クライアントの用途。コンソールの入力単位であって、api のモデルには無い（ADR-0032）。
///
/// 「redirect_uri を持つか」「`client_credentials` を許すか」は独立した 2 値だが、管理者が実際に
/// 決めたいのは「何に使うクライアントか」1 つである。2 値のまま見せると、両方を空にした
/// 何もできないクライアントや、ブラウザから使わないのに URI を捏造した登録が生まれる。
pub mod client_usage {
    /// ブラウザで利用者をログインさせる（authorization_code）。
    pub const USER_LOGIN: &str = "user_login";
    /// システムが API を呼ぶ（client_credentials）。利用者が不在なので redirect_uri を持たない。
    pub const SYSTEM: &str = "system";
}

impl ClientFormValues {
    /// この scope が選ばれているか（テンプレートのチェック状態）。
    ///
    /// 空白区切りの保持形を分解して照合する。部分一致で見ないのは、`profile` が
    /// 将来の `profile_extended` のような値に引っかかると、選んでいない欄が
    /// 選ばれて見えるためである。
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.split_whitespace().any(|s| s == scope)
    }

    /// 新規登録フォームの初期値（confidential・PKCE 必須・openid スコープ）。
    ///
    /// 認証方式の既定は `private_key_jwt`。共有シークレットは IdP 側にも保存され、クライアント側の
    /// 設定ファイルにも置かれ、要求ごとにネットワークを流れる（ADR-0030）。**既定は、選ぶ人が
    /// 何も考えなかったときに置かれる値**なので、そこを安全な側にしておく。
    pub fn default_new() -> Self {
        Self {
            app_name: String::new(),
            client_type: "confidential".to_string(),
            redirect_uris: String::new(),
            scopes: "openid".to_string(),
            client_status: "ACTIVE".to_string(),
            usage: client_usage::USER_LOGIN.to_string(),
            token_endpoint_auth_method: "private_key_jwt".to_string(),
            jwks: String::new(),
        }
    }

    /// 既存クライアントから編集フォームの初期値を作る（URI は改行区切り、scope は空白区切り）。
    pub fn from_client(c: &ClientView) -> Self {
        Self {
            app_name: c.app_name.clone(),
            client_type: c.client_type.clone(),
            redirect_uris: c.redirect_uris.join("\n"),
            scopes: c.scopes.join(" "),
            client_status: c.client_status.clone(),
            // 用途の真の出所は api が返す登録内容（G4）。フォームはその写しを表示する。
            usage: usage_from_registration(&c.grant_types, &c.redirect_uris),
            token_endpoint_auth_method: c.token_endpoint_auth_method.clone(),
            jwks: c.jwks.clone().unwrap_or_default(),
        }
    }
}

/// 登録済みの内容から画面上の用途を決める。
///
/// システム用は「`client_credentials` を持ち、かつ redirect_uri を持たない」もの。
/// `client_credentials` の有無だけで決めないのは、**用途で表せない登録を URI を残す側へ寄せる**ため。
/// 「両方」の姿（`authorization_code` + `client_credentials` + redirect_uri）は api が登録・更新の
/// どちらでも拒むので作れないが（ADR-0032 Revised）、DB を直接触るなどして存在した場合に
/// システム用と読むと、redirect_uri の欄を隠したまま保存させ、表示もしていない登録済み
/// リダイレクト先を黙って全消しする（＝稼働中のログインが `unauthorized_client` で止まる）。
/// この読みなら、保存しても api が `api-client-usage-conflict` で断るだけで済む。
fn usage_from_registration(grant_types: &[String], redirect_uris: &[String]) -> String {
    if grant_types.iter().any(|g| g == "client_credentials") && redirect_uris.is_empty() {
        client_usage::SYSTEM
    } else {
        client_usage::USER_LOGIN
    }
    .to_string()
}

/// 外部 IdP の一覧（`GET /{tenant_id}/admin/external-idps`。AP16。API は AP10）。
///
/// **登録フォームはこの画面に置かない。** プロトコル（OIDC / SAML）で必要な項目がまったく違い、
/// 1 枚のフォームに両方を並べると「いま何を登録しているのか」が読み取れない。入口でプロトコルを
/// 選ばせ、以降はそのプロトコルの画面だけを見せる（ADR-0038 が用途で登録を分けたのと同じ形）。
#[derive(Template)]
#[template(path = "console/external_idps.html")]
pub struct ExternalIdpsConsole<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub csrf: &'a str,
    pub providers: &'a [crate::admin_dto::ExternalIdpView],
    pub saved: bool,
    pub deleted: bool,
    pub error_key: Option<&'a str>,
}

/// 登録するプロトコルの選択（`GET /{tenant_id}/admin/external-idps/new`）。
///
/// ここが登録の入口である。OIDC と SAML は「同じものの設定違い」ではなく、相手から何を受け取り
/// 何で真正性を確かめるかが別なので、先に決めてもらう。
#[derive(Template)]
#[template(path = "console/external_idp_choose.html")]
pub struct ExternalIdpProtocolChoice<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
}

/// 外部 IdP の登録・編集フォーム（`GET /{tenant_id}/admin/external-idps/new/{protocol}` および
/// `GET /{tenant_id}/admin/external-idps/{id}/edit`）。
///
/// **プロトコルは画面に入る前に決まっている。** 新規は URL が、編集は登録済みの値が決めるため、
/// フォームの中に選択肢は無い（登録後のプロトコル変更は api も拒否する）。
#[derive(Template)]
#[template(path = "console/external_idp_form.html")]
pub struct ExternalIdpFormPage<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub csrf: &'a str,
    /// 編集対象の id（`None` は新規登録）。
    pub editing: Option<&'a str>,
    /// フォームの初期値（編集時は対象の現在値、新規は既定値）。
    pub values: &'a ExternalIdpFormValues,
    /// メタデータ取り込みでフォームに初期値が入った直後か（AP12）。
    pub imported: bool,
    pub error_key: Option<&'a str>,
}

/// 外部 IdP 設定フォームの値（往復用）。可変長の値（`scopes`・SAML の証明書）は 1 つの
/// 文字列で保持する（scope は空白区切り、証明書は空行区切り）。
///
/// **プロトコルで使う欄が変わるが、構造体は 1 つにする。** OIDC 用と SAML 用に分けても、
/// 画面が持ち回る値の形は変わらない（プロトコルは画面に入る前に決まっており、取り違えは
/// 起きない）。妥当な組み合わせの判断は api（`ExternalIdpConfig`）が単一の出所として持つ。
#[derive(Debug, Clone)]
pub struct ExternalIdpFormValues {
    pub provider_code: String,
    pub display_name: String,
    /// `oidc` / `saml`。登録後は変更できない（api が拒否する。既存の連携が別プロトコルの
    /// 識別子を指したまま残るため）。
    pub protocol: String,
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub client_id: String,
    /// シークレットは api が返さないため値は持たない。**設定済みかどうか**だけを画面へ渡し、
    /// 編集時の空欄は「変更しない」を意味する（空欄を削除と解釈すると、他の項目を直しただけで
    /// 連携が壊れる）。
    pub has_client_secret: bool,
    pub scopes: String,
    /// SAML: IdP の `SingleSignOnService` URL。
    pub saml_sso_url: String,
    /// SAML: 署名検証に使う証明書。空行区切りで複数書ける（証明書更新期間は新旧 2 枚が同時に有効）。
    pub saml_certificates: String,
    pub saml_name_id_format: String,
    pub enabled: bool,
    pub allow_auto_link: bool,
}

/// チェックボックスで選ばせる scope。`openid` は ID Token を得るために必ず要る（外せない）ので
/// 含めない —— 選べない項目を選択肢に並べると、外せるように見える。
///
/// **ここだけを増やしても選択肢は増えない。** チェックボックスの `name`（`scope_*`）は
/// `console/external_idp_form.html` に、送信値の組み立ては
/// `handlers::admin_external_idps_console::selected_scopes` にそれぞれ直接書いてある。片方だけ
/// 足すと、その scope は自由入力欄から除かれるのにチェックボックスも無い状態になり、**保存の
/// たびに黙って落ちる**。増やすときは 3 か所を揃える。
pub const EXTERNAL_IDP_OPTIONAL_SCOPES: [&str; 2] = ["profile", "email"];

impl ExternalIdpFormValues {
    pub fn is_saml(&self) -> bool {
        self.protocol == "saml"
    }

    /// この scope が選ばれているか（テンプレートのチェック状態）。空白区切りの保持形を分解して
    /// 照合する。部分一致で見ないのは、`email` が相手方の `email_verified` のような値に
    /// 引っかかると、選んでいない欄が選ばれて見えるためである。
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.split_whitespace().any(|s| s == scope)
    }

    /// チェックボックスに無い scope（空白区切り）。
    ///
    /// **外部 IdP へ要求する scope は相手が定義する**ので、選択肢を固定値に閉じてはいけない
    /// （`groups`・`User.Read` のような相手固有の値がある）。よく使う 2 つをチェックボックスに
    /// 出し、それ以外はこの欄で受ける。`openid` は常に付くので、ここには出さない。
    pub fn extra_scopes(&self) -> String {
        self.scopes
            .split_whitespace()
            .filter(|s| *s != "openid" && !EXTERNAL_IDP_OPTIONAL_SCOPES.contains(s))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

impl Default for ExternalIdpFormValues {
    fn default() -> Self {
        Self {
            provider_code: String::new(),
            display_name: String::new(),
            protocol: "oidc".to_string(),
            issuer: String::new(),
            authorization_endpoint: String::new(),
            token_endpoint: String::new(),
            jwks_uri: String::new(),
            client_id: String::new(),
            has_client_secret: false,
            // OIDC の最小構成。api の既定値と同じ。
            scopes: "openid profile email".to_string(),
            saml_sso_url: String::new(),
            saml_certificates: String::new(),
            saml_name_id_format: String::new(),
            enabled: true,
            // 自動連携は既定 OFF（検証済みメール一致だけで既存アカウントへ入れる設定のため）。
            allow_auto_link: false,
        }
    }
}

/// ログイン識別子の管理画面（`GET /{tenant_id}/admin/users/{user_id}/login-identifiers`。AP16。API は AP8）。
#[derive(Template)]
#[template(path = "console/login_identifiers.html")]
pub struct LoginIdentifiersConsole<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub csrf: &'a str,
    pub user_id: &'a str,
    pub identifiers: &'a [LoginIdentifierRow<'a>],
    pub type_options: &'a [LoginIdentifierTypeOption<'a>],
    pub error_key: Option<&'a str>,
    pub notice_key: Option<&'a str>,
}

/// 一覧の 1 行。種別の訳文はハンドラ側で解決して渡す（テンプレートで翻訳キーを組み立てない）。
pub struct LoginIdentifierRow<'a> {
    /// 登録簿の行 id。`None` は主たる識別子（合成行）で、識別子単位の操作ができない。
    pub id: Option<&'a str>,
    pub type_label: String,
    pub display_value: &'a str,
    pub normalized_value: &'a str,
    pub is_active: bool,
    pub is_primary: bool,
}

/// 追加フォームの種別プルダウンの選択肢。
pub struct LoginIdentifierTypeOption<'a> {
    pub code: &'a str,
    pub label: String,
}

/// `response_mode=form_post` の認可応答ページ（G12）。認可コードを URL ではなくフォーム本文で
/// RP へ渡す。描画の判断は [`crate::authorization_response`] に集約してある。
#[derive(Template)]
#[template(path = "authorization_post.html")]
pub struct AuthorizationPost<'a> {
    pub messages: &'a Messages,
    /// フォームの送信先（`redirect_uri`。認可応答のパラメータは載っていない）。
    pub action: &'a str,
    /// hidden フィールド（`code` / `state`、またはエラー）。値はテンプレートが自動エスケープする。
    pub fields: &'a [(String, String)],
}

/// クライアント一覧（`GET /{tenant_id}/admin/clients`）。
#[derive(Template)]
#[template(path = "console/clients_list.html")]
pub struct ClientsList<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    /// 一覧の見出し。連携先（OIDC）とサービスアカウントで同じテンプレートを使い分ける（ADR-0038）。
    pub title: String,
    /// 「新規登録」ボタンの文言と遷移先。用途はこの入口で決まる。
    pub new_label: String,
    pub new_href: String,
    /// 1 件も無いときの文言。系統によって「まだ登録されていない」の意味が違う。
    pub none_label: String,
    /// 現在のページに含まれるクライアント（G7 でページングを導入。全件ではない）。
    pub clients: &'a [ClientView],
    /// ページング前の総件数。「全 N 件」の表示に使う。
    pub total: i64,
    /// ページャの前後リンク（クエリ文字列を組み立て済み）。該当がなければ `None`。
    pub prev_href: Option<String>,
    pub next_href: Option<String>,
}

/// クライアント登録・編集フォーム（`is_new` で新規/編集を切り替える）。
#[derive(Template)]
#[template(path = "console/client_form.html")]
pub struct ClientForm<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub csrf: &'a str,
    pub error: Option<&'a str>,
    pub heading: &'a str,
    pub action: &'a str,
    pub is_new: bool,
    pub values: &'a ClientFormValues,
    /// 戻り先の一覧（ADR-0038 でクライアント一覧が系統ごとに分かれたため、固定にできない）。
    pub list_href: String,
}

/// クライアント詳細（`GET /{tenant_id}/admin/clients/{id}`）。
#[derive(Template)]
#[template(path = "console/client_detail.html")]
pub struct ClientDetail<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub client: &'a ClientView,
    pub csrf: &'a str,
    /// このクライアントが現在保有している管理権限コード（ADR-0037）。
    pub permission_codes: &'a [String],
    /// いま付与できる権限コード（クライアントへ付与可能なコードから保有済みを除いたもの）。
    pub grantable_permissions: &'a [String],
    /// 付与可能コードを api から取得できなかったか。`true` のときは選択肢を出せないため、
    /// 「候補が無い」との取り違えを避けて取得失敗であることを伝える。
    pub permissions_load_failed: bool,
    /// 管理権限の区画を出すか。**システム用クライアント（`client_credentials` が使える）か、
    /// 既に権限を保有している場合だけ**出す。ブラウザログイン用クライアントに付けても
    /// 管理トークンを取る手段が無く、効かない操作を見せることになる（ADR-0037）。
    pub shows_permissions: bool,
    /// 付与フォームを出すか。**システム用クライアントのときだけ** true。剥奪（`shows_permissions`）
    /// と分けるのは、権限が残っているだけのブラウザログイン用クライアントに対して、効かない権限を
    /// 新たに足せてしまうのを防ぐため（ADR-0037）。
    pub shows_grant_form: bool,
    pub error_key: Option<&'a str>,
    /// 戻り先の一覧（ADR-0038）。登録内容から決まる系統の一覧へ戻す。
    pub list_href: String,
}

/// secret 表示画面（作成直後・再発行直後。`secret` が `None` なら public で秘密なし）。
#[derive(Template)]
#[template(path = "console/client_secret.html")]
pub struct ClientSecret<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub heading: &'a str,
    pub client_id: &'a str,
    pub secret: Option<&'a str>,
    /// 戻り先の一覧（ADR-0038）。
    pub list_href: String,
}

/// 署名鍵一覧・管理画面（`GET /{tenant_id}/admin/signing-keys`、K1）。
#[derive(Template)]
#[template(path = "console/signing_keys.html")]
pub struct SigningKeysList<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub keys: &'a [SigningKeyView],
    pub csrf: &'a str,
    pub error: Option<&'a str>,
}

/// root 管理者向けのテナント一覧・登録画面（`GET /{tenant_id}/admin/tenants`）。
#[derive(Template)]
#[template(path = "console/tenants.html")]
pub struct TenantsConsole<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    /// 現在のページに含まれる子テナント（G7 でページングを導入。全件ではない）。
    pub tenants: &'a [TenantView],
    /// ページング前の総件数。「全 N 件」の表示に使う。
    pub total: i64,
    pub csrf: &'a str,
    pub error_key: Option<&'a str>,
    /// 更新完了通知（Post/Redirect/Get で戻ったときに成功バナーを出す。MT23）。
    pub saved: bool,
    /// ページャの前後リンク（クエリ文字列を組み立て済み）。該当がなければ `None`。
    pub prev_href: Option<String>,
    pub next_href: Option<String>,
}

/// テナント切り替え画面（`GET /{tenant_id}/admin/switch-tenant`）。ログイン中ユーザーが `ACTIVE` な
/// メンバーシップを持つテナントを一覧し、対象テナントの管理コンソールへ遷移する。SSO はホスト共有の
/// ため再ログインは不要（ADR-0009 §8）。
#[derive(Template)]
#[template(path = "console/switch_tenant.html")]
pub struct SwitchTenant<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    /// 切り替え可能なテナント一覧。
    pub tenants: &'a [idp_contracts::auth::AccountTenantSummary],
    /// 現在開いているテナントの内部 ID（現在地の強調に使う）。
    pub current_tenant_id: &'a str,
    /// api からの一覧取得に失敗したか（失敗時は注意文言を表示する）。
    pub load_failed: bool,
}

/// テナント作成結果（`POST /{tenant_id}/admin/tenants` 成功時）。
#[derive(Template)]
#[template(path = "console/tenant_created.html")]
pub struct TenantCreated<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub created: &'a TenantCreatedView,
}

/// 管理コンソールの設定画面（`GET /{tenant_id}/admin/settings`。MT14）。テナント設定区画（自テナント
/// 表示名）と、root（idp.system.admin）のみ表示するシステム設定区画（SMTP）。`system` が `None` の
/// ときはシステム設定区画を描画しない。
#[derive(Template)]
#[template(path = "console/admin_settings.html")]
pub struct AdminSettings<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub tenant_id: &'a str,
    pub tenant_name: &'a str,
    pub tenant_status: &'a str,
    /// 自己登録（/auth/register）の許可トグル（SEC6）。
    pub tenant_self_registration: bool,
    pub csrf: &'a str,
    /// 保存成功のバナー表示。
    pub saved: bool,
    pub error_key: Option<&'a str>,
    /// root のみ `Some`。SMTP 設定区画を描画する。
    pub system: Option<&'a crate::admin_dto::SystemSettingsView>,
    /// 保存済みだが api へ未反映のキー名（MT27）。空なら未反映なし。
    pub pending_api_keys: &'a [String],
    /// api は反映済みだが web が古い共有キー名（MT27）。api だけを再起動した状態で残る。
    pub stale_web_keys: &'a [String],
}

/// 再起動中の待機画面（`POST /{tenant_id}/admin/restart` の応答。ADR-0017）。
///
/// これを返した直後に web 自身が停止するため、共通レイアウト（ナビゲーション）は継承しない。
#[derive(Template)]
#[template(path = "console/restarting.html")]
pub struct Restarting<'a> {
    pub messages: &'a Messages,
    /// 再読み込み先（設定画面）。
    pub settings_href: &'a str,
    /// 自動再読み込みまでの秒数。両サービスが起動し直すのに要する時間より少し長く取る。
    pub retry_after_seconds: u64,
}

/// 利用者のセルフサービス設定画面（`GET /{tenant_id}/settings`。MT15）。パスワード変更・言語設定・
/// MFA への導線。管理コンソールとは別の利用者向け画面のため共通レイアウトには載せない。
#[derive(Template)]
#[template(path = "user_settings.html")]
pub struct UserSettings<'a> {
    pub messages: &'a Messages,
    /// `/{tenant_id}` プレフィクス（フォーム送信先・MFA リンクの組み立てに使う。ADR-0009 §6）。
    pub tenant: &'a str,
    /// 現在の表示言語（`ja` / `en`）。言語セレクタの初期選択に使う。
    pub current_lang: &'a str,
    /// 現在の配色（`light` / `dark` / `system`）。配色セレクタの初期選択に使う。
    pub current_theme: &'a str,
    /// 現在の表示名（プリフィル用。未設定なら空文字）。
    pub current_name: &'a str,
    /// ログイン識別子（表示のみ・変更不可。未設定なら空文字）。
    pub preferred_username: &'a str,
    /// 保存成功メッセージのキー（`None` なら非表示）。
    pub saved_key: Option<&'a str>,
    pub error_key: Option<&'a str>,
    /// 管理コンソール（`?from=admin`）から開いたか。左上に戻るリンクを出し、フォーム送信でも維持する。
    pub from_admin: bool,
}

/// 認証器一覧の 1 行（AP9）。種別・状態は翻訳キーに写した状態で受ける。
pub struct AuthenticatorView {
    pub id: String,
    /// 種別の翻訳キー。
    pub type_key: &'static str,
    /// 状態の翻訳キー。
    pub status_key: &'static str,
    pub label: String,
    pub created_at: String,
    /// 直近の利用時刻（未使用なら空文字）。
    pub last_used_at: String,
    /// 一時停止ボタンを出すか（`active` のときだけ）。
    pub suspendable: bool,
    /// 再開ボタンを出すか（`suspended` のときだけ）。
    pub resumable: bool,
}

/// 認証器の管理画面（`GET /{tenant_id}/settings/authenticators`。AP9）。
#[derive(Template)]
#[template(path = "user_authenticators.html")]
pub struct UserAuthenticators<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub csrf: &'a str,
    pub authenticators: &'a [AuthenticatorView],
    /// 未使用のリカバリーコードの残数。
    pub recovery_codes_remaining: usize,
    /// SMS ゲートウェイが設定されているか（AP13）。未設定なら登録導線ごと出さない。
    pub sms_available: bool,
    /// 確認済みの電話番号が登録されているか（番号そのものは web へ渡さない）。
    pub phone_registered: bool,
    /// 確認コードの入力待ちか（登録開始の直後）。
    pub awaiting_phone_code: bool,
    pub saved_key: Option<&'a str>,
    pub error_key: Option<&'a str>,
}

/// リカバリーコードの発行結果（AP9）。平文はこの画面でしか表示しない。
#[derive(Template)]
#[template(path = "recovery_codes.html")]
pub struct RecoveryCodes<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub codes: &'a [String],
}

/// Step-up 認証の本人確認画面（`GET /{tenant_id}/settings/verify`。AP5）。
#[derive(Template)]
#[template(path = "step_up_challenge.html")]
pub struct StepUpChallenge<'a> {
    pub messages: &'a Messages,
    /// `/{tenant_id}` プレフィクス。
    pub tenant: &'a str,
    /// ログイン後フォーム用の同期トークン（`console_csrf_token`）。
    pub csrf: &'a str,
    /// 対象操作（そのまま POST へ載せ、api が要件を決め直す）。
    pub operation: &'a str,
    /// 確認後に戻る先（web 側で同一テナントのパスに限定済み）。
    pub next: &'a str,
    /// TOTP 入力欄を出すか（要件が多要素のとき）。
    pub second_factor_required: bool,
    pub error_key: Option<&'a str>,
}

/// セキュリティ画面のセッション 1 行（G10）。時刻は api が返した RFC 3339 文字列をそのまま出す。
pub struct SecuritySessionView {
    /// 失効フォームに載せる表示用 ID（`session_hash` の非可逆な導出値）。
    pub id: String,
    pub current: bool,
    pub multi_factor: bool,
    pub auth_time: String,
    /// User-Agent（未記録なら空文字。`Option` を避けてテンプレートを単純に保つ）。
    pub user_agent: String,
    pub ip_address: String,
    pub absolute_expires_at: String,
}

/// セキュリティ画面の連携済みアプリ 1 行（G10）。
pub struct ConnectedAppView {
    pub client_id: String,
    pub app_name: String,
    /// 同意済み scope（空白区切りの表示用文字列）。
    pub scopes: String,
    pub granted_at: String,
}

/// セルフサービスのセキュリティ画面（`GET /{tenant_id}/settings/security`。G10）。
#[derive(Template)]
#[template(path = "user_security.html")]
pub struct UserSecurity<'a> {
    pub messages: &'a Messages,
    /// `/{tenant_id}` プレフィクス（フォーム送信先の組み立てに使う）。
    pub tenant: &'a str,
    /// ログイン後フォーム用の同期トークン（`console_csrf_token`）。
    pub csrf: &'a str,
    pub sessions: &'a [SecuritySessionView],
    pub connected_apps: &'a [ConnectedAppView],
    pub saved_key: Option<&'a str>,
    pub error_key: Option<&'a str>,
}

/// Passkey 一覧画面（`GET /account/passkey`）。登録済みクレデンシャルの一覧と削除ボタン。
#[derive(Template)]
#[template(path = "passkey_list.html")]
pub struct PasskeyListTemplate<'a> {
    pub messages: &'a Messages,
    /// `/{tenant_id}` プレフィクス（ADR-0009 §6）。
    pub tenant_prefix: &'a str,
    pub credentials: &'a [PasskeyCredentialInfo],
}

/// Passkey 登録画面（`GET /account/passkey/register`）。WebAuthn JS フローを起動する。
#[derive(Template)]
#[template(path = "passkey_register.html")]
pub struct PasskeyRegisterTemplate<'a> {
    pub messages: &'a Messages,
    /// `/{tenant_id}` プレフィクス（ADR-0009 §6）。
    pub tenant_prefix: &'a str,
    pub error_key: Option<&'a str>,
}

/// SAML SP（クライアント）一覧・追加画面（`GET /{tenant_id}/admin/saml-clients`）。
#[derive(Template)]
#[template(path = "console/saml_service_providers.html")]
pub struct SamlServiceProvidersConsole<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    /// 管理画面と同じ web オリジンにある IdP メタデータのダウンロード URL。
    pub idp_metadata_url: &'a str,
    pub admin: Admin<'a>,
    pub csrf: &'a str,
    pub saved: bool,
    /// 更新完了直後か（成功バナー表示に使う）。
    pub updated: bool,
    /// 削除完了直後か（成功バナー表示に使う）。
    pub deleted: bool,
    /// メタデータ取り込みで初期値を反映した直後か（案内バナー表示・追加パネル展開に使う）。
    pub imported: bool,
    pub error_key: Option<&'a str>,
    pub providers: &'a [SamlServiceProviderView],
    pub values: &'a SamlServiceProviderFormValues,
}

/// SAML SP（クライアント）追加フォームの入力値。
#[derive(Default)]
pub struct SamlServiceProviderFormValues {
    pub display_name: String,
    pub entity_id: String,
    pub acs_url: String,
    pub name_id_format: String,
    pub x509_certificate: String,
    pub enabled: bool,
}

/// 認証ポリシー一覧・作成・編集画面（`GET /{tenant_id}/admin/authentication-policies`、AP1）。
///
/// 一覧と作成・編集フォームを 1 画面に載せる（`?edit={id}` で同じフォームが編集モードになる）。
/// 更新は**全項目置換**なので、編集時はフォームに現在値をすべて出す必要がある —— 出せない項目が
/// あると保存の瞬間にその条件が消える。可変長の条件をテキストで往復させているのはこのためで、
/// 書式は [`crate::authentication_policy_form`] に置く。
#[derive(Template)]
#[template(path = "console/authentication_policies.html")]
pub struct AuthenticationPoliciesConsole<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub csrf: &'a str,
    /// 一致するポリシーが無いときの既定動作（`AUTH_POLICY_DEFAULT_EFFECT`）。ポリシーの意味は
    /// この既定値と組み合わせて初めて決まるため、一覧の上に必ず出す。
    pub default_effect: &'a str,
    pub saved: bool,
    pub updated: bool,
    pub deleted: bool,
    pub error_key: Option<&'a str>,
    /// 編集中のポリシー ID（`None` = 新規作成）。
    pub editing: Option<&'a str>,
    /// フォーム区画を最初から開くか（編集・入力エラーからの再表示）。
    pub form_open: bool,
    pub effect_options: &'a [&'a str],
    pub method_options: &'a [&'a str],
    pub values: &'a AuthenticationPolicyFormValues,
    pub policies: &'a [AuthenticationPolicyResponse],
}

impl AuthenticationPoliciesConsole<'_> {
    /// 効果コードの翻訳キー。未知の値は素通しせずコードそのものを出す（api が新しい効果を
    /// 足したとき、画面には出るが訳が無いと分かる形にする）。
    pub fn effect_label(&self, effect: &str) -> &'static str {
        match effect {
            "allow" => "admin-auth-policy-effect-allow",
            "deny" => "admin-auth-policy-effect-deny",
            "require_mfa" => "admin-auth-policy-effect-require-mfa",
            "require_specific_method" => "admin-auth-policy-effect-require-method",
            _ => "admin-auth-policy-effect-unknown",
        }
    }

    /// `require_specific_method` の要求内容を 1 行で示す（無ければ空文字）。
    pub fn required_methods_summary(&self, policy: &AuthenticationPolicyResponse) -> String {
        match &policy.effect_params {
            Some(params) => {
                let methods = params.methods.join(", ");
                if params.user_verification {
                    format!("{methods} +uv")
                } else {
                    methods
                }
            }
            None => String::new(),
        }
    }

    /// 一覧に出す条件の要約。**条件が 1 つも無い = 全員・全クライアントに当たる**ので、
    /// それが一目で分かる文言を出す（空欄にすると「条件が設定されていない」と読めてしまう）。
    pub fn condition_summary(&self, policy: &AuthenticationPolicyResponse) -> String {
        let mut parts = Vec::new();
        if !policy.client_ids.is_empty() {
            parts.push(format!("client×{}", policy.client_ids.len()));
        }
        if !policy.user_ids.is_empty() {
            parts.push(format!("user×{}", policy.user_ids.len()));
        }
        if !policy.ip_cidrs.is_empty() {
            parts.push(format!("network×{}", policy.ip_cidrs.len()));
        }
        if !policy.time_windows.is_empty() {
            parts.push(format!("time×{}", policy.time_windows.len()));
        }
        if !policy.requested_acr.is_empty() {
            parts.push(format!("acr×{}", policy.requested_acr.len()));
        }
        if parts.is_empty() {
            self.messages.get("admin-auth-policy-condition-any")
        } else {
            parts.join(" / ")
        }
    }
}

/// 認証ポリシーのフォーム入力値（新規作成の初期値・編集時の現在値・入力エラー時の再表示に使う）。
pub struct AuthenticationPolicyFormValues {
    pub policy_code: String,
    pub policy_name: String,
    pub priority: String,
    pub enabled: bool,
    pub effect: String,
    pub methods: Vec<String>,
    pub user_verification: bool,
    pub client_ids: String,
    pub user_ids: String,
    pub ip_cidrs: String,
    pub time_windows: String,
    pub requested_acr: String,
}

impl Default for AuthenticationPolicyFormValues {
    fn default() -> Self {
        Self {
            policy_code: String::new(),
            policy_name: String::new(),
            // 既定は末尾寄り（既存ポリシーの評価順を崩さない値から始める）。
            priority: "100".to_string(),
            enabled: true,
            effect: "deny".to_string(),
            methods: Vec::new(),
            user_verification: false,
            client_ids: String::new(),
            user_ids: String::new(),
            ip_cidrs: String::new(),
            time_windows: String::new(),
            requested_acr: String::new(),
        }
    }
}

impl AuthenticationPolicyFormValues {
    pub fn is_effect(&self, effect: &str) -> bool {
        self.effect == effect
    }

    pub fn has_method(&self, code: &str) -> bool {
        self.methods.iter().any(|m| m == code)
    }
}
