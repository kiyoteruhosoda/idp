//! axum ルータの組立。各コンテキストのルータを `.merge()` / `.nest()` で集約する。

use crate::presentation::correlation;
use crate::presentation::cors;
use crate::presentation::handlers::{
    admin, admin_application_logs, admin_audit, admin_authentication_policies,
    admin_client_permissions, admin_clients, admin_external_idps, admin_invitations,
    admin_login_identifiers, admin_members, admin_permissions, admin_resources, admin_restart,
    admin_saml_service_providers, admin_signing_keys, admin_system_settings, admin_tenants,
    admin_users, authorize, consent, discovery, health, internal_admin_token, internal_auth,
    internal_runtime_settings, introspect, invitations, logout, mfa, passkey, register, revoke,
    saml_sso, token, userinfo,
};
use crate::presentation::openapi::ApiDoc;
use crate::presentation::security_headers::add_security_headers;
use crate::presentation::state::AppState;
use crate::presentation::tenant::resolve_tenant;
use axum::middleware;
use axum::routing::{delete, get, patch, post, put};
use axum::Router;
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

pub fn build(state: AppState) -> Router {
    let hsts_max_age = state.config.hsts_max_age();
    let api_docs_enabled = state.config.api_docs_enabled();
    // 内部認証 API（ADR-0007 §3・§5）。web（将来）→api のサービス間 I/F。外部公開しない
    // （リバースプロキシで /internal/* を遮断する前提）。多層防御としてサービス認証トークン
    // （X-Internal-Auth-Token）を必須にする route_layer をこのサブルータにのみ付ける。
    let internal = Router::new()
        // 認可フローの再開（web ハンドオフのハンドル交換 + SSO 判定。ADR-0018 決定 2）。
        .route(
            "/internal/authorize/resume",
            post(authorize::authorize_resume),
        )
        // ログイン画面の文脈（`login_hint` / `ui_locales` の引き直し。G12）。
        .route(
            "/internal/authorize/login-context",
            post(authorize::authorize_login_context),
        )
        // SAML SSO フローの再開（web ハンドオフのハンドル交換 + SSO 判定 + 応答発行）。
        .route("/internal/saml/resume", post(saml_sso::saml_resume))
        // RP-initiated logout（end_session_endpoint は web。api は失効・通知・URL 組み立てを担う）。
        .route("/internal/logout/rp", post(logout::rp_logout))
        // 管理コンソールの SSO セッション → 管理トークンの交換（ADR-0037）。api の `/admin/*` は
        // Bearer しか受け付けないため、web はデータ操作の前に必ずここを通る。
        .route(
            "/internal/admin/token",
            post(internal_admin_token::issue_management_token),
        )
        .route("/internal/authenticate", post(internal_auth::authenticate))
        .route(
            "/internal/authenticate/admin",
            post(internal_auth::authenticate_admin),
        )
        .route(
            "/internal/authenticate/admin/change-password",
            post(internal_auth::admin_change_password),
        )
        // エンドユーザー・ポータルの直接ログイン（クライアント非依存。TOTP 尊重）。
        .route(
            "/internal/authenticate/portal",
            post(internal_auth::authenticate_portal),
        )
        .route(
            "/internal/authenticate/portal/mfa",
            post(internal_auth::authenticate_portal_mfa),
        )
        // ポータルの強制パスワード変更（初回ログイン時。ADR-0009 §5）。
        .route(
            "/internal/authenticate/portal/change-password",
            post(internal_auth::authenticate_portal_change_password),
        )
        .route(
            "/internal/change-password",
            post(internal_auth::change_password),
        )
        // セルフサービスのパスワード変更（ログイン済みユーザーの設定画面。MT15）。
        .route(
            "/internal/account/change-password",
            post(internal_auth::account_change_password),
        )
        // セルフサービスの表示言語変更（ログイン済みユーザーの設定画面。MT20）。
        .route(
            "/internal/account/update-language",
            post(internal_auth::account_update_language),
        )
        // セルフサービスの配色変更（ログイン済みユーザーの設定画面）。
        .route(
            "/internal/account/update-theme",
            post(internal_auth::account_update_theme),
        )
        // セルフサービスのプロフィール取得・表示名更新（ログイン済みユーザーの設定画面）。
        .route(
            "/internal/account/profile",
            post(internal_auth::account_profile),
        )
        .route(
            "/internal/account/update-name",
            post(internal_auth::account_update_name),
        )
        // 外部 IdP ログイン（AP10）。
        .route(
            "/internal/external/providers",
            post(internal_auth::external_providers),
        )
        .route(
            "/internal/external/start",
            post(internal_auth::external_start),
        )
        .route(
            "/internal/external/callback",
            post(internal_auth::external_callback),
        )
        .route(
            "/internal/external/saml/acs",
            post(internal_auth::external_saml_acs),
        )
        // 認証器の統合管理（一覧・状態変更・リカバリーコード・email OTP。AP9）。
        .route(
            "/internal/account/authenticators",
            post(internal_auth::account_authenticators),
        )
        .route(
            "/internal/account/authenticators/status",
            post(internal_auth::account_authenticator_status),
        )
        .route(
            "/internal/account/recovery-codes",
            post(internal_auth::account_recovery_codes),
        )
        .route(
            "/internal/account/email-otp",
            post(internal_auth::account_email_otp),
        )
        // SMS OTP と電話番号の登録（AP13）。送信は MFA 待ちの利用者のみ、登録は SSO セッションで。
        .route(
            "/internal/account/sms-otp",
            post(internal_auth::account_sms_otp),
        )
        .route(
            "/internal/account/phone/register",
            post(internal_auth::account_phone_register),
        )
        .route(
            "/internal/account/phone/confirm",
            post(internal_auth::account_phone_confirm),
        )
        // Step-up 認証（重要操作の直前の本人確認。AP5）。
        .route(
            "/internal/step-up/check",
            post(internal_auth::step_up_check),
        )
        .route(
            "/internal/step-up/verify",
            post(internal_auth::step_up_verify),
        )
        // 本人確認のパスキー経路（T38）。ログインの開始・完了とは用途の違うチャレンジを扱う。
        .route(
            "/internal/step-up/passkey/begin",
            post(internal_auth::step_up_passkey_begin),
        )
        .route(
            "/internal/step-up/passkey/verify",
            post(internal_auth::step_up_passkey_verify),
        )
        // セルフサービスのセキュリティ画面（セッション一覧・失効／連携アプリ解除。G10）。
        .route(
            "/internal/account/security",
            post(internal_auth::account_security),
        )
        .route(
            "/internal/account/security/revoke-session",
            post(internal_auth::account_revoke_session),
        )
        .route(
            "/internal/account/security/revoke-consent",
            post(internal_auth::account_revoke_consent),
        )
        // ログイン中ユーザーの所属テナント列挙（テナント切り替え UI）。
        .route(
            "/internal/account/tenants",
            post(internal_auth::account_tenants),
        )
        .route("/internal/logout", post(internal_auth::logout))
        // パスワードリセット（忘失時。MT18）。未ログイン経路（web がフォームを仲介する）。
        .route(
            "/internal/password-reset/request",
            post(internal_auth::password_reset_request),
        )
        .route(
            "/internal/password-reset/complete",
            post(internal_auth::password_reset_complete),
        )
        // 同意 API（F3: Consent）。
        .route("/internal/consent-info", get(consent::consent_info))
        .route("/internal/consent/approve", post(consent::consent_approve))
        .route("/internal/consent/deny", post(consent::consent_deny))
        // MFA（TOTP）自己登録・ログイン検証 API。
        .route("/internal/mfa/totp/setup", post(mfa::setup_totp))
        .route("/internal/mfa/totp/confirm", post(mfa::confirm_totp))
        .route("/internal/mfa/totp/delete", post(mfa::delete_totp))
        .route("/internal/mfa/totp/verify", post(mfa::verify_totp))
        // Passkey（WebAuthn）セルフ登録 API。
        .route(
            "/internal/passkey/register/begin",
            post(passkey::register_begin),
        )
        .route(
            "/internal/passkey/register/complete",
            post(passkey::register_complete),
        )
        .route("/internal/passkey/delete", post(passkey::passkey_delete))
        .route("/internal/passkey/list", post(passkey::passkey_list))
        // Passkey ログインフロー API。
        .route("/internal/passkey/login/begin", post(passkey::login_begin))
        .route(
            "/internal/passkey/login/complete",
            post(passkey::login_complete),
        )
        // 認可フロー外の直接ログイン（管理コンソール・ポータル）。開始は上の login/begin を共有し、
        // `auth_session_id` を渡さずに得たチャレンジをここで完了する。
        .route(
            "/internal/passkey/login/admin/complete",
            post(passkey::admin_login_complete),
        )
        .route(
            "/internal/passkey/login/portal/complete",
            post(passkey::portal_login_complete),
        )
        // web が起動時に読む共有ランタイム設定（MT26 / ADR-0013）。web は DB を持たないため、
        // api/web の両方が消費する DB 管理値（COOKIE_SECURE 等）はここが唯一の出所になる。
        .route(
            assay_contracts::runtime_settings::SHARED_RUNTIME_SETTINGS_PATH,
            get(internal_runtime_settings::shared_runtime_settings),
        )
        // web の WARN / ERROR 取り込み（CLAUDE.md「ログ」）。web は DB を持たないため、自身の
        // アプリケーションログはここへ送って `log` テーブルへ書いてもらう。
        .route(
            "/internal/logs",
            post(admin_application_logs::ingest_application_logs),
        )
        // Prometheus メトリクス（G6）。公開面ではなく内部面に置く（誰がいつ何回失敗したかを
        // 集約した情報であり、外から読めてよい値ではない）。プロキシ遮断 + サービストークンの二重。
        .route(
            "/internal/metrics",
            get(crate::presentation::metrics::metrics_endpoint),
        )
        // 詳細ヘルス（ADR-0031）。版数・稼働時間・サーバー時刻・依存先の検査結果を返す。
        // 公開面（`/healthz`・`/readyz`）はサービス名までで、詳細はここにしか出さない。
        .route("/internal/health", get(health::internal_health))
        // ビルド情報とスキーマ適用状態（ADR-0034）。稼働中のコミットが分かると、どの既知の
        // 不具合が塞がっていないかを外から判断できるため、無認証では出さない。web は
        // サービストークンを付けて呼ぶので、コンソールのバージョン画面はそのまま動く。
        .route("/internal/version", get(health::version))
        .route("/internal/version/schema", get(health::schema_version))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            internal_auth::require_service_token,
        ));

    // テナントスコープのルート（ADR-0009 §6）。パスに `/{tenant_id}` は書かず、`.nest()` で前置する。
    // `resolve_tenant` を `route_layer` で付与し、各ハンドラは `Extension<ResolvedTenant>` を受け取る。
    let tenant_scoped = Router::new()
        .route("/auth/register", post(register::register))
        .route("/auth/verify-email", post(register::verify_email))
        .route("/authorize", get(authorize::authorize))
        // トークン系 3 本（クライアント認証 = Argon2 照合を伴う）は負荷ゲートを通す（SEC10）。
        // ルートを増やすときは、クライアント認証を伴うなら同じゲートへ載せる。
        .merge(
            Router::new()
                .route("/token", post(token::token))
                .route("/revoke", post(revoke::revoke))
                .route("/introspect", post(introspect::introspect))
                .route_layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    crate::presentation::token_endpoint_load::limit_token_endpoint_load,
                )),
        )
        .route("/userinfo", get(userinfo::userinfo))
        // `/logout`（end_session_endpoint）は web が受ける（ADR-0018 決定 2）。api はブラウザ
        // Cookie を読まないため、公開の logout ルートを持たない（処理は /internal/logout/rp）。
        // 管理者身元確認（idp.tenant.admin 必須。RequirePerms<IdpAdmin>）。web の管理コンソールが
        // 管理トークンで認証状態・身元を得るのに使う（ADR-0007 §4 / ADR-0037）。HTML 画面は web crate 側。
        .route("/admin/whoami", get(admin::whoami))
        // テナント作成・管理（ADR-0009 §5・§6）。idp.system.admin 必須（実質 root のみ）。
        .route(
            "/admin/tenants",
            get(admin_tenants::list_tenants).post(admin_tenants::create_tenant),
        )
        .route(
            "/admin/tenants/{child_id}",
            get(admin_tenants::get_tenant)
                .patch(admin_tenants::update_tenant)
                .delete(admin_tenants::delete_tenant),
        )
        // 子テナント管理者のパスワード再発行（idp.system.admin 必須）。
        .route(
            "/admin/tenants/{child_id}/admin-password-reset",
            post(admin_tenants::reset_tenant_admin_password),
        )
        // テナントへのドメイン割り当て（ADR-0029。idp.system.admin 必須）。対象は**自テナントまたは
        // 直下の子**で、root 自身にも割り当てられる（root の利用者は作成したテナントへゲストとして
        // 入るため、ドメイン修飾で入れなければ意味がない）。ドメインの一意性はグローバルなので、
        // 早い者勝ちにしないよう root の system 管理者だけが操作できる。
        .route(
            "/admin/tenants/{target_id}/domains",
            get(admin_tenants::list_tenant_domains).post(admin_tenants::add_tenant_domain),
        )
        .route(
            "/admin/tenants/{target_id}/domains/{domain_id}",
            delete(admin_tenants::remove_tenant_domain),
        )
        // 設定画面（MT14）。テナント設定区画（自テナント表示名。idp.tenant-settings:read / :write）と
        // システム設定区画（SMTP 等。idp.system.admin 必須 = 実質 root のみ。細粒度へは分割しない）。
        .route(
            "/admin/settings/tenant",
            get(admin_tenants::get_current_tenant).patch(admin_tenants::update_current_tenant),
        )
        .route(
            "/admin/system-settings",
            get(admin_system_settings::get_system_settings)
                .put(admin_system_settings::update_system_settings),
        )
        // ランタイム設定の DB 上書き（DB_MANAGED キーのみ。idp.system.admin 必須）。
        .route(
            "/admin/system-settings/runtime",
            axum::routing::put(admin_system_settings::update_runtime_setting),
        )
        // 保存したランタイム設定を反映するための api 再起動（idp.system.admin 必須。ADR-0017）。
        .route("/admin/restart", post(admin_restart::restart_service))
        // メンバー・招待（ADR-0009 §3・§6）。idp.members:read / idp.members:write 必須。
        .route("/admin/members", get(admin_members::list_members))
        // ゲストメンバーシップの解除（DELETE）と一時停止・再開（PATCH。MT24）。
        .route(
            "/admin/members/{user_id}",
            axum::routing::delete(admin_members::revoke_member)
                .patch(admin_members::update_member_status),
        )
        .route(
            "/admin/invitations",
            post(admin_invitations::create_invitation),
        )
        // 招待の承諾（管理 API ではない。ログイン済み利用者本人が用いる。ADR-0009 §3）。
        .route("/invitations/accept", post(invitations::accept_invitation))
        // クライアント（RP）登録・管理 API（A1、設計仕様 §9.3）。idp.clients:read / idp.clients:write 必須。
        .route(
            "/admin/clients",
            post(admin_clients::create_client).get(admin_clients::list_clients),
        )
        // 状況一覧（静的 status は動的 {client_id} より優先）。
        .route(
            "/admin/clients/status",
            get(admin_clients::list_client_status),
        )
        .route(
            "/admin/clients/{client_id}",
            get(admin_clients::get_client)
                .patch(admin_clients::update_client)
                // 論理削除（ADR-0035）。実体は残し、状態を DELETED にする。
                .delete(admin_clients::delete_client),
        )
        .route(
            "/admin/clients/{client_id}/secret",
            post(admin_clients::rotate_client_secret),
        )
        // システム用クライアントへの管理権限の付与・剥奪（ADR-0037）。ここで付けた権限コードが
        // `client_credentials`（`resource={issuer}/admin`）で得る管理トークンの `perms` になる。
        // idp.clients:read / idp.clients:write 必須。
        .route(
            "/admin/clients/{client_id}/permissions",
            get(admin_client_permissions::list_client_permissions)
                .post(admin_client_permissions::grant_client_permission),
        )
        .route(
            "/admin/clients/{client_id}/permissions/{permission_code}",
            delete(admin_client_permissions::revoke_client_permission),
        )
        // 付与可能な権限コード（マスタ）と利用者検索・取得（管理コンソール支援 API）。
        // idp.permissions:read / idp.users:* 必須（ADR-0037）。
        .route(
            "/admin/permissions",
            get(admin_permissions::list_available_permissions),
        )
        .route(
            "/admin/users",
            post(admin_users::create_user).get(admin_users::search_user),
        )
        // 利用者の取得・状態変更（有効化・無効化）・削除。idp.users:read / idp.users:write 必須。
        .route(
            "/admin/users/{user_id}",
            get(admin_users::get_user)
                .patch(admin_users::update_user_status)
                .delete(admin_users::delete_user),
        )
        // 利用者のパスワード再発行（must_change_password 付き自動生成）。idp.users:write 必須。
        .route(
            "/admin/users/{user_id}/profile",
            patch(admin_users::update_user_profile),
        )
        .route(
            "/admin/users/{user_id}/password-reset",
            post(admin_users::reset_user_password),
        )
        // 利用者の MFA（TOTP・Passkey）解除（端末紛失時の復旧。MT21）。idp.users:write 必須。
        .route(
            "/admin/users/{user_id}/mfa-reset",
            post(admin_users::reset_user_mfa),
        )
        // アカウントロックの即時解除（AP6。仕様 §17.1・§24.6）。idp.users:write 必須。
        .route(
            "/admin/users/{user_id}/unlock",
            post(admin_users::unlock_user),
        )
        // ログイン識別子の割り当て（AP8。仕様 §4）。idp.users:read / idp.users:write 必須。
        .route(
            "/admin/users/{user_id}/login-identifiers",
            get(admin_login_identifiers::list_login_identifiers)
                .post(admin_login_identifiers::add_login_identifier),
        )
        .route(
            "/admin/users/{user_id}/login-identifiers/{identifier_id}",
            patch(admin_login_identifiers::update_login_identifier)
                .delete(admin_login_identifiers::delete_login_identifier),
        )
        // 利用者権限の付与・剥奪・参照（A2、ADR-0006）。idp.permissions:read / :write 必須。
        .route(
            "/admin/users/{user_id}/permissions",
            get(admin_permissions::list_permissions).post(admin_permissions::grant_permission),
        )
        .route(
            "/admin/users/{user_id}/permissions/{permission_code}",
            axum::routing::delete(admin_permissions::revoke_permission),
        )
        // 保護リソース（`aud` に入る宛名）の登録・停止・削除（ADR-0042）。idp.resources:* 必須。
        .route(
            "/admin/resources",
            get(admin_resources::list_resources).post(admin_resources::register_resource),
        )
        .route(
            "/admin/resources/{resource_id}",
            patch(admin_resources::update_resource_status).delete(admin_resources::delete_resource),
        )
        // クライアントへの宛先の貸し出し（ADR-0042）。貸すときは名前で、取り消すときは行の id で指す。
        .route(
            "/admin/clients/{client_id}/resources",
            get(admin_resources::list_client_resources)
                .post(admin_resources::grant_client_resource),
        )
        .route(
            "/admin/clients/{client_id}/resources/{resource_id}",
            axum::routing::delete(admin_resources::revoke_client_resource),
        )
        // 認証ポリシーの管理（ユーザー認証・認証ポリシー仕様書 §7）。idp.authentication-policies:* 必須。
        .route(
            "/admin/authentication-policies",
            get(admin_authentication_policies::list_authentication_policies)
                .post(admin_authentication_policies::create_authentication_policy),
        )
        .route(
            "/admin/authentication-policies/{policy_id}",
            put(admin_authentication_policies::update_authentication_policy)
                .delete(admin_authentication_policies::delete_authentication_policy),
        )
        // 外部 IdP 設定（AP10）。idp.external-idps:read / :write 必須。クライアントシークレットは書き込み専用。
        .route(
            "/admin/external-idps",
            get(admin_external_idps::list_external_idps)
                .post(admin_external_idps::register_external_idp),
        )
        // 外部 IdP メタデータ取り込み（解析のみ・非永続。AP12）。`{id}` より先に置く——
        // `import-metadata` を id として解釈されると 404 になる。
        .route(
            "/admin/external-idps/import-metadata",
            post(admin_external_idps::import_external_idp_metadata),
        )
        .route(
            "/admin/external-idps/{id}",
            patch(admin_external_idps::update_external_idp)
                .delete(admin_external_idps::delete_external_idp),
        )
        // 監査ログ参照（A3、設計仕様 §7）。idp.audit:read 必須。
        .route("/admin/audit-logs", get(admin_audit::list_audit_logs))
        // エラー・警告ログ参照（`log` テーブル）。テナント横断の運用情報のため idp.system.admin 必須。
        .route(
            "/admin/logs",
            get(admin_application_logs::list_application_logs),
        )
        // SAML SP（クライアント）登録。idp.saml-service-providers:read / :write 必須。
        .route(
            "/admin/saml-service-providers",
            get(admin_saml_service_providers::list).post(admin_saml_service_providers::register),
        )
        // SP メタデータ取り込み（解析のみ・非永続）。idp.saml-service-providers:write 必須。
        .route(
            "/admin/saml-service-providers/import-metadata",
            post(admin_saml_service_providers::import_metadata),
        )
        // SP の更新・削除。idp.saml-service-providers:write 必須。
        .route(
            "/admin/saml-service-providers/{id}",
            put(admin_saml_service_providers::update).delete(admin_saml_service_providers::delete),
        )
        // 署名鍵管理 API（K1）。idp.keys:read / idp.keys:write 必須。
        .route(
            "/admin/signing-keys",
            get(admin_signing_keys::list_keys).post(admin_signing_keys::generate_key),
        )
        .route(
            "/admin/signing-keys/{kid}/retire",
            post(admin_signing_keys::retire_key),
        )
        .route(
            "/admin/signing-keys/{kid}",
            axum::routing::delete(admin_signing_keys::delete_key),
        )
        .route(
            "/.well-known/openid-configuration",
            get(discovery::openid_configuration),
        )
        .route("/.well-known/jwks.json", get(discovery::jwks))
        // SAML IdP メタデータ出力（公開。SP が assay を信頼するために取り込むメタデータ）。
        .route("/saml/metadata", get(discovery::saml_idp_metadata))
        // SAML SSO エンドポイント（メタデータが広告する SingleSignOnService。Redirect / POST 両対応）。
        .route(
            "/saml/sso",
            get(saml_sso::sso_redirect).post(saml_sso::sso_post),
        )
        // テナント解決（UUID 検証・存在/ACTIVE 確認）を全テナントルートへ付与する（ADR-0009 §7）。
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            resolve_tenant,
        ));

    // テナント外パス（プレフィクスなし。ADR-0009 §6）: ヘルスチェック・内部 API・API ドキュメント。
    Router::new()
        .route("/healthz", get(health::liveness))
        .route("/readyz", get(health::readiness))
        .nest("/{tenant_id}", tenant_scoped)
        .merge(internal)
        // Swagger UI と OpenAPI 文書（SEC12）。api 面は公開されるため既定では配信しない
        // （管理 API を含む全エンドポイントの仕様が無認証で読めてしまう）。開発・検証環境では
        // `API_DOCS_ENABLED=true` で有効化する。
        .merge(if api_docs_enabled {
            SwaggerUi::new("/api/docs")
                .url("/api/openapi.json", ApiDoc::openapi())
                .into()
        } else {
            Router::new()
        })
        // CORS（G1）。`route_layer` ではなく `layer` で付けるのは、プリフライト（OPTIONS）が
        // どのルートにもマッチせず 405 になるため——ここで受け止めて CORS ヘッダ付きで返す。
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            cors::apply_cors,
        ))
        .layer(axum::middleware::from_fn(correlation::propagate))
        // エンドポイント別の所要時間（G6）。`correlation::propagate` より外側に置き、
        // 相関 ID 付与を含めた「入口から出口まで」を測る。
        .layer(axum::middleware::from_fn(
            crate::presentation::metrics::track_http_metrics,
        ))
        // アクセススパンはパスのみを記録する（クエリ文字列に載る `code`・`code_challenge` を
        // ログへ落とさない。SEC9）。組み立ては web と共有する。
        .layer(TraceLayer::new_for_http().make_span_with(assay_contracts::http_trace::request_span))
        .layer(middleware::from_fn(move |req, next| {
            add_security_headers(req, next, hsts_max_age)
        }))
        .with_state(state)
}
