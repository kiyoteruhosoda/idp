//! Integration tests for the tenant setting values endpoint (`/{tenant_id}/admin/settings/tenant/keys`; ADR-0058).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_tenant_settings
//!
//! Key points checked:
//! - A tenant value applies **only to that tenant**, and other tenants see the global value
//!   (a test with only one tenant would pass even when reading the global value)
//! - "Revert to global" **deletes the row** (different from writing the same value)
//! - ⚠ Someone with only `idp.tenant-settings:*` **cannot open** globally decided keys. Stopped twice: on the
//!   granting side (the global settings endpoint is 403) and on the using side (global keys are 400 even at the
//!   tenant endpoint and written to neither table)
//! - From the global settings screen, for keys tenants can override, "the number of tenants following it" and
//!   "tenants deviating from the default" can be read
//!
//! ⚠ **Do not write values for the root tenant.** Other tests running in parallel use root, and once consumers
//! (follow-ups of ADR-0058) land, root overrides would change their behaviour. Only write to tenants created here.

mod support;

use axum::http::StatusCode;
use serde_json::{json, Value};
use sqlx::Row;
use support::{
    body_json, create_sso_session, delete, exchange_admin_token, get, post, put, send, unique,
    TestEnv,
};

/// The created tenant and the SSO session of its HOME admin (`idp.tenant.admin`).
struct CreatedTenant {
    id: String,
    admin_sso: String,
}

async fn tok(env: &TestEnv, sso: &str, tenant_id: &str) -> String {
    exchange_admin_token(&env.app, tenant_id, sso).await
}

/// root creates a tenant and sets up a HOME admin (same procedure as `tenant_isolation`).
async fn create_tenant(env: &TestEnv, root_sso: &str, name: &str) -> CreatedTenant {
    let res = send(
        &env.app,
        post(
            &tok(env, root_sso, &env.root_tenant_id).await,
            &format!("/{}/admin/tenants", env.root_tenant_id),
            json!({ "name": format!("{name}-{}", unique()) }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "create tenant {name}");
    let id = body_json(res).await["id"]
        .as_str()
        .expect("tenant id")
        .to_string();

    let admin_id = create_user_with_permission(env, root_sso, &id, "idp.tenant.admin").await;
    CreatedTenant {
        id,
        admin_sso: create_sso_session(&env.pool, &admin_id).await,
    }
}

/// Creates a user in the tenant and grants exactly one permission code.
async fn create_user_with_permission(
    env: &TestEnv,
    granter_sso: &str,
    tenant_id: &str,
    code: &str,
) -> String {
    let res = send(
        &env.app,
        post(
            &tok(env, granter_sso, tenant_id).await,
            &format!("/{tenant_id}/admin/users"),
            json!({ "email": format!("settings-{}@example.com", unique()) }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "create user");
    let user_id = body_json(res).await["user_id"]
        .as_str()
        .expect("user id")
        .to_string();
    let res = send(
        &env.app,
        post(
            &tok(env, granter_sso, tenant_id).await,
            &format!("/{tenant_id}/admin/users/{user_id}/permissions"),
            json!({ "permission_code": code }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "grant {code}");
    // The created person is used as a character directly, so clear provisional status (instead of the user finishing setup).
    support::finish_setup(&env.pool, &user_id).await;
    user_id
}

fn item<'a>(list: &'a Value, key: &str) -> &'a Value {
    list["settings"]
        .as_array()
        .expect("settings")
        .iter()
        .find(|item| item["key"] == json!(key))
        .unwrap_or_else(|| panic!("{key} is not listed: {list}"))
}

async fn tenant_rows(env: &TestEnv, tenant_id: &str) -> Vec<(String, String)> {
    sqlx::query("SELECT setting_key, setting_value FROM tenant_settings WHERE tenant_id = ?")
        .bind(tenant_id)
        .fetch_all(&env.pool)
        .await
        .expect("tenant_settings")
        .iter()
        .map(|row| (row.get("setting_key"), row.get("setting_value")))
        .collect()
}

#[tokio::test]
async fn a_tenant_decides_its_own_value_and_can_return_to_the_whole_idp() {
    let Some(env) = support::setup("tenant settings decide").await else {
        return;
    };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let a = create_tenant(&env, &root_sso, "SettingsA").await;
    let b = create_tenant(&env, &root_sso, "SettingsB").await;
    let a_uri = format!("/{}/admin/settings/tenant/keys", a.id);
    let b_uri = format!("/{}/admin/settings/tenant/keys", b.id);
    let a_tok = tok(&env, &a.admin_sso, &a.id).await;

    let res = send(&env.app, get(&a_tok, &a_uri)).await;
    assert_eq!(res.status(), StatusCode::OK, "list");
    let before = body_json(res).await;
    let min_length = item(&before, "PASSWORD_MIN_LENGTH");
    assert_eq!(min_length["origin"], json!("INHERITED"));
    assert_eq!(min_length["value"], min_length["whole_idp_value"]);
    assert_eq!(min_length["kind"], json!("UNSIGNED_INTEGER"));
    let whole_idp_value = min_length["whole_idp_value"].clone();

    let res = send(
        &env.app,
        put(
            &a_tok,
            &format!("{a_uri}/PASSWORD_MIN_LENGTH"),
            json!({ "value": "17" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "set");
    let after = body_json(res).await;
    let min_length = item(&after, "PASSWORD_MIN_LENGTH");
    assert_eq!(min_length["origin"], json!("TENANT_OVERRIDE"));
    assert_eq!(min_length["value"], json!("17"));
    assert_eq!(
        min_length["whole_idp_value"], whole_idp_value,
        "the whole-IdP value is shown next to the override"
    );
    // Writing one key does not create copies of other keys.
    assert_eq!(
        tenant_rows(&env, &a.id).await,
        vec![("PASSWORD_MIN_LENGTH".to_string(), "17".to_string())]
    );

    // ⚠ It does not apply to other tenants.
    let res = send(&env.app, get(&tok(&env, &b.admin_sso, &b.id).await, &b_uri)).await;
    assert_eq!(res.status(), StatusCode::OK);
    let other = body_json(res).await;
    assert_eq!(
        item(&other, "PASSWORD_MIN_LENGTH")["origin"],
        json!("INHERITED")
    );
    assert_eq!(
        item(&other, "PASSWORD_MIN_LENGTH")["value"],
        whole_idp_value
    );

    // Values that do not fit the type are not saved.
    let res = send(
        &env.app,
        put(
            &a_tok,
            &format!("{a_uri}/PASSWORD_MIN_LENGTH"),
            json!({ "value": "seventeen" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "kind is checked");

    // Revert to global = delete the row.
    let res = send(
        &env.app,
        delete(&a_tok, &format!("{a_uri}/PASSWORD_MIN_LENGTH")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "clear");
    let cleared = body_json(res).await;
    assert_eq!(
        item(&cleared, "PASSWORD_MIN_LENGTH")["origin"],
        json!("INHERITED")
    );
    assert!(tenant_rows(&env, &a.id).await.is_empty(), "the row is gone");

    // Only the key and whether it was set or cleared remain in the audit log, not the value.
    let reasons: Vec<String> = sqlx::query(
        "SELECT reason FROM audit_log WHERE event_type = 'tenant_settings.updated' \
         AND tenant_id = ? ORDER BY occurred_at",
    )
    .bind(&a.id)
    .fetch_all(&env.pool)
    .await
    .expect("audit_log")
    .iter()
    .map(|row| row.get("reason"))
    .collect();
    assert_eq!(
        reasons,
        ["PASSWORD_MIN_LENGTH set", "PASSWORD_MIN_LENGTH cleared"]
    );
}

#[tokio::test]
async fn the_tenant_settings_code_never_opens_keys_decided_by_the_whole_idp() {
    let Some(env) = support::setup("tenant settings boundary").await else {
        return;
    };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let tenant = create_tenant(&env, &root_sso, "SettingsBoundary").await;
    let user = create_user_with_permission(
        &env,
        &tenant.admin_sso,
        &tenant.id,
        "idp.tenant-settings:write",
    )
    .await;
    let user_sso = create_sso_session(&env.pool, &user).await;
    let user_tok = tok(&env, &user_sso, &tenant.id).await;
    let uri = format!("/{}/admin/settings/tenant/keys", tenant.id);

    let whole_idp_rows = || async {
        sqlx::query("SELECT setting_key, setting_value FROM system_settings ORDER BY setting_key")
            .fetch_all(&env.pool)
            .await
            .expect("system_settings")
            .iter()
            .map(|row| {
                (
                    row.get::<String, _>("setting_key"),
                    row.get::<String, _>("setting_value"),
                )
            })
            .filter(|(key, _)| key == "ACCESS_TOKEN_TTL_SECS" || key == "ISSUER")
            .collect::<Vec<_>>()
    };
    let whole_idp_before = whole_idp_rows().await;

    // Reading works, and only keys tenants can override are listed.
    let res = send(&env.app, get(&user_tok, &uri)).await;
    assert_eq!(res.status(), StatusCode::OK, "write implies read");
    let list = body_json(res).await;
    let keys: Vec<&str> = list["settings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["key"].as_str().unwrap())
        .collect();
    assert!(keys.contains(&"PASSWORD_MIN_LENGTH"), "{keys:?}");
    for global in [
        "ACCESS_TOKEN_TTL_SECS",
        "ISSUER",
        "COOKIE_SECURE",
        "SMTP_HOST",
    ] {
        assert!(!keys.contains(&global), "{global} must not be listed");
    }

    // Using side: even the tenant endpoint cannot write or delete global keys.
    for key in [
        "ACCESS_TOKEN_TTL_SECS",
        "ISSUER",
        "COOKIE_SECURE",
        "KEY_ENCRYPTION_KEY",
        "smtp.host",
        "PASSWORD_MIN_LENGHT",
    ] {
        let res = send(
            &env.app,
            put(
                &user_tok,
                &format!("{uri}/{key}"),
                json!({ "value": "1", "confirmed": true }),
            ),
        )
        .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "PUT {key}");
        let res = send(&env.app, delete(&user_tok, &format!("{uri}/{key}"))).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "DELETE {key}");
    }
    assert!(tenant_rows(&env, &tenant.id).await.is_empty());
    assert_eq!(
        whole_idp_rows().await,
        whole_idp_before,
        "whole IdP untouched"
    );

    // Granting side: the global settings endpoint passes only with an exact match of `idp.system.admin`.
    // Same for tenant admins (`idp.tenant.admin`).
    let admin_tok = tok(&env, &tenant.admin_sso, &tenant.id).await;
    for token in [&user_tok, &admin_tok] {
        let res = send(
            &env.app,
            get(token, &format!("/{}/admin/system-settings", tenant.id)),
        )
        .await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN, "GET system-settings");
        let res = send(
            &env.app,
            put(
                token,
                &format!("/{}/admin/system-settings/runtime", tenant.id),
                json!({ "key": "PASSWORD_MIN_LENGTH", "value": "3" }),
            ),
        )
        .await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN, "PUT runtime");
    }

    // Read-only permission cannot write.
    let reader = create_user_with_permission(
        &env,
        &tenant.admin_sso,
        &tenant.id,
        "idp.tenant-settings:read",
    )
    .await;
    let reader_tok = tok(
        &env,
        &create_sso_session(&env.pool, &reader).await,
        &tenant.id,
    )
    .await;
    let res = send(&env.app, get(&reader_tok, &uri)).await;
    assert_eq!(res.status(), StatusCode::OK, "read");
    let res = send(
        &env.app,
        put(
            &reader_tok,
            &format!("{uri}/PASSWORD_MIN_LENGTH"),
            json!({ "value": "12" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "read cannot write");
}

#[tokio::test]
async fn the_whole_idp_settings_show_which_tenants_follow_and_which_do_not() {
    let Some(env) = support::setup("tenant settings adoption").await else {
        return;
    };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let tenant = create_tenant(&env, &root_sso, "SettingsAdoption").await;
    let res = send(
        &env.app,
        put(
            &tok(&env, &tenant.admin_sso, &tenant.id).await,
            &format!(
                "/{}/admin/settings/tenant/keys/LOGIN_LOCK_DURATION_SECS",
                tenant.id
            ),
            json!({ "value": "1234" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "tenant sets a value");

    let res = send(
        &env.app,
        get(
            &tok(&env, &root_sso, &env.root_tenant_id).await,
            &format!("/{}/admin/system-settings", env.root_tenant_id),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let settings = body_json(res).await;
    let runtime = settings["runtime_settings"].as_array().unwrap();
    let find = |key: &str| {
        runtime
            .iter()
            .find(|item| item["key"] == json!(key))
            .unwrap_or_else(|| panic!("{key}"))
    };

    let lock = find("LOGIN_LOCK_DURATION_SECS");
    assert_eq!(lock["tenant_overridable"], json!(true));
    let overriding = lock["tenants_overriding"].as_array().unwrap();
    let ours = overriding
        .iter()
        .find(|entry| entry["tenant_id"] == json!(tenant.id))
        .unwrap_or_else(|| panic!("our tenant is listed: {lock}"));
    assert_eq!(ours["value"], json!("1234"));
    assert!(ours["tenant_name"]
        .as_str()
        .unwrap()
        .starts_with("SettingsAdoption"));
    // root has not written it, so at least one tenant follows it.
    assert!(lock["tenants_following"].as_u64().unwrap() >= 1, "{lock}");

    let token_ttl = find("ACCESS_TOKEN_TTL_SECS");
    assert_eq!(token_ttl["tenant_overridable"], json!(false));
    assert!(token_ttl.get("tenants_following").is_none());
    assert!(token_ttl["tenants_overriding"]
        .as_array()
        .unwrap()
        .is_empty());
}

/// Values that can lock people out (policy default `deny`, assignment `enforce`) are not saved without `confirmed`
/// (409). The decision comes from the definition's `locks_out`, not from branching on key names.
#[tokio::test]
async fn a_value_that_can_lock_people_out_is_not_saved_without_confirmation() {
    let Some(env) = support::setup("tenant settings confirmation").await else {
        return;
    };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let tenant = create_tenant(&env, &root_sso, "SettingsConfirm").await;
    let admin_tok = tok(&env, &tenant.admin_sso, &tenant.id).await;
    let uri = format!("/{}/admin/settings/tenant/keys", tenant.id);

    let res = send(&env.app, get(&admin_tok, &uri)).await;
    let list = body_json(res).await;
    let enforcement = item(&list, "APPLICATION_ASSIGNMENT_ENFORCEMENT");
    assert_eq!(enforcement["kind"], json!("CHOICE"));
    assert_eq!(
        enforcement["choices"],
        json!([
            { "value": "record_only", "locks_out": false },
            { "value": "enforce", "locks_out": true }
        ])
    );

    for (key, value) in [
        ("AUTH_POLICY_DEFAULT_EFFECT", "deny"),
        ("APPLICATION_ASSIGNMENT_ENFORCEMENT", "enforce"),
    ] {
        let res = send(
            &env.app,
            put(
                &admin_tok,
                &format!("{uri}/{key}"),
                json!({ "value": value }),
            ),
        )
        .await;
        assert_eq!(
            res.status(),
            StatusCode::CONFLICT,
            "{key} without confirmation"
        );
        assert!(
            tenant_rows(&env, &tenant.id).await.is_empty(),
            "{key} not saved"
        );

        let res = send(
            &env.app,
            put(
                &admin_tok,
                &format!("{uri}/{key}"),
                json!({ "value": value, "confirmed": true }),
            ),
        )
        .await;
        assert_eq!(res.status(), StatusCode::OK, "{key} with confirmation");
        assert_eq!(
            item(&body_json(res).await, key)["origin"],
            json!("TENANT_OVERRIDE")
        );

        // Cleanup (rows only for the created tenant, but do not leave them).
        let res = send(&env.app, delete(&admin_tok, &format!("{uri}/{key}"))).await;
        assert_eq!(res.status(), StatusCode::OK);
    }

    // Values not among the choices are refused even with confirmation.
    let res = send(
        &env.app,
        put(
            &admin_tok,
            &format!("{uri}/AUTH_POLICY_DEFAULT_EFFECT"),
            json!({ "value": "denyy", "confirmed": true }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert!(tenant_rows(&env, &tenant.id).await.is_empty());
}
