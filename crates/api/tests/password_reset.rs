//! E2E integration tests for self-service password reset (MT18).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test password_reset
//!
//! Starts a minimal in-process SMTP server, points system settings (system_settings) at it as the real delivery target,
//! and checks end to end "request → mail received → reset with the token → single use, all sessions revoked".

mod support;

use axum::http::StatusCode;
use serde_json::json;
use support::{body_json, create_sso_session, post_internal, send, SERVICE_TOKEN};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

/// An in-process server speaking minimal SMTP. Returns the received DATA body.
async fn run_minimal_smtp_server(listener: TcpListener) -> String {
    let (socket, _) = listener.accept().await.expect("accept");
    let (read_half, mut write_half) = socket.into_split();
    let mut lines = BufReader::new(read_half).lines();
    write_half.write_all(b"220 test ESMTP\r\n").await.unwrap();
    let mut data = String::new();
    let mut in_data = false;
    while let Ok(Some(line)) = lines.next_line().await {
        if in_data {
            if line == "." {
                in_data = false;
                write_half.write_all(b"250 OK\r\n").await.unwrap();
            } else {
                data.push_str(&line);
                data.push('\n');
            }
            continue;
        }
        let verb = line
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_ascii_uppercase();
        match verb.as_str() {
            "EHLO" | "HELO" => write_half.write_all(b"250 test\r\n").await.unwrap(),
            "MAIL" | "RCPT" => write_half.write_all(b"250 OK\r\n").await.unwrap(),
            "DATA" => {
                in_data = true;
                write_half
                    .write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    .await
                    .unwrap();
            }
            "QUIT" => {
                write_half.write_all(b"221 Bye\r\n").await.unwrap();
                break;
            }
            _ => write_half.write_all(b"250 OK\r\n").await.unwrap(),
        }
    }
    data
}

/// There is **only one SMTP destination, in system settings (not per tenant)**. If tests rewriting the settings
/// ran in parallel, one's mail would go to the target the other set, and if cleanup (resetting `smtp.host` to empty)
/// ran before the other received it, the waiting side would never receive it. Serializes from rewriting the
/// settings through receiving and cleanup.
///
/// ⚠ **This Mutex serializes only within this binary.** Test binaries run in parallel as separate processes,
/// so other binaries touching the same settings (`admin_smtp_settings`) are coordinated via
/// [`support::SmtpSettingsLock`] (a DB advisory lock). Both are needed because within a process
/// this one is lighter, and across processes only that one works.
static SMTP_SETTINGS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Extracts body text with readable links from the raw data received over SMTP.
///
/// The body is carried in base64 (or quoted-printable) and wrapped along the way. Tests that want to inspect the URL
/// as a plain string need to look at this decoded text.
fn mail_text(raw: &str) -> String {
    mail_text_candidates(raw)
        .into_iter()
        .find(|text| text.contains("token="))
        .unwrap_or_else(|| raw.to_string())
}

fn mail_text_candidates(raw: &str) -> Vec<String> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    let mut candidates = vec![raw.replace("=\n", "").replace("=3D", "=")];
    if let Some((_, body)) = raw.split_once("\n\n") {
        let joined: String = body.split_whitespace().collect();
        if let Ok(bytes) = STANDARD.decode(joined.trim_end_matches('.')) {
            if let Ok(text) = String::from_utf8(bytes) {
                candidates.push(text);
            }
        }
    }
    candidates
}

/// Extracts the reset token from the mail body. The body contains Japanese, so lettre chooses
/// base64 Content-Transfer-Encoding (everything after the blank line following the headers is decoded as base64).
/// Quoted-printable (soft breaks, `=3D`) is handled too, just in case.
fn token_from_mail_body(raw: &str) -> String {
    let candidates = mail_text_candidates(raw);
    for text in candidates {
        if let Some(start) = text.find("token=") {
            return text[start + "token=".len()..]
                .split_whitespace()
                .next()
                .expect("token value")
                .to_string();
        }
    }
    panic!("token not found in mail body: {raw}");
}

async fn upsert_setting(pool: &sqlx::MySqlPool, key: &str, value: &str) {
    sqlx::query(
        "INSERT INTO system_settings (setting_key, setting_value, is_secret) VALUES (?, ?, 0) \
         ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)",
    )
    .bind(key)
    .bind(value)
    .execute(pool)
    .await
    .expect("upsert system setting");
}

#[tokio::test]
async fn full_reset_flow_via_email_link() {
    let Some(env) = support::setup("password reset").await else {
        return;
    };
    // Take it **before registering**. Self-registration sends an email verification notice, so passing here while
    // the other test has pointed the delivery target at its own in-process SMTP server would let that notice be eaten
    // by the other's server (which ends after one connection), and the other would never receive its reset mail.
    let _smtp_guard = SMTP_SETTINGS.lock().await;
    let smtp_lock = support::SmtpSettingsLock::acquire(&env.pool).await;

    // Create the target user by self-registration and give it one SSO session (to check revocation).
    let email = format!("reset-{}@example.com", uuid::Uuid::new_v4().simple());
    let res = send(
        &env.app,
        axum::http::Request::builder()
            .method("POST")
            .uri(format!("/{}/auth/register", env.root_tenant_id))
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                json!({ "email": email, "password": "original-pass-123" }).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let user_id: String = sqlx::query_scalar("SELECT id FROM users WHERE email = ?")
        .bind(&email)
        .fetch_one(&env.pool)
        .await
        .unwrap();
    let _sso_cookie = create_sso_session(&env.pool, &user_id).await;

    // Point the delivery target at the in-process SMTP server. Set it after creating the target user so the
    // verification notice at registration is not picked up (settings are reset to empty at the end of the test).
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind smtp");
    let smtp_port = listener.local_addr().unwrap().port();
    let smtp_server = tokio::spawn(run_minimal_smtp_server(listener));
    upsert_setting(&env.pool, "smtp.host", "127.0.0.1").await;
    upsert_setting(&env.pool, "smtp.port", &smtp_port.to_string()).await;
    upsert_setting(&env.pool, "smtp.from_address", "noreply@example.test").await;
    upsert_setting(&env.pool, "smtp.use_tls", "false").await;

    // 1. Reset request → accepted, and the mail is actually delivered.
    let res = send(
        &env.app,
        post_internal(
            "/internal/password-reset/request",
            Some(SERVICE_TOKEN),
            json!({ "tenant_id": env.root_tenant_id, "email": email }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_json(res).await["result"], "accepted");
    let mail_body = smtp_server.await.expect("smtp server task");
    let token = token_from_mail_body(&mail_body);
    assert!(!token.is_empty());

    // A nonexistent account also gets the same accepted (prevents enumeration).
    let res = send(
        &env.app,
        post_internal(
            "/internal/password-reset/request",
            Some(SERVICE_TOKEN),
            json!({ "tenant_id": env.root_tenant_id, "email": "nobody@example.com" }),
        ),
    )
    .await;
    assert_eq!(body_json(res).await["result"], "accepted");

    // 2. Set a new password with the token → ok.
    let res = send(
        &env.app,
        post_internal(
            "/internal/password-reset/complete",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": env.root_tenant_id,
                "token": token,
                "new_password": "brand-new-pass-456"
            }),
        ),
    )
    .await;
    assert_eq!(body_json(res).await["result"], "ok");

    // The token was consumed once, with used_at set.
    let used: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = ? AND used_at IS NOT NULL",
    )
    .bind(&user_id)
    .fetch_one(&env.pool)
    .await
    .unwrap();
    assert_eq!(used, 1, "token consumed");

    // All existing SSO sessions are revoked.
    let sessions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sso_sessions WHERE user_id = ?")
        .bind(&user_id)
        .fetch_one(&env.pool)
        .await
        .unwrap();
    assert_eq!(sessions, 0, "all SSO sessions revoked after reset");

    // 3. Reusing the same token is rejected.
    let res = send(
        &env.app,
        post_internal(
            "/internal/password-reset/complete",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": env.root_tenant_id,
                "token": token,
                "new_password": "yet-another-pass-789"
            }),
        ),
    )
    .await;
    assert_eq!(body_json(res).await["result"], "invalid_or_expired");

    // Cleanup: reset the SMTP settings to empty (leave no delivery target for other tests).
    upsert_setting(&env.pool, "smtp.host", "").await;
    upsert_setting(&env.pool, "smtp.from_address", "").await;
    smtp_lock.release().await;
}

/// A user who joined a tenant as a guest can request a reset from that tenant's screen (MT26).
///
/// Two key points.
///
/// 1. Even if `users.email` cannot be found in the requested (joined) tenant, it is resolved **as a joined guest**.
///    Without this, one could sign in from the joined tenant's screen but hit a dead end for reset only.
/// 2. The mail link points to **the home tenant**. Executing a reset requires "the token user's home tenant ==
///    the requested tenant", so a link pointing to the joined tenant is always rejected.
#[tokio::test]
async fn a_guest_can_request_a_reset_from_the_host_tenant() {
    let Some(env) = support::setup("password reset guest").await else {
        return;
    };
    // Take it before registering (same reason as [`full_reset_flow_via_email_link`]).
    let _smtp_guard = SMTP_SETTINGS.lock().await;
    let smtp_lock = support::SmtpSettingsLock::acquire(&env.pool).await;

    // The home tenant is root. The joined tenant and guest membership are created directly (what we want to test is
    // the reset bridging, not the invitation flow).
    let email = format!("guest-reset-{}@example.com", uuid::Uuid::new_v4().simple());
    let res = send(
        &env.app,
        axum::http::Request::builder()
            .method("POST")
            .uri(format!("/{}/auth/register", env.root_tenant_id))
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                json!({ "email": email, "password": "original-pass-123" }).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let user_id: String = sqlx::query_scalar("SELECT id FROM users WHERE email = ?")
        .bind(&email)
        .fetch_one(&env.pool)
        .await
        .unwrap();

    let host_tenant = uuid::Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO tenants (id, parent_tenant_id, name, status) VALUES (?, ?, ?, 'ACTIVE')",
    )
    .bind(&host_tenant)
    .bind(&env.root_tenant_id)
    .bind(format!("GuestResetHost {}", &host_tenant[..8]))
    .execute(&env.pool)
    .await
    .expect("create host tenant");
    sqlx::query(
        "INSERT INTO tenant_memberships (tenant_id, user_id, membership_type, status) \
         VALUES (?, ?, 'GUEST', 'ACTIVE')",
    )
    .bind(&host_tenant)
    .bind(&user_id)
    .execute(&env.pool)
    .await
    .expect("create guest membership");

    // Put one **inactive** guest with the same address in another (ACTIVE) home tenant.
    // `users.email` is unique only within a tenant, so this can really happen.
    // If ambiguity were decided by a plain row count rather than "people who could be recipients", this one person's
    // presence would mean **the only active guest never gets the reset mail** (the response stays Accepted,
    // so nobody would notice).
    let other_home = uuid::Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO tenants (id, parent_tenant_id, name, status) VALUES (?, ?, ?, 'ACTIVE')",
    )
    .bind(&other_home)
    .bind(&env.root_tenant_id)
    .bind(format!("GuestResetTwin {}", &other_home[..8]))
    .execute(&env.pool)
    .await
    .expect("create the twin's home tenant");
    let disabled_twin = uuid::Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO users (id, tenant_id, sub, email, email_verified, password_hash, status) \
         VALUES (?, ?, ?, ?, 1, 'x', 'DISABLED')",
    )
    .bind(&disabled_twin)
    .bind(&other_home)
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(&email)
    .execute(&env.pool)
    .await
    .expect("create the disabled twin");
    sqlx::query(
        "INSERT INTO tenant_memberships (tenant_id, user_id, membership_type, status) \
         VALUES (?, ?, 'GUEST', 'ACTIVE')",
    )
    .bind(&host_tenant)
    .bind(&disabled_twin)
    .execute(&env.pool)
    .await
    .expect("create the twin's guest membership");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind smtp");
    let smtp_port = listener.local_addr().unwrap().port();
    let smtp_server = tokio::spawn(run_minimal_smtp_server(listener));
    upsert_setting(&env.pool, "smtp.host", "127.0.0.1").await;
    upsert_setting(&env.pool, "smtp.port", &smtp_port.to_string()).await;
    upsert_setting(&env.pool, "smtp.from_address", "noreply@example.test").await;
    upsert_setting(&env.pool, "smtp.use_tls", "false").await;

    // ── Request from the joined tenant's screen.
    let res = send(
        &env.app,
        post_internal(
            "/internal/password-reset/request",
            Some(SERVICE_TOKEN),
            json!({ "tenant_id": host_tenant, "email": email }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_json(res).await["result"], "accepted");

    // **Put a cap on the wait.** If the guest is not resolved no mail is sent and the SMTP server keeps waiting.
    // Without a cap, a broken feature would make the test **hang** instead of fail (slowing down finding the cause).
    let mail_body = tokio::time::timeout(std::time::Duration::from_secs(20), smtp_server)
        .await
        .expect("the guest was not resolved and no mail was delivered (MT26 regression)")
        .expect("smtp server task");
    let token = token_from_mail_body(&mail_body);
    assert!(!token.is_empty());

    // ── The link points to the home tenant (the body is carried in base64, so decode before looking).
    let text = mail_text(&mail_body);
    assert!(
        text.contains(&format!("/{}/password-reset?token=", env.root_tenant_id)),
        "the link points to the home tenant: {text}"
    );
    assert!(
        !text.contains(&format!("/{host_tenant}/password-reset?token=")),
        "a link pointing to the joined tenant is always rejected when executing the reset"
    );

    // ── Reset in the home tenant passes.
    let res = send(
        &env.app,
        post_internal(
            "/internal/password-reset/complete",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": env.root_tenant_id,
                "token": token,
                "new_password": "guest-brand-new-789"
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_json(res).await["result"], "ok");

    upsert_setting(&env.pool, "smtp.host", "").await;
    smtp_lock.release().await;
}

/// Requests whose tenant cannot be resolved are 400 with **a machine-distinguishable code** (MT28).
///
/// web maps only this code to the 404 screen, and other non-2xx to 502 as "web implementation / configuration error".
/// Before this distinction existed, merely mistyping the tenant ID in the URL turned submission into a bare 502.
#[tokio::test]
async fn an_unknown_tenant_is_rejected_with_a_distinguishable_code() {
    let Some(env) = support::setup("password reset unknown tenant").await else {
        return;
    };
    let res = send(
        &env.app,
        post_internal(
            "/internal/password-reset/request",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": uuid::Uuid::now_v7().to_string(),
                "email": "nobody@example.com"
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(res).await["error"],
        assay_contracts::auth::UNKNOWN_TENANT_ERROR_CODE
    );
}
