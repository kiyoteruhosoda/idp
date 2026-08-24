//! セルフサービス・パスワードリセットの E2E 統合テスト（MT18）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test password_reset
//!
//! インプロセスの最小 SMTP サーバを立て、システム設定（system_settings）を実際の配送先へ向けた
//! うえで「要求 → メール受信 → トークンでリセット → 単回消費・全セッション失効」を通しで検証する。

mod support;

use axum::http::StatusCode;
use serde_json::json;
use support::{body_json, create_sso_session, post_internal, send, SERVICE_TOKEN};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

/// 最小の SMTP 対話を話すインプロセスサーバ。受信した DATA 本文を返す。
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

/// メール本文からリセットトークンを取り出す。本文は日本語を含むため lettre が
/// base64 の Content-Transfer-Encoding を選ぶ（ヘッダ後の空行以降を base64 として復号する）。
/// 念のため quoted-printable（soft break・`=3D`）にも対応する。
/// SMTP の宛先は**システム設定（テナント別ではない）で 1 つしかない**。設定を書き換えるテストが
/// 並行に走ると、片方が向けた配送先へもう片方のメールが飛び、後始末（`smtp.host` を空へ戻す）が
/// 相手の受信前に走れば、待っている側は永久に受け取れない。設定の書き換えから受信・後始末までを
/// 直列化する。
static SMTP_SETTINGS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// SMTP で受け取った生データから、リンクを読める本文テキストを取り出す。
///
/// 本文は base64（または quoted-printable）で運ばれ、途中で折り返される。URL を素の文字列として
/// 検査したいテストは、この復号後のテキストを見る必要がある。
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

    // 対象ユーザーを自己登録で作成し、SSO セッションを 1 本持たせておく（失効の検証用）。
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

    // インプロセス SMTP サーバへ配送先を向ける。登録時のメール検証通知を拾わないよう、
    // 対象ユーザー作成後に設定する（テスト終了時に設定を空へ戻す）。
    let _smtp_guard = SMTP_SETTINGS.lock().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind smtp");
    let smtp_port = listener.local_addr().unwrap().port();
    let smtp_server = tokio::spawn(run_minimal_smtp_server(listener));
    upsert_setting(&env.pool, "smtp.host", "127.0.0.1").await;
    upsert_setting(&env.pool, "smtp.port", &smtp_port.to_string()).await;
    upsert_setting(&env.pool, "smtp.from_address", "noreply@example.test").await;
    upsert_setting(&env.pool, "smtp.use_tls", "false").await;

    // 1. リセット要求 → accepted・メールが実際に配送される。
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

    // 不存在アカウントでも同じ accepted（列挙防止）。
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

    // 2. トークンで新パスワードを設定 → ok。
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

    // トークンは used_at 付きで単回消費済み。
    let used: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = ? AND used_at IS NOT NULL",
    )
    .bind(&user_id)
    .fetch_one(&env.pool)
    .await
    .unwrap();
    assert_eq!(used, 1, "token consumed");

    // 既存 SSO セッションは全失効している。
    let sessions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sso_sessions WHERE user_id = ?")
        .bind(&user_id)
        .fetch_one(&env.pool)
        .await
        .unwrap();
    assert_eq!(sessions, 0, "all SSO sessions revoked after reset");

    // 3. 同じトークンの再利用は拒否される。
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

    // 後片付け: SMTP 設定を空へ戻す（他テストへ配送先を残さない）。
    upsert_setting(&env.pool, "smtp.host", "").await;
    upsert_setting(&env.pool, "smtp.from_address", "").await;
}

/// 参加先テナントにゲストとして参加している利用者が、その画面から再設定を要求できる（MT26）。
///
/// 要点は 2 つ。
///
/// 1. 要求テナント（参加先）で `users.email` が引けなくても、**参加中のゲストとして**解決される。
///    これが無いと、参加先の画面から入れるのに再設定だけができない行き止まりになる。
/// 2. メールのリンクは**所属元テナント**を指す。再設定の実行は「トークンの利用者の所属元 ==
///    要求テナント」を要求するため、参加先を指すリンクでは必ず弾かれる。
#[tokio::test]
async fn a_guest_can_request_a_reset_from_the_host_tenant() {
    let Some(env) = support::setup("password reset guest").await else {
        return;
    };

    // 所属元は root。参加先テナントとゲストメンバーシップは直接作る（検証したいのは招待フローでは
    // なく再設定の橋渡しのため）。
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

    let _smtp_guard = SMTP_SETTINGS.lock().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind smtp");
    let smtp_port = listener.local_addr().unwrap().port();
    let smtp_server = tokio::spawn(run_minimal_smtp_server(listener));
    upsert_setting(&env.pool, "smtp.host", "127.0.0.1").await;
    upsert_setting(&env.pool, "smtp.port", &smtp_port.to_string()).await;
    upsert_setting(&env.pool, "smtp.from_address", "noreply@example.test").await;
    upsert_setting(&env.pool, "smtp.use_tls", "false").await;

    // ── 参加先テナントの画面から要求する。
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

    // **待ちに上限を置く。** ゲストが解決されなければメールは飛ばず、SMTP サーバは接続を待ち続ける。
    // 上限が無いと、機能が壊れたときテストは失敗せず**ハングする**（原因に辿り着くのが遅れる）。
    let mail_body = tokio::time::timeout(std::time::Duration::from_secs(20), smtp_server)
        .await
        .expect("ゲストが解決されず、メールが配送されなかった（MT26 の回帰）")
        .expect("smtp server task");
    let token = token_from_mail_body(&mail_body);
    assert!(!token.is_empty());

    // ── リンクは所属元テナントを指す（本文は base64 で運ばれるので復号してから見る）。
    let text = mail_text(&mail_body);
    assert!(
        text.contains(&format!("/{}/password-reset?token=", env.root_tenant_id)),
        "リンクは所属元テナントを指すこと: {text}"
    );
    assert!(
        !text.contains(&format!("/{host_tenant}/password-reset?token=")),
        "参加先テナントを指すリンクは、再設定の実行で必ず弾かれる"
    );

    // ── 所属元テナントでの再設定は通る。
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
}

/// テナントを解決できない要求は、**機械的に区別できるコード**で 400 になる（MT28）。
///
/// web はこのコードだけを 404 の画面へ倒し、他の非 2xx は「web の実装/構成エラー」として 502 に
/// 倒す。区別が無かった頃は、URL のテナント ID を打ち間違えただけで送信が素の 502 になっていた。
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
        idp_contracts::auth::UNKNOWN_TENANT_ERROR_CODE
    );
}
