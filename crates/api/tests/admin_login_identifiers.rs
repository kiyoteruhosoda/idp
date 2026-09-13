//! ログイン識別子の管理 API（`/{tenant_id}/admin/users/{user_id}/login-identifiers`。AP8）の
//! 統合テスト（DB あり）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_login_identifiers
//!
//! 検証するのは:
//!
//! 1. 認可（未認証 401 / 権限なし 403）。
//! 2. 追加した識別子で**実際にログインできる**こと（登録簿を足しただけで解決経路が変わる。ADR-0025）。
//! 3. 無効化すると一致しなくなり、しかし行は残って他人が同じ値を取れないこと。
//! 4. すでにログインに使える値を拒否すること（他人の識別子・他人のメール・自分の主識別子）。
//! 5. 主たるログイン識別子は一覧に合成行として出るが、保存されていないので操作対象にならないこと。
//! 6. 監査には種別だけが残り、値（PII）が漏れないこと。

mod support;

/// テスト関数ごとのレート制限バケツ（下の `admin_login_result` のコメント参照）。
const IP_ASSIGN: &str = "203.0.113.81";
const IP_CONFLICT: &str = "203.0.113.82";

use axum::http::{Method, StatusCode};
use serde_json::{json, Value};
use sqlx::{MySqlPool, Row};
use support::{
    admin_token, body_json, delete, get, patch, post, post_internal, send, SERVICE_TOKEN,
};

/// 管理コンソールのログイン経路（`/internal/authenticate/admin`）で解決を確かめる。
///
/// ログイン識別子の解決は 4 経路が同じ `find_by_login_identifier` を通るため、代表 1 本で足りる。
/// 管理ログインを選ぶのは、`auth_session` の準備なしに「入力 → 結果」だけを見られるため。
/// 管理権限を持たない利用者なら、資格情報が正しければ `forbidden`（＝利用者は特定できた）、
/// 特定できなければ `invalid_credentials` になる。この差で解決の成否が読める。
///
/// `ip` はテスト関数ごとに変える。IP 単位のレートリミッタはプロセス内メモリ（シングル
/// インスタンス前提）で、同一バイナリ内で並行に走るテストがバケツを共有するため。
async fn admin_login_result(
    app: &axum::Router,
    tenant: &str,
    ip: &str,
    username: &str,
    password: &str,
) -> String {
    let response = send(
        app,
        post_internal(
            "/internal/authenticate/admin",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": tenant,
                "username": username,
                "password": password,
                "ip_address": ip,
                "user_agent": "integration-test",
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    body_json(response).await["result"]
        .as_str()
        .expect("result tag")
        .to_string()
}

async fn audit_reasons(pool: &MySqlPool, tenant_id: &str, event_type: &str) -> Vec<String> {
    sqlx::query(
        "SELECT reason FROM audit_log WHERE event_type = ? AND tenant_id = ? AND result = 'success' \
         ORDER BY occurred_at DESC LIMIT 20",
    )
    .bind(event_type)
    .bind(tenant_id)
    .fetch_all(pool)
    .await
    .expect("audit rows")
    .iter()
    .map(|row| row.get::<Option<String>, _>("reason").unwrap_or_default())
    .collect()
}

/// 自己登録で利用者を 1 人作り、その内部 ID を返す。
async fn register(env: &support::TestEnv, username: &str, password: &str) -> String {
    support::register_user(&env.app, &env.root_tenant_id, username, password).await;
    support::find_user_id_by_username(&env.pool, &env.root_tenant_id, username)
        .await
        .expect("registered user")
}

#[tokio::test]
async fn admin_assigns_a_phone_identifier_that_can_then_be_used_to_sign_in() {
    let Some(env) = support::setup("admin login identifiers").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;

    let unique = uuid::Uuid::now_v7().simple().to_string();
    let username = format!("li{}", &unique[..10]);
    let password = "correct-horse-battery";
    let target = register(&env, &username, password).await;
    let uri = format!(
        "/{}/admin/users/{target}/login-identifiers",
        env.root_tenant_id
    );

    // ── 認可。
    let res = send(&env.app, support::anonymous(Method::GET, &uri, None)).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    let outsider = support::create_plain_user(&env.pool, &env.root_tenant_id).await;
    let outsider_token = admin_token(&env.app, &env.pool, &env.root_tenant_id, &outsider).await;
    let res = send(&env.app, get(&outsider_token, &uri)).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // ── 一覧の先頭は主たる識別子、次が主メール（ADR-0050）。AP15 以降は登録簿にも実体の行が
    //    あるので `id` が付く（合成行が返るのは、移送前に作られた利用者だけ。
    //    `primary_login_identifier` テスト参照）。
    let res = send(&env.app, get(&admin_tok, &uri)).await;
    assert_eq!(res.status(), StatusCode::OK);
    let listed = body_json(res).await;
    let rows = listed.as_array().expect("array");
    assert_eq!(rows.len(), 2, "{listed}");
    assert_eq!(rows[0]["is_primary"], Value::Bool(true));
    assert!(rows[0]["id"].is_string(), "{listed}");
    assert_eq!(rows[0]["normalized_value"], username.to_lowercase());
    assert_eq!(rows[1]["is_primary_email"], Value::Bool(true));
    assert_eq!(rows[1]["identifier_type"], "email");
    let stored: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_login_identifiers \
         WHERE user_id = ? AND primary_of_user IS NOT NULL",
    )
    .bind(&target)
    .fetch_one(&env.pool)
    .await
    .expect("count");
    assert_eq!(stored, 1, "主識別子は登録簿にも載る（移送中は両方に在る）");

    // ── 電話番号を追加する。表示は登録どおり、照合は正規化した値。
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &uri,
            json!({"identifier_type": "phone_number", "value": "090-1234-5678"}),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let added = body_json(res).await;
    assert_eq!(added["display_value"], "090-1234-5678");
    assert_eq!(added["normalized_value"], "09012345678");
    assert_eq!(added["is_primary"], Value::Bool(false));
    let identifier_id = added["id"].as_str().expect("id").to_string();

    // ── 区切り記号の書き方が違っても同じ番号として解決される（正規化の効き目）。
    //    国際表記（`+81…`）は**別のキー**にしてある（国番号と国内プレフィクスの対応を
    //    推測すると別人の番号に当たり得るため。domain::login_identifier のテスト参照）。
    assert_eq!(
        admin_login_result(
            &env.app,
            &env.root_tenant_id,
            IP_ASSIGN,
            "(090) 1234.5678",
            password
        )
        .await,
        "forbidden",
        "電話番号で利用者は特定できるが、この利用者は管理権限を持たない"
    );
    // 資格情報が違えば invalid_credentials。識別子の解決とパスワード検証は別物である。
    assert_eq!(
        admin_login_result(
            &env.app,
            &env.root_tenant_id,
            IP_ASSIGN,
            "09012345678",
            "wrong-password"
        )
        .await,
        "invalid_credentials"
    );

    // ── 無効化すると解決されなくなる（＝未知の利用者と同じ扱い）。
    let item_uri = format!("{uri}/{identifier_id}");
    let res = send(
        &env.app,
        patch(&admin_tok, &item_uri, json!({"is_active": false})),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_json(res).await["is_active"], Value::Bool(false));
    assert_eq!(
        admin_login_result(
            &env.app,
            &env.root_tenant_id,
            IP_ASSIGN,
            "090-1234-5678",
            password
        )
        .await,
        "invalid_credentials"
    );

    // ── 無効化しても行は残るため、他の利用者は同じ値を取れない。
    let other = support::create_plain_user(&env.pool, &env.root_tenant_id).await;
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!(
                "/{}/admin/users/{other}/login-identifiers",
                env.root_tenant_id
            ),
            json!({"identifier_type": "phone_number", "value": "09012345678"}),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CONFLICT);

    // ── 監査には種別だけが残り、番号は残らない。
    let reasons = audit_reasons(
        &env.pool,
        &env.root_tenant_id,
        "user.login_identifier_added",
    )
    .await;
    assert!(reasons.iter().any(|r| r.contains("type=phone_number")));
    assert!(
        !reasons.iter().any(|r| r.contains("1234")),
        "監査に電話番号が残っている: {reasons:?}"
    );

    // ── 削除できる（無効化した行も消せる）。
    let res = send(&env.app, delete(&admin_tok, &item_uri)).await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let res = send(&env.app, delete(&admin_tok, &item_uri)).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND, "二度目は 404");
}

#[tokio::test]
async fn rejects_values_that_are_already_usable_for_signing_in() {
    let Some(env) = support::setup("login identifier conflicts").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;

    let unique = uuid::Uuid::now_v7().simple().to_string();
    let alice = format!("la{}", &unique[..10]);
    let bob = format!("lb{}", &unique[..10]);
    let password = "correct-horse-battery";
    let alice_id = register(&env, &alice, password).await;
    register(&env, &bob, password).await;
    let uri = format!(
        "/{}/admin/users/{alice_id}/login-identifiers",
        env.root_tenant_id
    );

    // 他人のユーザー名（大小違い）は拒否する。通すとログイン時に別人が返る。
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &uri,
            json!({"identifier_type": "username", "value": bob.to_uppercase()}),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CONFLICT);

    // 他人のメールアドレスも拒否する（メールは現状ログインの入り口ではないが、なりすませる）。
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &uri,
            json!({"identifier_type": "email", "value": format!("{bob}@example.com")}),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CONFLICT);

    // 自分の主識別子と同じ値も拒否する。登録できてしまうと、その行を無効化しても
    // `users.preferred_username` へのフォールバックで認証が通る（「止めたのに使える」）。
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &uri,
            json!({"identifier_type": "username", "value": alice.to_uppercase()}),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CONFLICT);

    // ── 種別が違っても、同じ値は別人が取れない（migration 0041）。**無効な行でも取れない。**
    //
    //    無効な行は解決にも空き判定にも当たらないため、ここは一意制約だけが止めている。
    //    止めないと、無効化している間に別人が同じ値を別種別で取り、有効へ戻した瞬間に
    //    「1 つの入力が 2 人に当たる」状態ができる —— 当人たちは正しいパスワードを出しても
    //    入れなくなり、しかも当人以外からは見えない。
    let reserved = format!("7{:09}", uuid::Uuid::new_v4().as_u128() % 1_000_000_000);
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &uri,
            json!({"identifier_type": "employee_number", "value": reserved, "is_active": false}),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "alice の社員番号（無効）"
    );

    let bob_id = support::find_user_id_by_username(&env.pool, &env.root_tenant_id, &bob)
        .await
        .expect("registered bob");
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!(
                "/{}/admin/users/{bob_id}/login-identifiers",
                env.root_tenant_id
            ),
            json!({"identifier_type": "username", "value": reserved}),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::CONFLICT,
        "無効な行が押さえている値は、種別を変えても別人が取れない"
    );

    // 書式不正は 400（登録できてしまうと「一致しない識別子」になり、理由が分からない）。
    for bad in [
        json!({"identifier_type": "phone_number", "value": "090-1234-abcd"}),
        json!({"identifier_type": "employee_number", "value": "A 1234"}),
        json!({"identifier_type": "not-a-type", "value": "x"}),
    ] {
        let res = send(&env.app, post(&admin_tok, &uri, bad.clone())).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{bad}");
    }

    // 自分のメールアドレスも拒否する。ADR-0050 以降、`users.email` は**主メール行として
    // 登録簿に在る**ので、同じ値をもう 1 行足すのは重複である（以前はここが 201 だった）。
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &uri,
            json!({"identifier_type": "email", "value": format!("{alice}@example.com")}),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CONFLICT);

    // ── メールでのログインはテナントのスイッチが決める（ADR-0050 決定 3）。
    //
    //    行は移行・作成時から在るが、スイッチが入るまでログイン欄では一致しない。
    //    「一意性は常に効く／入り口はテナントが開ける」を分けてあることの確認である。
    //
    //    ⚠ **既定に頼らず、両方の状態を明示的に作る。** テナントは他のテストと共有で、DB は
    //    実行をまたいで使い回される。切ってから確かめないと、前の実行が入れたままのスイッチで
    //    「入っていない側」の検証が素通りする（実際にそれで 2 回目が落ちた）。
    let set_email_login = |on: bool| {
        let pool = env.pool.clone();
        let tenant = env.root_tenant_id.clone();
        async move {
            sqlx::query("UPDATE tenants SET email_login_enabled = ? WHERE id = ?")
                .bind(on)
                .bind(tenant)
                .execute(&pool)
                .await
                .expect("toggle email login");
        }
    };

    set_email_login(false).await;
    assert_eq!(
        admin_login_result(
            &env.app,
            &env.root_tenant_id,
            IP_CONFLICT,
            &format!("{alice}@example.com"),
            password
        )
        .await,
        "invalid_credentials",
        "スイッチが入るまではメールで利用者を特定できない"
    );

    set_email_login(true).await;
    let with_switch_on = admin_login_result(
        &env.app,
        &env.root_tenant_id,
        IP_CONFLICT,
        &format!("{alice}@example.com"),
        password,
    )
    .await;
    // 共有テナントなので、確かめたら必ず戻す（次のテスト・次の実行へ持ち越さない）。
    set_email_login(false).await;
    assert_eq!(
        with_switch_on, "forbidden",
        "スイッチを入れるとメールで利用者が特定できる（この利用者は管理権限を持たない）"
    );
}

#[tokio::test]
async fn the_primary_rows_cannot_be_targeted_even_by_their_real_id() {
    let Some(env) = support::setup("login identifier primary").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;

    let unique = uuid::Uuid::now_v7().simple().to_string();
    let username = format!("lp{}", &unique[..10]);
    let target = register(&env, &username, "correct-horse-battery").await;
    let uri = format!(
        "/{}/admin/users/{target}/login-identifiers",
        env.root_tenant_id
    );

    // 存在しない id は 404。
    let stray = uuid::Uuid::now_v7();
    let res = send(
        &env.app,
        patch(
            &admin_tok,
            &format!("{uri}/{stray}"),
            json!({"is_active": false}),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let res = send(&env.app, delete(&admin_tok, &format!("{uri}/{stray}"))).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    // ── ⚠ **実在する id で撃つ。** AP15b で主識別子も登録簿の行になり `id` が付いたので、
    //    「合成行には id が無いから宛先を作れない」はもう成り立たない。守っているのは
    //    リポジトリの条件（`primary_of_user IS NULL` / `primary_email_of_user IS NULL`）
    //    だけで、そこを撃たないとこのテストは**通る理由が違ってしまう**。
    let listed = body_json(send(&env.app, get(&admin_tok, &uri)).await).await;
    let rows = listed.as_array().expect("array");
    for key in ["is_primary", "is_primary_email"] {
        let row = rows
            .iter()
            .find(|r| r[key] == Value::Bool(true))
            .unwrap_or_else(|| panic!("no row with {key}: {listed}"));
        let id = row["id"].as_str().expect("real id");
        let res = send(
            &env.app,
            patch(
                &admin_tok,
                &format!("{uri}/{id}"),
                json!({"is_active": false}),
            ),
        )
        .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "{key} は止められない");
        let res = send(&env.app, delete(&admin_tok, &format!("{uri}/{id}"))).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "{key} は消せない");
    }

    // プロフィール編集でログイン識別子を変えると、一覧も追随する（AP15 の移送中は `users` と
    // 登録簿の両方へ書くので、古い値が片側に残らない）。
    let renamed = format!("lq{}", &unique[..10]);
    let res = send(
        &env.app,
        patch(
            &admin_tok,
            &format!("/{}/admin/users/{target}/profile", env.root_tenant_id),
            json!({"preferred_username": renamed}),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);

    let listed = body_json(send(&env.app, get(&admin_tok, &uri)).await).await;
    let rows = listed.as_array().expect("array");
    assert_eq!(rows.len(), 2, "{listed}");
    assert_eq!(rows[0]["is_primary"], Value::Bool(true));
    assert_eq!(rows[0]["normalized_value"], renamed.to_lowercase());
    // 改名はユーザー名の行だけを動かす。主メール行はメールアドレスの写しなので、
    // プロフィール編集でメールを変えていない以上そのままである（ADR-0050）。
    assert_eq!(rows[1]["is_primary_email"], Value::Bool(true));
    assert_eq!(rows[1]["identifier_type"], "email");
}
