//! メンバー一覧のページング・絞り込み（`GET /{tenant_id}/admin/members`。MT22）の統合テスト（DB あり）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_members_list
//!
//! 一覧はテナント全体を返すため、テスト用の行だけを対象にできるよう**一意なマーカーを含む
//! メールアドレス**で絞り込む（同じ DB を共有する他のテストが root テナントへ行を追加しても
//! 件数の検証が壊れないようにするため）。検証するのは:
//!
//! 1. 認可（未認証 401 / 権限なし 403）。
//! 2. `limit` / `offset` でページが切り出され、`total` は絞り込み後の総件数を返すこと。
//! 3. ページ間で行が重複・欠落しないこと（並びが安定していること）。
//! 4. `limit` が上限へ丸められ、丸めた結果が応答の `limit` に載ること。
//! 5. `LIKE` のワイルドカードがエスケープされること（`%` が「全件一致」にならない）。
//! 6. 一覧の対象が**メンバーシップ**であること（他テナント所属のゲストは出る／非メンバーは出ない）。

mod support;

use axum::http::{Method, StatusCode};
use serde_json::Value;
use sqlx::MySqlPool;
use support::{admin_token, body_json, create_plain_user, get, send};

/// メールアドレスに一意マーカーを含む利用者を当該テナントへ作る（HOME メンバーシップ付き）。
/// `index` は並び順（メールアドレスの昇順）が予測できるようゼロ埋めする。
async fn insert_marked_user(pool: &MySqlPool, tenant_id: &str, marker: &str, index: u32) -> String {
    let id = uuid::Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO users (id, tenant_id, sub, email, email_verified, name, password_hash, status) \
         VALUES (?, ?, ?, ?, 1, ?, 'x', 'ACTIVE')",
    )
    .bind(&id)
    .bind(tenant_id)
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(format!("{marker}-{index:02}@example.com"))
    .bind(format!("Member {index:02}"))
    .execute(pool)
    .await
    .expect("insert marked user");
    sqlx::query(
        "INSERT INTO tenant_memberships (tenant_id, user_id, membership_type, status) \
         VALUES (?, ?, 'HOME', 'ACTIVE')",
    )
    .bind(tenant_id)
    .bind(&id)
    .execute(pool)
    .await
    .expect("insert home membership");
    id
}

fn emails(body: &Value) -> Vec<String> {
    body["members"]
        .as_array()
        .expect("members array")
        .iter()
        .map(|m| m["email"].as_str().unwrap_or_default().to_string())
        .collect()
}

#[tokio::test]
async fn member_list_pages_and_filters_on_the_server() {
    let Some(env) = support::setup("admin members list").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let marker = format!("mt22-{}", uuid::Uuid::now_v7().simple());
    for index in 1..=5 {
        insert_marked_user(&env.pool, &env.root_tenant_id, &marker, index).await;
    }
    let base = format!("/{}/admin/members", env.root_tenant_id);

    // ── 認可: トークン無しは 401、権限の無い利用者は 403。
    let res = send(&env.app, support::anonymous(Method::GET, &base, None)).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "no cookie -> 401");

    let plain = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let plain_token = admin_token(&env.app, &env.pool, &env.root_tenant_id, &plain).await;
    let res = send(&env.app, get(&plain_token, &base)).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "no admin perm -> 403");

    // ── 1 ページ目。`total` は limit を無視した該当総数。
    let res = send(
        &env.app,
        get(&admin_tok, &format!("{base}?q={marker}&limit=2&offset=0")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let first = body_json(res).await;
    assert_eq!(first["total"], 5, "絞り込み後の総件数");
    assert_eq!(first["limit"], 2);
    assert_eq!(first["offset"], 0);
    let page1 = emails(&first);
    assert_eq!(
        page1,
        vec![
            format!("{marker}-01@example.com"),
            format!("{marker}-02@example.com"),
        ],
        "メールアドレスの昇順で 1 ページ分だけ返る"
    );

    // ── 2 ページ目。ページ間で行が重複・欠落しない（並びが安定している）。
    let res = send(
        &env.app,
        get(&admin_tok, &format!("{base}?q={marker}&limit=2&offset=2")),
    )
    .await;
    let second = body_json(res).await;
    assert_eq!(second["total"], 5);
    let page2 = emails(&second);
    assert_eq!(
        page2,
        vec![
            format!("{marker}-03@example.com"),
            format!("{marker}-04@example.com"),
        ]
    );

    // ── 最終ページは端数（残り 1 件）。
    let res = send(
        &env.app,
        get(&admin_tok, &format!("{base}?q={marker}&limit=2&offset=4")),
    )
    .await;
    let third = body_json(res).await;
    assert_eq!(emails(&third), vec![format!("{marker}-05@example.com")]);

    // ── 範囲外の offset は空ページ（エラーにしない）。total は変わらない。
    let res = send(
        &env.app,
        get(&admin_tok, &format!("{base}?q={marker}&offset=999")),
    )
    .await;
    let beyond = body_json(res).await;
    assert_eq!(beyond["total"], 5);
    assert!(emails(&beyond).is_empty());

    // ── limit は上限（200）へ丸め、丸めた値を応答に載せる（呼び出し側がページ送りに使えるよう）。
    let res = send(
        &env.app,
        get(&admin_tok, &format!("{base}?q={marker}&limit=100000")),
    )
    .await;
    let clamped = body_json(res).await;
    assert_eq!(clamped["limit"], 200, "上限へ丸める");
    assert_eq!(clamped["members"].as_array().unwrap().len(), 5);

    // ── 氏名でも部分一致する（`name` 側の LIKE）。
    let res = send(&env.app, get(&admin_tok, &format!("{base}?q=Member%2003"))).await;
    let by_name = body_json(res).await;
    assert!(
        emails(&by_name).contains(&format!("{marker}-03@example.com")),
        "氏名の部分一致で見つかる: {by_name}"
    );
}

/// `%` / `_` は `LIKE` のワイルドカードなので、エスケープしないと検索語が意図しない広い一致になる
/// （`%` 単独なら全件一致）。
#[tokio::test]
async fn like_wildcards_in_the_search_term_are_escaped() {
    let Some(env) = support::setup("admin members list wildcards").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let marker = format!("mt22esc-{}", uuid::Uuid::now_v7().simple());
    insert_marked_user(&env.pool, &env.root_tenant_id, &marker, 1).await;
    let base = format!("/{}/admin/members", env.root_tenant_id);

    // `%` は「全件一致」ではなく、リテラルの `%` を含む行（＝無い）にだけ一致する。
    let res = send(&env.app, get(&admin_tok, &format!("{base}?q=%25"))).await;
    assert_eq!(res.status(), StatusCode::OK);
    let escaped = body_json(res).await;
    assert_eq!(escaped["total"], 0, "`%` が全件一致になってはいけない");

    // `_` も同様（任意の 1 文字ではなくリテラル）。マーカーの `-` は `_` に一致しない。
    let res = send(&env.app, get(&admin_tok, &format!("{base}?q=mt22esc_"))).await;
    let underscore = body_json(res).await;
    assert_eq!(
        underscore["total"], 0,
        "`_` が任意の 1 文字になってはいけない"
    );

    // エスケープしても通常の検索は効く。
    let res = send(&env.app, get(&admin_tok, &format!("{base}?q={marker}"))).await;
    assert_eq!(body_json(res).await["total"], 1);
}

/// 一覧の対象は**当該テナントのメンバーシップ**であって「所属元が当該テナントの利用者」ではない。
/// 他テナント所属のゲストは出て、メンバーシップを持たない利用者は出ない（テナント分離）。
#[tokio::test]
async fn list_covers_memberships_not_home_users() {
    let Some(env) = support::setup("admin members list scope").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let marker = format!("mt22scope-{}", uuid::Uuid::now_v7().simple());

    // 別テナント（root の子）に 2 名。片方だけ root へゲスト参加させる。
    let other_tenant = uuid::Uuid::now_v7().to_string();
    sqlx::query("INSERT INTO tenants (id, parent_tenant_id, name) VALUES (?, ?, ?)")
        .bind(&other_tenant)
        .bind(&env.root_tenant_id)
        .bind(format!("other-{}", &other_tenant[..8]))
        .execute(&env.pool)
        .await
        .expect("create other tenant");
    let guest = insert_marked_user(&env.pool, &other_tenant, &marker, 1).await;
    insert_marked_user(&env.pool, &other_tenant, &marker, 2).await;
    sqlx::query(
        "INSERT INTO tenant_memberships (tenant_id, user_id, membership_type, status) \
         VALUES (?, ?, 'GUEST', 'ACTIVE')",
    )
    .bind(&env.root_tenant_id)
    .bind(&guest)
    .execute(&env.pool)
    .await
    .expect("invite guest into root");

    let res = send(
        &env.app,
        get(
            &admin_tok,
            &format!("/{}/admin/members?q={marker}", env.root_tenant_id),
        ),
    )
    .await;
    let body = body_json(res).await;
    assert_eq!(
        body["total"], 1,
        "ゲスト 1 名だけが root のメンバー: {body}"
    );
    assert_eq!(emails(&body), vec![format!("{marker}-01@example.com")]);
    assert_eq!(body["members"][0]["membership_type"], "GUEST");

    // 招待中（未承諾）もメンバーシップ行なので一覧には出る（状態で区別できる）。
    let invited = insert_marked_user(&env.pool, &other_tenant, &marker, 3).await;
    sqlx::query(
        "INSERT INTO tenant_memberships (tenant_id, user_id, membership_type, status) \
         VALUES (?, ?, 'GUEST', 'INVITED')",
    )
    .bind(&env.root_tenant_id)
    .bind(&invited)
    .execute(&env.pool)
    .await
    .expect("invite guest into root");
    let res = send(
        &env.app,
        get(
            &admin_tok,
            &format!("/{}/admin/members?q={marker}", env.root_tenant_id),
        ),
    )
    .await;
    let body = body_json(res).await;
    assert_eq!(body["total"], 2);
    assert_eq!(body["members"][1]["status"], "INVITED");
}
