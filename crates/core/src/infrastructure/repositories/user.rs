//! `UserRepository` の sqlx 実装。UUID は CHAR(36) 正準文字列として入出力する。

use crate::domain::authentication_policy::LockoutPolicy;
use crate::domain::error::{DomainError, Result};
use crate::domain::login_identifier::LoginIdentifierMatch;
use crate::domain::repositories::UserRepository;
use crate::domain::tenant::TenantId;
use crate::domain::user::{LoginFailureRecord, User};
use crate::domain::values::{MembershipStatus, MembershipType, UserStatus};
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::mysql::MySqlRow;
use sqlx::{MySql, QueryBuilder, Row};
use uuid::Uuid;

pub struct SqlxUserRepository {
    pool: Db,
}

impl SqlxUserRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }

    /// 登録簿（`user_login_identifiers`）を引く 2 つの解決が共有する本体（AP8、ADR-0009 §8）。
    ///
    /// **複数の利用者に当たったら誰も返さない**（[`LoginIdentifierMatch::Unresolved`] の
    /// `Ambiguous`。「不在」とは区別する。MT25）。1 テナント内で 1 正規化値は 1 人のものだが
    /// （migration 0041）、種別ごとに正規化が違うため 1 つの入力は複数の正規化値へ広がり、
    /// 「ユーザー名としては A、電話番号としては B」という入力があり得る（ゲスト解決は所属元
    /// テナントもまたぐ）。
    /// `LIMIT 1` でどちらかを選ぶと、どちらが返るかが索引の都合で決まってしまう。曖昧な入力で
    /// 認証を通すより、通さない方を選ぶ（候補生成側でも起きにくくしてある。
    /// [`crate::domain::login_identifier::lookup_candidates`]）。
    async fn resolve_login_identifier(
        &self,
        scope: IdentifierScope,
        tenant_id: TenantId,
        input: &str,
    ) -> Result<LoginIdentifierMatch> {
        let candidates = crate::domain::login_identifier::lookup_candidates(input);
        if candidates.is_empty() {
            return Ok(LoginIdentifierMatch::not_found());
        }
        let sql = login_identifier_sql(scope, candidates.len());
        let mut query = sqlx::query(&sql);
        for bind in scope.binds(tenant_id) {
            query = query.bind(bind);
        }
        for (kind, normalized) in &candidates {
            query = query.bind(kind.as_str()).bind(normalized.clone());
        }
        let rows = query.fetch_all(&self.pool).await.map_err(repo_err)?;
        match rows.len() {
            0 => Ok(LoginIdentifierMatch::not_found()),
            1 => map_row(&rows[0]).map(LoginIdentifierMatch::Resolved),
            _ => {
                // 曖昧。ログイン経路は監査にも残すが（`UnresolvedReason::audit_code`）、登録・改名の
                // 空き判定はここを通っても監査に出ないため、運用ログにも残す（値は PII のため出さない）。
                tracing::warn!(
                    tenant_id = %tenant_id,
                    "login identifier resolved to multiple users; refusing to authenticate"
                );
                Ok(LoginIdentifierMatch::ambiguous())
            }
        }
    }
}

/// 登録簿を引く範囲（ADR-0009 §8・ADR-0029）。ログイン経路が「所属元として引くのか、参加先の
/// ゲストとして引くのか、ドメインで決まった所属元テナントに絞って引くのか」を選ぶ。SQL 断片を
/// 引数で渡し回さず列挙で表すことで、組み立て可能な形がこの 3 つに閉じる。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdentifierScope {
    /// 所属元テナントの登録簿（`user_login_identifiers.tenant_id` = 要求テナント）。
    /// 引き方に合わせた索引 `user_login_identifiers_lookup_idx (tenant_id, 種別, 正規化値)`
    /// に乗る（migration 0041 で一意キーから種別が外れたため、索引は別立てになった）。
    Home,
    /// 要求テナントに ACTIVE な GUEST として参加している利用者を、**その利用者の所属元の**
    /// 登録簿で引く。
    ActiveGuest,
    /// 所属元テナントが**分かっている**とき（ドメインから決まった。ADR-0029）に、そのテナントの
    /// 登録簿だけを引く。要求テナントで ACTIVE なメンバー（HOME / GUEST を問わない）であることは
    /// [`Self::ActiveGuest`] と同じく課す。
    ///
    /// **この範囲では曖昧さが原理的に起きない。** 引くのは 1 テナントの登録簿だけで、その中では
    /// 1 正規化値が 1 人のものだからである（migration 0041）。ゲストを横断走査しないので、
    /// 同名のゲストが何人参加していても互いに干渉しない。
    MemberWithHomeTenant(TenantId),
}

impl IdentifierScope {
    /// `FROM user_login_identifiers i JOIN users u ...` に続く JOIN と WHERE。候補の IN 句以外の
    /// 絞り込みをここに書き、末尾は条件で終える（IN 句を ` AND` で継ぐため）。
    ///
    /// `ActiveGuest` の `i.tenant_id = u.tenant_id` は「識別子は所属元テナントに登録される」という
    /// 登録簿の不変条件を明示するもので、これが無いと他テナントに登録された行でも解決されうる。
    ///
    /// `home.status = 'ACTIVE'`（所属元テナントが有効）も課す（ADR-0009 §8）。所属元の無効化は
    /// 「その組織の利用者を止める」操作であり、参加先テナント経由の裏口を残す意味ではない。
    /// `Home` 側に同じ条件が要らないのは、そちらの要求テナント＝所属元テナントであり、middleware
    /// （`TenantResolutionService`）が `DISABLED` なら 404 で先に止めているため。同じ規則を
    /// メンバーシップ側から見たものが `TenantMembershipRepository::is_active_member`。
    ///
    /// `ActiveGuest` は `Home` と違い引き方の索引（`user_login_identifiers_lookup_idx`
    /// = `(tenant_id, 種別, 正規化値)`）には乗らず、
    /// 当該テナントの ACTIVE な GUEST メンバーシップ
    /// （`tenant_memberships_tenant_type_status_idx (tenant_id, membership_type, status)`。
    /// migration 0040）から、利用者の識別子（`(user_id, identifier_type)` の索引）へ辿る。等値条件を
    /// 索引の列順に合わせてあるので、走査はテナントのメンバー数ではなく**ゲスト数**に比例する。
    ///
    /// この経路が走るのは所属元での解決が空振りしたとき、つまり**参加先の画面からのゲストの
    /// ログインすべて**と、**存在しないユーザー名でのログイン試行**のたびである。前者は通常の
    /// ログインであり、後者は総当たりが最も送ってくる形でもあるため、どちらもメンバー数に
    /// 比例させない。
    fn sql(self) -> &'static str {
        match self {
            Self::Home => "WHERE i.tenant_id = ?",
            Self::ActiveGuest => {
                "JOIN tenant_memberships m ON m.user_id = u.id \
                 JOIN tenants home ON home.id = u.tenant_id AND home.status = 'ACTIVE' \
                 WHERE m.tenant_id = ? AND m.membership_type = ? AND m.status = ? \
                   AND i.tenant_id = u.tenant_id"
            }
            // 所属元が決まっているので、メンバーシップ種別では絞らない（HOME でも GUEST でもよい）。
            // 代わりに `u.tenant_id = ?` で所属元を固定する。要求テナント自身がドメインを持つ場合も
            // この形で足りる（そのときの所属元＝要求テナントで、HOME 側に当たる）。
            Self::MemberWithHomeTenant(_) => {
                "JOIN tenant_memberships m ON m.user_id = u.id \
                 JOIN tenants home ON home.id = u.tenant_id AND home.status = 'ACTIVE' \
                 WHERE m.tenant_id = ? AND m.status = ? \
                   AND u.tenant_id = ? AND i.tenant_id = u.tenant_id"
            }
        }
    }

    /// [`Self::sql`] のプレースホルダを、候補（種別 × 正規化値）より先に埋める値。メンバーシップの
    /// 種別・状態はリテラルを書かず Rust 側の enum から取り、許可値の単一の出所から離れないようにする。
    fn binds(self, tenant_id: TenantId) -> Vec<String> {
        match self {
            Self::Home => vec![tenant_id.to_string()],
            Self::ActiveGuest => vec![
                tenant_id.to_string(),
                MembershipType::Guest.as_str().to_string(),
                MembershipStatus::Active.as_str().to_string(),
            ],
            Self::MemberWithHomeTenant(home_tenant_id) => vec![
                tenant_id.to_string(),
                MembershipStatus::Active.as_str().to_string(),
                home_tenant_id.to_string(),
            ],
        }
    }
}

/// 登録簿の解決クエリを組み立てる。外部入力は必ず bind を通り、この文字列に載るのは
/// モジュール内のリテラルと `?` の個数だけ（DB 無しで形を検証できるよう関数に切り出す）。
fn login_identifier_sql(scope: IdentifierScope, candidate_count: usize) -> String {
    let placeholders = vec!["(?, ?)"; candidate_count].join(", ");
    let scope = scope.sql();
    format!(
        "SELECT DISTINCT {SELECT_COLUMNS} \
         FROM user_login_identifiers i \
         JOIN users u ON u.id = i.user_id \
         {scope} \
           AND i.is_active = 1 \
           AND (i.identifier_type, i.normalized_value) IN ({placeholders}) \
         LIMIT 2"
    )
}

/// `users` の列と、**登録簿から連れてくる主たるログイン識別子**。
///
/// AP15b で `users.preferred_username` を撤去したので、この 1 列だけは
/// `user_login_identifiers` の主識別子行（`primary_of_user`）から引く。JOIN ではなく相関
/// サブクエリにするのは、主識別子を持たない利用者（管理者が作ってユーザー名を付けていない
/// アカウント）を落とさないため —— `find_by_id` が突然 `None` を返すようになる。
const SELECT_COLUMNS: &str = "u.id AS id, u.tenant_id AS tenant_id, u.sub AS sub, \
     u.email AS email, u.email_verified AS email_verified, \
     (SELECT p.display_value FROM user_login_identifiers p WHERE p.primary_of_user = u.id) \
        AS preferred_username, \
     u.name AS name, u.language AS language, u.password_hash AS password_hash, \
     u.must_change_password AS must_change_password, \
     u.password_changed_at AS password_changed_at, u.status AS status, \
     u.failed_login_count AS failed_login_count, u.locked_until AS locked_until, \
     u.created_at AS created_at, u.updated_at AS updated_at";

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

/// 登録簿の一意制約（tenant × 正規化値。migration 0041 で種別に依存しない）違反を `Conflict`
/// として返す。事前チェックをすり抜けた同時実行はここで捕まる
/// （AP15b でこの制約が主識別子にも効くようになった）。
fn identifier_conflict(e: sqlx::Error) -> DomainError {
    match &e {
        sqlx::Error::Database(db) if db.is_unique_violation() => DomainError::Conflict(
            "preferred_username is already used as a login identifier by another user".to_string(),
        ),
        _ => DomainError::Repository(e.to_string()),
    }
}

fn to_utc(naive: NaiveDateTime) -> DateTime<Utc> {
    Utc.from_utc_datetime(&naive)
}

fn parse_uuid(s: &str) -> Result<Uuid> {
    Uuid::parse_str(s).map_err(|e| DomainError::Repository(format!("invalid UUID `{s}`: {e}")))
}

fn map_row(row: &MySqlRow) -> Result<User> {
    let id: String = row.try_get("id").map_err(repo_err)?;
    let tenant_id: String = row.try_get("tenant_id").map_err(repo_err)?;
    let sub: String = row.try_get("sub").map_err(repo_err)?;
    let status: String = row.try_get("status").map_err(repo_err)?;
    let locked_until: Option<NaiveDateTime> = row.try_get("locked_until").map_err(repo_err)?;
    let password_changed_at: Option<NaiveDateTime> =
        row.try_get("password_changed_at").map_err(repo_err)?;
    Ok(User {
        id: parse_uuid(&id)?,
        tenant_id: parse_uuid(&tenant_id)?.into(),
        sub: parse_uuid(&sub)?,
        email: row.try_get("email").map_err(repo_err)?,
        email_verified: row.try_get("email_verified").map_err(repo_err)?,
        preferred_username: row.try_get("preferred_username").map_err(repo_err)?,
        name: row.try_get("name").map_err(repo_err)?,
        language: row.try_get("language").map_err(repo_err)?,
        password_hash: row.try_get("password_hash").map_err(repo_err)?,
        must_change_password: row.try_get("must_change_password").map_err(repo_err)?,
        password_changed_at: password_changed_at.map(to_utc),
        status: UserStatus::parse(&status)?,
        failed_login_count: row.try_get("failed_login_count").map_err(repo_err)?,
        locked_until: locked_until.map(to_utc),
        created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
        updated_at: to_utc(row.try_get("updated_at").map_err(repo_err)?),
    })
}

/// 主たるログイン識別子を登録簿へ書き込む（AP15b で**唯一の置き場所**になった）。
///
/// `preferred_username` が `None`・空のときは主識別子行を削除する（解除）。
///
/// # 同じ値を他人が持っているとき
///
/// **`Conflict` で失敗させる。** 前半（expand）の間は「登録簿を諦めて `users` 側を正とする」で
/// 済ませていた —— どちらにも在り、`users` 側で解決され続けたからである。列を落とした今、
/// 諦めると**そのユーザー名でログインできない利用者を黙って作る**ことになる。
///
/// 衝突は 2 通りの経路で当たる。他人の識別子と同じ値なら下の事前チェックが（**種別を問わず**。
/// 一意キーと同じ範囲で見る）、同時実行ですり抜けたものは登録簿の一意制約
/// （tenant × 正規化値）が捕まえる。移送が済んだことで、
/// ADR-0025 が「残る限界」として挙げていた同時実行の窓は DB 側で塞がった。
async fn sync_primary_login_identifier(
    conn: &mut sqlx::MySqlConnection,
    user_id: Uuid,
    preferred_username: Option<&str>,
) -> Result<()> {
    use crate::domain::login_identifier::LoginIdentifierType;

    let Some(value) = preferred_username.map(str::trim).filter(|v| !v.is_empty()) else {
        sqlx::query(
            "DELETE FROM user_login_identifiers WHERE user_id = ? AND primary_of_user IS NOT NULL",
        )
        .bind(user_id.to_string())
        .execute(&mut *conn)
        .await
        .map_err(repo_err)?;
        return Ok(());
    };
    let normalized = LoginIdentifierType::Username.normalize(value);

    // 他人が同じ値を握っているか（テナントは利用者の行から引く。呼び出し側に渡させると
    // `users` と食い違う余地が生まれる）。
    //
    // **種別で絞らない。** migration 0041 で一意キーから `identifier_type` が外れたので、種別で
    // 絞ると制約より狭い判定になる —— 他人が別種別で同じ正規化値を持っていると素通りし、この
    // 事前チェックの存在意義（「制約が弾くものを、書きに行く前に同じ範囲で見る」）が失われる。
    // 利用者から見た応答は変わらない（素通りしても書き込みが一意制約で落ち、どちらの経路も
    // `Conflict` になる）が、DB エラー頼みの経路をトランザクションの途中に残さない。
    // 無効な行も見る（一意キーが `is_active` を見ないのと同じ。無効化した識別子の値は別人へ
    // 渡さない）。条件が一意キーと同じ 2 列なので、索引もそのまま乗る。
    let taken_by_someone_else: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM user_login_identifiers i \
         JOIN users u ON u.id = ? \
         WHERE i.tenant_id = u.tenant_id \
           AND i.normalized_value = ? AND i.user_id <> u.id \
         LIMIT 1",
    )
    .bind(user_id.to_string())
    .bind(&normalized)
    .fetch_optional(&mut *conn)
    .await
    .map_err(repo_err)?;
    if taken_by_someone_else.is_some() {
        // 値そのものは PII なので出さない（`CLAUDE.md`「ログ」）。
        return Err(DomainError::Conflict(
            "preferred_username is already used as a login identifier by another user".to_string(),
        ));
    }

    // 主識別子は 1 利用者 1 行（`primary_of_user` の UNIQUE が保証する）。既存行があれば
    // 値を入れ替え、無ければ作る。「更新して 0 行なら INSERT」にしないのは、MariaDB の
    // 影響行数が**変わった行**の数で、同じ値で更新すると 0 になるためである（そこで INSERT に
    // 回ると一意制約で落ちる）。
    let existing: Option<String> = sqlx::query_scalar(
        "SELECT id FROM user_login_identifiers WHERE user_id = ? AND primary_of_user IS NOT NULL",
    )
    .bind(user_id.to_string())
    .fetch_optional(&mut *conn)
    .await
    .map_err(repo_err)?;

    match existing {
        Some(id) => {
            sqlx::query(
                "UPDATE user_login_identifiers \
                 SET identifier_type = 'username', display_value = ?, normalized_value = ?, \
                     is_active = 1 \
                 WHERE id = ?",
            )
            .bind(value)
            .bind(&normalized)
            .bind(id)
            .execute(&mut *conn)
            .await
            .map_err(identifier_conflict)?;
        }
        None => {
            sqlx::query(
                "INSERT INTO user_login_identifiers \
                 (id, tenant_id, user_id, identifier_type, display_value, normalized_value, \
                  is_active, primary_of_user) \
                 SELECT ?, u.tenant_id, u.id, 'username', ?, ?, 1, u.id FROM users u WHERE u.id = ?",
            )
            .bind(uuid::Uuid::now_v7().to_string())
            .bind(value)
            .bind(&normalized)
            .bind(user_id.to_string())
            .execute(&mut *conn)
            .await
            .map_err(identifier_conflict)?;
        }
    }
    Ok(())
}

/// users への INSERT と、主たるログイン識別子の登録。
///
/// **必ず同じトランザクションで行う。** ユーザー名が他人と衝突すると識別子の側が `Conflict` で
/// 失敗するが（AP15b）、`users` の行だけが残ると「ログインする手段を持たない利用者」が
/// できてしまう。呼び出し側にトランザクションを渡させるのはそのためである。
async fn insert_user(conn: &mut sqlx::MySqlConnection, user: &User) -> Result<()> {
    sqlx::query(
        "INSERT INTO users \
         (id, tenant_id, sub, email, email_verified, name, language, \
          password_hash, must_change_password, password_changed_at, status, failed_login_count, \
          locked_until) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(user.id.to_string())
    .bind(user.tenant_id.to_string())
    .bind(user.sub.to_string())
    .bind(&user.email)
    .bind(user.email_verified)
    .bind(&user.name)
    .bind(&user.language)
    .bind(&user.password_hash)
    .bind(user.must_change_password)
    .bind(user.password_changed_at.map(|d| d.naive_utc()))
    .bind(user.status.as_str())
    .bind(user.failed_login_count)
    .bind(user.locked_until.map(|d| d.naive_utc()))
    .execute(&mut *conn)
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            DomainError::Conflict("email already exists".to_string())
        }
        _ => DomainError::Repository(e.to_string()),
    })?;
    // 主たるログイン識別子の置き場所は登録簿だけである（AP15b）。値が他人と衝突していれば
    // ここで `Conflict` になり、利用者の作成ごと失敗する。
    sync_primary_login_identifier(conn, user.id, user.preferred_username.as_deref()).await?;
    Ok(())
}

#[async_trait]
impl UserRepository for SqlxUserRepository {
    async fn create(&self, user: &User) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(repo_err)?;
        insert_user(&mut tx, user).await?;
        tx.commit().await.map_err(repo_err)?;
        Ok(())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>> {
        let sql = format!("SELECT {SELECT_COLUMNS} FROM users u WHERE u.id = ?");
        let row = sqlx::query(&sql)
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn find_by_sub(&self, sub: Uuid) -> Result<Option<User>> {
        let sql = format!("SELECT {SELECT_COLUMNS} FROM users u WHERE u.sub = ?");
        let row = sqlx::query(&sql)
            .bind(sub.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn find_by_email(&self, tenant_id: TenantId, email: &str) -> Result<Option<User>> {
        let sql =
            format!("SELECT {SELECT_COLUMNS} FROM users u WHERE u.tenant_id = ? AND u.email = ?");
        let row = sqlx::query(&sql)
            .bind(tenant_id.to_string())
            .bind(email)
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    /// 主たるログイン識別子（ユーザー名）で引く。
    ///
    /// 照合は登録簿の正規化値で行う（AP15b）。`users.preferred_username` の照合は照合順序
    /// （`utf8mb4_unicode_ci`）任せで大小を無視していたが、登録簿は種別ごとの正規化を
    /// **明示的に**持っている。同じ規則を通すために、入力もここで正規化する。
    async fn find_by_username(&self, tenant_id: TenantId, username: &str) -> Result<Option<User>> {
        use crate::domain::login_identifier::LoginIdentifierType;

        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM users u \
             JOIN user_login_identifiers p ON p.primary_of_user = u.id \
             WHERE u.tenant_id = ? AND p.normalized_value = ?"
        );
        let row = sqlx::query(&sql)
            .bind(tenant_id.to_string())
            .bind(LoginIdentifierType::Username.normalize(username))
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    /// ログイン欄の入力から解決する（AP8）。
    ///
    /// 登録簿（`user_login_identifiers`）の**有効な行**を、種別ごとの正規化キーで 1 クエリで引く。
    /// 「全件読んでアプリ側で正規化して突き合わせる」方式は取らない（テナントの規模に比例して
    /// 破綻するうえ、一意性の保証が DB から離れる）。
    ///
    /// 曖昧な入力を通さない規則は [`Self::resolve_login_identifier`] に置いてあり、参加先テナントの
    /// ゲスト解決（[`Self::find_active_guest_by_login_identifier`]）と共有する。
    ///
    /// **登録簿だけを見る。** 主識別子も登録簿の行になったので（AP15b）、`users` 側への
    /// フォールバックは無い。無いことに意味がある —— フォールバックが残っていると、
    /// 登録簿で無効化した識別子でも `users` 側で解決されて認証が通り、「止めたのに使える」
    /// 識別子ができる。
    async fn find_by_login_identifier(
        &self,
        tenant_id: TenantId,
        input: &str,
    ) -> Result<LoginIdentifierMatch> {
        self.resolve_login_identifier(IdentifierScope::Home, tenant_id, input)
            .await
    }

    /// 参加先テナントの ACTIVE な GUEST を、**その利用者の所属元テナントの**登録簿で解決する
    /// （[`IdentifierScope::ActiveGuest`]）。
    async fn find_active_guest_by_login_identifier(
        &self,
        tenant_id: TenantId,
        input: &str,
    ) -> Result<LoginIdentifierMatch> {
        self.resolve_login_identifier(IdentifierScope::ActiveGuest, tenant_id, input)
            .await
    }

    /// 所属元テナントが分かっているとき、そのテナントの登録簿だけを引く
    /// （[`IdentifierScope::MemberWithHomeTenant`]。ADR-0029）。
    async fn find_member_by_login_identifier(
        &self,
        tenant_id: TenantId,
        home_tenant_id: TenantId,
        input: &str,
    ) -> Result<LoginIdentifierMatch> {
        self.resolve_login_identifier(
            IdentifierScope::MemberWithHomeTenant(home_tenant_id),
            tenant_id,
            input,
        )
        .await
    }

    async fn update_login_state(
        &self,
        id: Uuid,
        failed_login_count: i32,
        locked_until: Option<DateTime<Utc>>,
    ) -> Result<()> {
        sqlx::query("UPDATE users SET failed_login_count = ?, locked_until = ? WHERE id = ?")
            .bind(failed_login_count)
            .bind(locked_until.map(|d| d.naive_utc()))
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }

    async fn record_login_failure(
        &self,
        id: Uuid,
        lockout: LockoutPolicy,
        now: DateTime<Utc>,
    ) -> Result<LoginFailureRecord> {
        // 加算とロック判定を 1 文で行う（SEC13）。読んで書き戻す方式では、並行する試行が同じ値を
        // 読んで同じ値を書くため、N 回失敗しても 1 しか進まないことがある。
        //
        // **代入の順序に意味がある。** MariaDB / MySQL の単一表 UPDATE は SET を左から右へ評価し、
        // 後続の式は先に更新された列の**新しい値**を見る。`locked_until` を先に置くことで、
        // その CASE の中の `failed_login_count` は更新前の値を指す（逆順にすると 2 回分進む）。
        //
        // 段階的ロック（AP6）: ロック時間は失敗回数で変わるが、その回数はこの UPDATE の中に
        // しか無い。計算式を SQL へ写すと定義が二重化するため、**段の一覧をドメインから受け取り
        // （`escalation_ladder`）、SQL 側は該当する段を選ぶだけ**にする。段は超過の大きい順に
        // 並んでいるので、先に一致した WHEN が最も長いロック時間になる。
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new("UPDATE users SET locked_until = CASE");
        for (threshold, duration_secs) in lockout.escalation_ladder() {
            qb.push(" WHEN failed_login_count + 1 >= ");
            qb.push_bind(threshold);
            qb.push(" THEN ");
            qb.push_bind((now + chrono::Duration::seconds(duration_secs as i64)).naive_utc());
        }
        qb.push(" ELSE locked_until END, failed_login_count = failed_login_count + 1 WHERE id = ");
        qb.push_bind(id.to_string());
        qb.build().execute(&self.pool).await.map_err(repo_err)?;

        // 記録後の状態を読み直す（MariaDB の UPDATE は RETURNING を持たない）。並行する失敗が
        // 間に挟まれば、より進んだ値・より新しいロック期限が返る。どちらも「今ロックされているか」の
        // 判定としては正しく、監査に残る回数が実際の試行数を下回ることも無い。
        let row = sqlx::query("SELECT failed_login_count, locked_until FROM users WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        let Some(row) = row else {
            // 記録の途中で利用者が消えた（管理者削除）。ロック判定の対象が無いだけなので、
            // 「ロックされていない」として扱う。
            return Ok(LoginFailureRecord {
                failed_login_count: 0,
                locked_until: None,
            });
        };
        let locked_until: Option<NaiveDateTime> = row.try_get("locked_until").map_err(repo_err)?;
        Ok(LoginFailureRecord {
            failed_login_count: row.try_get("failed_login_count").map_err(repo_err)?,
            // 期限切れのロックは「掛かっていない」とみなす（読み直しの時点で判定する）。
            locked_until: locked_until.map(to_utc).filter(|until| *until > now),
        })
    }

    async fn update_password(
        &self,
        id: Uuid,
        expected_current_hash: &str,
        password_hash: &str,
    ) -> Result<bool> {
        // 現行ハッシュを条件に含めた compare-and-swap（トレイト定義の理由参照）。
        // 設定時刻は DB の時計で入れる（`created_at` / `updated_at` と同じ扱い。AP7 の有効期限は
        // この列を起点に測る）。
        let result = sqlx::query(
            "UPDATE users SET password_hash = ?, must_change_password = 0, \
             password_changed_at = UTC_TIMESTAMP(6) WHERE id = ? AND password_hash = ?",
        )
        .bind(password_hash)
        .bind(id.to_string())
        .bind(expected_current_hash)
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(result.rows_affected() == 1)
    }

    async fn reset_password_forced(
        &self,
        id: Uuid,
        expected_current_hash: &str,
        password_hash: &str,
    ) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE users SET password_hash = ?, must_change_password = 1, \
             password_changed_at = UTC_TIMESTAMP(6) WHERE id = ? AND password_hash = ?",
        )
        .bind(password_hash)
        .bind(id.to_string())
        .bind(expected_current_hash)
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(result.rows_affected() == 1)
    }

    async fn update_status(&self, id: Uuid, status: UserStatus) -> Result<()> {
        sqlx::query("UPDATE users SET status = ? WHERE id = ?")
            .bind(status.as_str())
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }

    async fn mark_email_verified(&self, id: Uuid) -> Result<()> {
        sqlx::query("UPDATE users SET email_verified = 1 WHERE id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }

    async fn update_language(&self, id: Uuid, language: Option<&str>) -> Result<()> {
        sqlx::query("UPDATE users SET language = ? WHERE id = ?")
            .bind(language)
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }

    async fn update_name(&self, id: Uuid, name: Option<&str>) -> Result<()> {
        sqlx::query("UPDATE users SET name = ? WHERE id = ?")
            .bind(name)
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }

    async fn update_profile(
        &self,
        id: Uuid,
        email: &str,
        preferred_username: Option<&str>,
        name: Option<&str>,
    ) -> Result<()> {
        // メール・表示名とユーザー名を**同じトランザクションで**更新する。ユーザー名が他人と
        // 衝突すると識別子の側が `Conflict` になるが（AP15b）、そこで `users` の変更だけが
        // 残ると「エラーを返したのに変更は起きている」状態を外へ見せてしまう。
        let mut tx = self.pool.begin().await.map_err(repo_err)?;
        sqlx::query("UPDATE users SET email = ?, name = ? WHERE id = ?")
            .bind(email)
            .bind(name)
            .bind(id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| match &e {
                // 事前チェックとの競合（同時更新）は DB の UNIQUE 制約が最終的に保証する。
                sqlx::Error::Database(db) if db.is_unique_violation() => {
                    DomainError::Conflict("email already exists".to_string())
                }
                _ => DomainError::Repository(e.to_string()),
            })?;
        // ユーザー名の置き場所は登録簿だけである（AP15b）。
        sync_primary_login_identifier(&mut tx, id, preferred_username).await?;
        tx.commit().await.map_err(repo_err)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 所属元の解決は登録簿を要求テナントで引く（`user_login_identifiers_lookup_idx` と同じキー）。
    #[test]
    fn home_scope_filters_the_registry_by_the_requested_tenant() {
        let sql = login_identifier_sql(IdentifierScope::Home, 2);
        assert!(
            sql.contains("WHERE i.tenant_id = ? AND i.is_active = 1"),
            "{sql}"
        );
        assert!(!sql.contains("tenant_memberships"), "{sql}");
        // 所属元経路は要求テナント＝所属元テナントで、middleware が DISABLED を 404 で止めている。
        // ここで tenants を JOIN すると、一意性チェック等の非ログイン経路にも条件が漏れる。
        assert!(!sql.contains("JOIN tenants"), "{sql}");
        // 候補 1 件につき (?, ?) 1 組。
        assert!(sql.contains("IN ((?, ?), (?, ?)) LIMIT 2"), "{sql}");
    }

    /// ゲストの解決は、要求テナントの ACTIVE な GUEST を、その利用者の所属元の登録簿で引く。
    /// `i.tenant_id = u.tenant_id` が落ちると他テナントの識別子でも解決されてしまうため、
    /// 条件の有無をここで固定する。
    #[test]
    fn active_guest_scope_joins_membership_and_stays_in_the_home_registry() {
        let sql = login_identifier_sql(IdentifierScope::ActiveGuest, 1);
        assert!(
            sql.contains("JOIN tenant_memberships m ON m.user_id = u.id"),
            "{sql}"
        );
        // 所属元テナントが DISABLED なら解決しない（ADR-0009 §8）。この JOIN が落ちると
        // 「所属元は止めたのに参加先からは入れる」利用者ができる。
        assert!(
            sql.contains("JOIN tenants home ON home.id = u.tenant_id AND home.status = 'ACTIVE'"),
            "{sql}"
        );
        assert!(
            sql.contains("WHERE m.tenant_id = ? AND m.membership_type = ? AND m.status = ?"),
            "{sql}"
        );
        assert!(sql.contains("AND i.tenant_id = u.tenant_id"), "{sql}");
        assert!(sql.contains("AND i.is_active = 1"), "{sql}");
        assert!(sql.contains("IN ((?, ?)) LIMIT 2"), "{sql}");
    }

    /// bind の個数が SQL のプレースホルダと一致する（ずれると照合キーがテナント ID として
    /// 使われ、静かに誰も解決しなくなる）。
    #[test]
    fn scope_binds_match_the_placeholders_in_the_scope_fragment() {
        let tenant: TenantId = uuid::Uuid::now_v7().into();
        for (scope, expected) in [
            (IdentifierScope::Home, 1),
            (IdentifierScope::ActiveGuest, 3),
        ] {
            assert_eq!(scope.binds(tenant).len(), expected, "{scope:?}");
            assert_eq!(scope.sql().matches('?').count(), expected, "{scope:?}");
        }
        assert_eq!(
            IdentifierScope::ActiveGuest.binds(tenant),
            vec![
                tenant.to_string(),
                "GUEST".to_string(),
                "ACTIVE".to_string()
            ]
        );
    }
}
