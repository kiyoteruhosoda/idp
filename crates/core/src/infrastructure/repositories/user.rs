//! `UserRepository` の sqlx 実装。UUID は CHAR(36) 正準文字列として入出力する。

use crate::domain::authentication_policy::LockoutPolicy;
use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::UserRepository;
use crate::domain::tenant::TenantId;
use crate::domain::user::{LoginFailureRecord, User};
use crate::domain::values::UserStatus;
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
}

const SELECT_COLUMNS: &str = "id, tenant_id, sub, email, email_verified, preferred_username, \
     name, language, password_hash, must_change_password, password_changed_at, status, \
     failed_login_count, locked_until, created_at, updated_at";

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
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

/// 主たるログイン識別子（`users.preferred_username`）を登録簿へ同期する（AP15）。
///
/// 移行中は**両方に在る**。登録簿だけに書くとローリングデプロイ中の古いプロセス（`users` しか
/// 読まない）がログインさせられず、`users` だけに書くと新しいプロセスの一覧・クレームから
/// 主識別子が消える。撤去（`users.preferred_username` を落とす）は次のリリース。
///
/// `preferred_username` が `None`・空のときは登録簿の主識別子行を削除する（解除）。
///
/// # 同じ値を他人が持っているとき
///
/// その値が**他人**の識別子として既に登録簿に在る場合は、登録簿を触らずに `users` 側だけを
/// 正とする。`users.preferred_username` への一意制約は、その値が他人の**追加**識別子として
/// 登録されている場合までは弾かないので、この状況は実際に起こりうる。
///
/// ここで `ON DUPLICATE KEY UPDATE` を使うと、一意キー（tenant × 種別 × 正規化値）の衝突で
/// **他人の行が書き換わる**（`user_id` は更新されないので、他人の識別子の表示値・有効状態だけが
/// 変わる）。それは黙って他人のログインを壊す。エラーにして操作ごと失敗させるのも過剰で、
/// 移行前は通っていたプロフィール編集が通らなくなる。そこで migration 0036 と**同じ判断**を採る
/// ——登録簿は諦め、その利用者は `users.preferred_username` へのフォールバックで解決され続ける
/// （フォールバックは撤去まで残る）。
async fn sync_primary_login_identifier<'e>(
    executor: impl sqlx::Executor<'e, Database = sqlx::MySql> + Copy,
    user_id: Uuid,
    preferred_username: Option<&str>,
) -> Result<()> {
    use crate::domain::login_identifier::LoginIdentifierType;

    let Some(value) = preferred_username.map(str::trim).filter(|v| !v.is_empty()) else {
        sqlx::query("DELETE FROM user_login_identifiers WHERE user_id = ? AND is_primary = 1")
            .bind(user_id.to_string())
            .execute(executor)
            .await
            .map_err(repo_err)?;
        return Ok(());
    };
    let normalized = LoginIdentifierType::Username.normalize(value);

    // 他人が同じ値を握っているか（テナントは利用者の行から引く。呼び出し側に渡させると
    // `users` と食い違う余地が生まれる）。
    let taken_by_someone_else: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM user_login_identifiers i \
         JOIN users u ON u.id = ? \
         WHERE i.tenant_id = u.tenant_id AND i.identifier_type = 'username' \
           AND i.normalized_value = ? AND i.user_id <> u.id \
         LIMIT 1",
    )
    .bind(user_id.to_string())
    .bind(&normalized)
    .fetch_optional(executor)
    .await
    .map_err(repo_err)?;
    if taken_by_someone_else.is_some() {
        // 値そのものは PII なので出さない（`docs/CLAUDE.md`「ログ」）。
        tracing::warn!(
            "primary login identifier not mirrored into the registry: value already taken by another user"
        );
        return Ok(());
    }

    // 主識別子は 1 利用者 1 行（`primary_of_user` の UNIQUE が保証する）。既存行があれば
    // 値を入れ替え、無ければ作る。「更新して 0 行なら INSERT」にしないのは、MariaDB の
    // 影響行数が**変わった行**の数で、同じ値で更新すると 0 になるためである（そこで INSERT に
    // 回ると一意制約で落ちる）。
    let existing: Option<String> = sqlx::query_scalar(
        "SELECT id FROM user_login_identifiers WHERE user_id = ? AND is_primary = 1",
    )
    .bind(user_id.to_string())
    .fetch_optional(executor)
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
            .execute(executor)
            .await
            .map_err(repo_err)?;
        }
        None => {
            sqlx::query(
                "INSERT INTO user_login_identifiers \
                 (id, tenant_id, user_id, identifier_type, display_value, normalized_value, \
                  is_active, is_primary) \
                 SELECT ?, u.tenant_id, u.id, 'username', ?, ?, 1, 1 FROM users u WHERE u.id = ?",
            )
            .bind(uuid::Uuid::now_v7().to_string())
            .bind(value)
            .bind(&normalized)
            .bind(user_id.to_string())
            .execute(executor)
            .await
            .map_err(repo_err)?;
        }
    }
    Ok(())
}

/// users への INSERT（プール直接実行と provisioning トランザクションで共用する）。
pub(crate) async fn insert_user<'e>(
    executor: impl sqlx::Executor<'e, Database = sqlx::MySql> + Copy,
    user: &User,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO users \
         (id, tenant_id, sub, email, email_verified, preferred_username, name, language, \
          password_hash, must_change_password, password_changed_at, status, failed_login_count, \
          locked_until) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(user.id.to_string())
    .bind(user.tenant_id.to_string())
    .bind(user.sub.to_string())
    .bind(&user.email)
    .bind(user.email_verified)
    .bind(&user.preferred_username)
    .bind(&user.name)
    .bind(&user.language)
    .bind(&user.password_hash)
    .bind(user.must_change_password)
    .bind(user.password_changed_at.map(|d| d.naive_utc()))
    .bind(user.status.as_str())
    .bind(user.failed_login_count)
    .bind(user.locked_until.map(|d| d.naive_utc()))
    .execute(executor)
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            DomainError::Conflict("email or preferred_username already exists".to_string())
        }
        _ => DomainError::Repository(e.to_string()),
    })?;
    sync_primary_login_identifier(executor, user.id, user.preferred_username.as_deref()).await?;
    Ok(())
}

#[async_trait]
impl UserRepository for SqlxUserRepository {
    async fn create(&self, user: &User) -> Result<()> {
        insert_user(&self.pool, user).await
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>> {
        let sql = format!("SELECT {SELECT_COLUMNS} FROM users WHERE id = ?");
        let row = sqlx::query(&sql)
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn find_by_sub(&self, sub: Uuid) -> Result<Option<User>> {
        let sql = format!("SELECT {SELECT_COLUMNS} FROM users WHERE sub = ?");
        let row = sqlx::query(&sql)
            .bind(sub.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn find_by_email(&self, tenant_id: TenantId, email: &str) -> Result<Option<User>> {
        let sql = format!("SELECT {SELECT_COLUMNS} FROM users WHERE tenant_id = ? AND email = ?");
        let row = sqlx::query(&sql)
            .bind(tenant_id.to_string())
            .bind(email)
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn find_by_username(&self, tenant_id: TenantId, username: &str) -> Result<Option<User>> {
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM users WHERE tenant_id = ? AND preferred_username = ?"
        );
        let row = sqlx::query(&sql)
            .bind(tenant_id.to_string())
            .bind(username)
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
    /// **複数の利用者に当たったら誰も返さない。** 一意制約は `(tenant_id, identifier_type,
    /// normalized_value)` に張ってあり、1 種別の中では 1 人に決まるが、種別をまたぐと
    /// 「ユーザー名としては A、社員番号としては B」という入力があり得る。`LIMIT 1` で
    /// どちらかを選ぶと、どちらが返るかが索引の都合で決まってしまう。曖昧な入力で
    /// 認証を通すより、通さない方を選ぶ（候補生成側でも起きにくくしてある。
    /// [`crate::domain::login_identifier::lookup_candidates`]）。
    ///
    /// 一致が無ければ `users.preferred_username` へ落とす。登録簿の導入は expand フェーズで、
    /// 主たる識別子はまだ `users` 側にあるため（migration 0029）。
    async fn find_by_login_identifier(
        &self,
        tenant_id: TenantId,
        input: &str,
    ) -> Result<Option<User>> {
        let candidates = crate::domain::login_identifier::lookup_candidates(input);
        if !candidates.is_empty() {
            let placeholders = vec!["(?, ?)"; candidates.len()].join(", ");
            let sql = format!(
                "SELECT DISTINCT u.id AS id, u.tenant_id AS tenant_id, u.sub AS sub, \
                 u.email AS email, u.email_verified AS email_verified, \
                 u.preferred_username AS preferred_username, u.name AS name, \
                 u.language AS language, u.password_hash AS password_hash, \
                 u.must_change_password AS must_change_password, \
                 u.password_changed_at AS password_changed_at, u.status AS status, \
                 u.failed_login_count AS failed_login_count, u.locked_until AS locked_until, \
                 u.created_at AS created_at, u.updated_at AS updated_at \
                 FROM user_login_identifiers i \
                 JOIN users u ON u.id = i.user_id \
                 WHERE i.tenant_id = ? AND i.is_active = 1 \
                   AND (i.identifier_type, i.normalized_value) IN ({placeholders}) \
                 LIMIT 2"
            );
            let mut query = sqlx::query(&sql).bind(tenant_id.to_string());
            for (kind, normalized) in &candidates {
                query = query.bind(kind.as_str()).bind(normalized.clone());
            }
            let rows = query.fetch_all(&self.pool).await.map_err(repo_err)?;
            match rows.len() {
                0 => {}
                1 => return map_row(&rows[0]).map(Some),
                _ => {
                    // 曖昧。監査には残らない経路なので、運用ログにだけ残す（値は PII のため出さない）。
                    tracing::warn!(
                        tenant_id = %tenant_id,
                        "login identifier resolved to multiple users; refusing to authenticate"
                    );
                    return Ok(None);
                }
            }
        }
        self.find_by_username(tenant_id, input.trim()).await
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
        sqlx::query("UPDATE users SET email = ?, preferred_username = ?, name = ? WHERE id = ?")
            .bind(email)
            .bind(preferred_username)
            .bind(name)
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| match &e {
                // 事前チェックとの競合（同時更新）は DB の UNIQUE 制約が最終的に保証する。
                sqlx::Error::Database(db) if db.is_unique_violation() => {
                    DomainError::Conflict("email or preferred_username already exists".to_string())
                }
                _ => DomainError::Repository(e.to_string()),
            })?;
        // 主識別子は移行中どちらにも在る。`users` だけ変えると、登録簿を見る経路（一覧・
        // `preferred_username` クレーム・ログイン解決）が**古い名前**を指したままになる。
        sync_primary_login_identifier(&self.pool, id, preferred_username).await?;
        Ok(())
    }
}
