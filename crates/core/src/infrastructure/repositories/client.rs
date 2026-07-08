//! `ClientRepository` の sqlx 実装。配列カラム（redirect_uris 等）は JSON として入出力する。

use crate::domain::client::Client;
use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::ClientRepository;
use crate::domain::values::{ClientStatus, ClientType, TokenEndpointAuthMethod};
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::mysql::MySqlRow;
use sqlx::Row;
use uuid::Uuid;

pub struct SqlxClientRepository {
    pool: Db,
}

impl SqlxClientRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

const SELECT_COLUMNS: &str = "id, client_id, client_secret_hash, client_type, client_status, \
     app_name, redirect_uris, post_logout_redirect_uris, frontchannel_logout_uri, \
     backchannel_logout_uri, grant_types, response_types, scopes, \
     token_endpoint_auth_method, require_pkce, created_at, updated_at";

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

fn to_utc(naive: NaiveDateTime) -> DateTime<Utc> {
    Utc.from_utc_datetime(&naive)
}

// MariaDB の JSON カラム（LONGTEXT 別名）は sqlx では BLOB として返るため、バイト列で受けて parse する。
fn parse_json_strings(raw: &[u8], column: &str) -> Result<Vec<String>> {
    serde_json::from_slice(raw)
        .map_err(|e| DomainError::Repository(format!("invalid JSON in `{column}`: {e}")))
}

fn map_row(row: &MySqlRow) -> Result<Client> {
    let id: String = row.try_get("id").map_err(repo_err)?;
    let client_type: String = row.try_get("client_type").map_err(repo_err)?;
    let client_status: String = row.try_get("client_status").map_err(repo_err)?;
    let auth_method: String = row
        .try_get("token_endpoint_auth_method")
        .map_err(repo_err)?;
    let redirect_uris: Vec<u8> = row.try_get("redirect_uris").map_err(repo_err)?;
    let post_logout_redirect_uris: Option<Vec<u8>> =
        row.try_get("post_logout_redirect_uris").map_err(repo_err)?;
    let grant_types: Vec<u8> = row.try_get("grant_types").map_err(repo_err)?;
    let response_types: Vec<u8> = row.try_get("response_types").map_err(repo_err)?;
    let scopes: Vec<u8> = row.try_get("scopes").map_err(repo_err)?;
    Ok(Client {
        id: Uuid::parse_str(&id)
            .map_err(|e| DomainError::Repository(format!("invalid UUID `{id}`: {e}")))?,
        client_id: row.try_get("client_id").map_err(repo_err)?,
        client_secret_hash: row.try_get("client_secret_hash").map_err(repo_err)?,
        client_type: ClientType::parse(&client_type)?,
        client_status: ClientStatus::parse(&client_status)?,
        app_name: row.try_get("app_name").map_err(repo_err)?,
        redirect_uris: parse_json_strings(&redirect_uris, "redirect_uris")?,
        post_logout_redirect_uris: match post_logout_redirect_uris {
            Some(raw) => parse_json_strings(&raw, "post_logout_redirect_uris")?,
            None => vec![],
        },
        frontchannel_logout_uri: row.try_get("frontchannel_logout_uri").map_err(repo_err)?,
        backchannel_logout_uri: row.try_get("backchannel_logout_uri").map_err(repo_err)?,
        grant_types: parse_json_strings(&grant_types, "grant_types")?,
        response_types: parse_json_strings(&response_types, "response_types")?,
        scopes: parse_json_strings(&scopes, "scopes")?,
        token_endpoint_auth_method: TokenEndpointAuthMethod::parse(&auth_method)?,
        require_pkce: row.try_get("require_pkce").map_err(repo_err)?,
        created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
        updated_at: to_utc(row.try_get("updated_at").map_err(repo_err)?),
    })
}

// JSON カラムへ格納する文字列配列をシリアライズする。
fn to_json(values: &[String], column: &str) -> Result<String> {
    serde_json::to_string(values)
        .map_err(|e| DomainError::Repository(format!("failed to serialize `{column}`: {e}")))
}

#[async_trait]
impl ClientRepository for SqlxClientRepository {
    async fn find_by_client_id(&self, client_id: &str) -> Result<Option<Client>> {
        let sql = format!("SELECT {SELECT_COLUMNS} FROM clients WHERE client_id = ?");
        let row = sqlx::query(&sql)
            .bind(client_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn create(&self, client: &Client) -> Result<()> {
        sqlx::query(
            "INSERT INTO clients \
             (id, client_id, client_secret_hash, client_type, client_status, app_name, \
              redirect_uris, post_logout_redirect_uris, frontchannel_logout_uri, \
              backchannel_logout_uri, grant_types, response_types, scopes, \
              token_endpoint_auth_method, require_pkce) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(client.id.to_string())
        .bind(&client.client_id)
        .bind(&client.client_secret_hash)
        .bind(client.client_type.as_str())
        .bind(client.client_status.as_str())
        .bind(&client.app_name)
        .bind(to_json(&client.redirect_uris, "redirect_uris")?)
        .bind(if client.post_logout_redirect_uris.is_empty() {
            None
        } else {
            Some(to_json(&client.post_logout_redirect_uris, "post_logout_redirect_uris")?)
        })
        .bind(&client.frontchannel_logout_uri)
        .bind(&client.backchannel_logout_uri)
        .bind(to_json(&client.grant_types, "grant_types")?)
        .bind(to_json(&client.response_types, "response_types")?)
        .bind(to_json(&client.scopes, "scopes")?)
        .bind(client.token_endpoint_auth_method.as_str())
        .bind(client.require_pkce)
        .execute(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                DomainError::Conflict("client_id already exists".to_string())
            }
            _ => DomainError::Repository(e.to_string()),
        })?;
        Ok(())
    }

    async fn list(&self) -> Result<Vec<Client>> {
        let sql = format!("SELECT {SELECT_COLUMNS} FROM clients ORDER BY created_at DESC");
        let rows = sqlx::query(&sql)
            .fetch_all(&self.pool)
            .await
            .map_err(repo_err)?;
        rows.iter().map(map_row).collect()
    }

    async fn update(&self, client: &Client) -> Result<()> {
        // 対象の存在は呼び出し側（load-then-update）が保証する。updated_at は
        // ON UPDATE CURRENT_TIMESTAMP(6) に委ねる。値無変更時に MySQL が返す rows_affected=0 は
        // 「不存在」と区別できないため、rows_affected では存在判定しない。
        sqlx::query(
            "UPDATE clients SET \
             client_secret_hash = ?, client_type = ?, client_status = ?, app_name = ?, \
             redirect_uris = ?, post_logout_redirect_uris = ?, frontchannel_logout_uri = ?, \
             backchannel_logout_uri = ?, grant_types = ?, response_types = ?, scopes = ?, \
             token_endpoint_auth_method = ?, require_pkce = ? \
             WHERE id = ?",
        )
        .bind(&client.client_secret_hash)
        .bind(client.client_type.as_str())
        .bind(client.client_status.as_str())
        .bind(&client.app_name)
        .bind(to_json(&client.redirect_uris, "redirect_uris")?)
        .bind(if client.post_logout_redirect_uris.is_empty() {
            None
        } else {
            Some(to_json(&client.post_logout_redirect_uris, "post_logout_redirect_uris")?)
        })
        .bind(&client.frontchannel_logout_uri)
        .bind(&client.backchannel_logout_uri)
        .bind(to_json(&client.grant_types, "grant_types")?)
        .bind(to_json(&client.response_types, "response_types")?)
        .bind(to_json(&client.scopes, "scopes")?)
        .bind(client.token_endpoint_auth_method.as_str())
        .bind(client.require_pkce)
        .bind(client.id.to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }
}
