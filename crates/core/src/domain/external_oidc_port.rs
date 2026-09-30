//! 外部 OpenID Provider との通信ポート（DIP 境界。AP10）。
//!
//! assay が**クライアントとして**外部 IdP を呼ぶ経路。実装（reqwest + jsonwebtoken）は
//! `infrastructure::external_oidc` にある。Application 層はこのトレイト越しにしか外部へ出ない
//! ので、テストではネットワーク無しで（固定の ID Token を返す実装で）検証できる。
//!
//! ID Token の検証（署名・`iss`・`aud`・`exp`・`nonce`）を Application 層ではなく実装側に置くのは、
//! 検証と JWKS の取得が不可分だから（鍵は `kid` で選ぶため、取得と照合を分けられない）。
//! **検証に通ったクレームだけ**がこのポートから出てくる、という契約にする。
#![allow(dead_code)]

use crate::domain::error::Result;
use crate::domain::external_idp::ExternalClaims;
use crate::domain::oidc_discovery::{DiscoveryUrl, OidcDiscoveryDocument};
use async_trait::async_trait;

/// 認可コードの交換に必要な情報（`ExternalIdentityProvider` から Application 層が組み立てる）。
pub struct ExternalTokenRequest<'a> {
    pub token_endpoint: &'a str,
    pub jwks_uri: &'a str,
    /// 外部 IdP の issuer。ID Token の `iss` と完全一致すること。
    pub expected_issuer: &'a str,
    pub client_id: &'a str,
    /// 復号済みのクライアントシークレット（public クライアントなら `None`）。
    pub client_secret: Option<&'a str>,
    pub redirect_uri: &'a str,
    pub code: &'a str,
    /// PKCE の `code_verifier`（復号済み）。
    pub code_verifier: &'a str,
    /// 保存しておいた `nonce`。ID Token の `nonce` と一致すること。
    pub expected_nonce: &'a str,
}

#[async_trait]
pub trait ExternalOidcClient: Send + Sync {
    /// 認可コードを ID Token へ交換し、**検証済みの**クレームを返す。
    ///
    /// 検証に失敗した場合（署名不正・`iss`/`aud`/`exp`/`nonce` 不一致）はエラーを返し、
    /// クレームは返さない。呼び出し側が検証漏れを起こしようがない形にするための契約。
    async fn exchange_code(&self, request: ExternalTokenRequest<'_>) -> Result<ExternalClaims>;
}

/// 外部 IdP の discovery ドキュメントを取りに行くポート（task #77）。
///
/// 宛先は [`DiscoveryUrl`] でしか渡せない（issuer を ADR-0023 決定 5 の検査に通したときにしか
/// 作れない型）。実装は `exchange_code` と同じ作法——**リダイレクトを追わない**・タイムアウトを持つ——
/// に加えて、応答の大きさに上限を置く（管理者の入れた先が巨大な応答を返しても api のメモリを
/// 食わせない）。返すのは取得したそのままの値で、`issuer` の照合とエンドポイントの検査は
/// [`OidcDiscoveryDocument::verify_for`] が行う。
#[async_trait]
pub trait OidcDiscoveryClient: Send + Sync {
    async fn fetch_discovery(&self, url: &DiscoveryUrl) -> Result<OidcDiscoveryDocument>;
}
