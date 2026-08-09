//! RP-initiated Logout のユースケース（F4、設計仕様 §9 拡張）。
//!
//! OIDC RP-initiated Logout 1.0 spec に基づき、SSO セッションを終了し
//! `sso_session.terminated` 監査イベントを記録する。
//! back-channel / front-channel の通知に必要な情報を返すが、
//! 実際の HTTP 送信は Presentation 層（ハンドラ）が行う。

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::issuer::tenant_issuer;
use crate::domain::jwt;
use crate::domain::repositories::{
    AuthorizationCodeRepository, ClientRepository, SigningKeyRepository, SsoSessionRepository,
    UserRepository,
};
use crate::domain::tenant_context::TenantContext;
use jsonwebtoken::Validation;
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

/// back-channel logout 通知先の 1 クライアント。
#[derive(Debug, Clone)]
pub struct BackchannelTarget {
    pub client_id: String,
    pub backchannel_logout_uri: String,
}

/// `id_token_hint` から取り出した検証済みの手掛かり（G12。OIDC RP-Initiated Logout 1.0 §2）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIdTokenHint {
    /// ログアウト対象として RP が指している利用者の `sub`。
    pub subject: String,
    /// ID Token を受け取った RP（`aud`）。`post_logout_redirect_uri` の照合先になる。
    pub client_id: String,
}

/// `id_token_hint` の検証結果。
#[derive(Debug, Clone, PartialEq, Eq)]
enum IdTokenHintOutcome {
    /// 指定なし。
    Absent,
    /// 検証を通った。
    Verified(VerifiedIdTokenHint),
    /// 指定されたが検証を通らなかった（署名不正・issuer 違い・未知の kid・JWT でない 等）。
    Invalid,
}

/// RP-initiated logout の帰結。
pub enum LogoutOutcome {
    /// ログアウト処理を実施した（対象セッションが無かった場合も含む。冪等）。
    Completed(LogoutResult),
    /// `id_token_hint` が指す利用者と、いま手元のセッションの利用者が一致しないため**何もしなかった**。
    ///
    /// Presentation は**ブラウザの SSO Cookie も消してはならない**。消すと「DB にはセッションが
    /// 生きているのに、ブラウザからはそこへ戻れない」宙ぶらりんの状態になり、守ろうとした
    /// 別利用者のログイン状態を結局は壊してしまう。
    SubjectMismatch,
}

/// RP-initiated logout の結果。Presentation がこれを元に通知とリダイレクトを実施する。
pub struct LogoutResult {
    /// ログアウトしたユーザーの `sub`（back-channel logout token に使用）。
    pub user_sub: Option<String>,
    /// ログアウトしたユーザーの内部 ID（監査用）。
    pub user_id: Option<Uuid>,
    /// 終了した SSO セッションの `sid`（G5）。logout_token へ載せ、RP がセッション単位で失効できる
    /// ようにする。セッションを特定できなかった場合は `None`（RP は `sub` 単位の失効へ落ちる）。
    pub sid: Option<String>,
    /// back-channel logout 通知先（`backchannel_logout_uri` を持つ全クライアント）。
    pub backchannel_targets: Vec<BackchannelTarget>,
    /// front-channel logout URI 群（`frontchannel_logout_uri` を持つ全クライアント）。
    pub frontchannel_uris: Vec<String>,
    /// 検証済みの post-logout redirect URI（未指定または検証失敗の場合は `None`）。
    pub post_logout_redirect_uri: Option<String>,
}

pub struct LogoutService {
    sso_sessions: Arc<dyn SsoSessionRepository>,
    users: Arc<dyn UserRepository>,
    clients: Arc<dyn ClientRepository>,
    codes: Arc<dyn AuthorizationCodeRepository>,
    signing_keys: Arc<dyn SigningKeyRepository>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    /// 基底 issuer。front-channel logout の `iss` はテナント毎に合成する（ADR-0009 §6）。
    base_issuer: String,
}

impl LogoutService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sso_sessions: Arc<dyn SsoSessionRepository>,
        users: Arc<dyn UserRepository>,
        clients: Arc<dyn ClientRepository>,
        codes: Arc<dyn AuthorizationCodeRepository>,
        signing_keys: Arc<dyn SigningKeyRepository>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        base_issuer: String,
    ) -> Self {
        Self {
            sso_sessions,
            users,
            clients,
            codes,
            signing_keys,
            audit,
            clock,
            base_issuer,
        }
    }

    /// RP-initiated logout を処理する。
    ///
    /// - `sso_session_id`: SSO Cookie の値（平文）。`None` なら既にログアウト済み扱い。
    /// - `client_id_hint`: `client_id` パラメータ（post_logout_redirect_uri の検証に使う）。
    /// - `id_token_hint`: RP が受け取った ID Token（G12）。署名・issuer を検証し、`aud` を
    ///   `post_logout_redirect_uri` の照合先に、`sub` を「誰のログアウトか」の確認に使う。
    /// - `post_logout_redirect_uri`: RP が指定したリダイレクト先。登録済みのもののみ許可。
    #[allow(clippy::too_many_arguments)]
    pub async fn logout(
        &self,
        tenant: TenantContext,
        sso_session_id: Option<&str>,
        client_id_hint: Option<&str>,
        id_token_hint: Option<&str>,
        post_logout_redirect_uri: Option<&str>,
        ctx: &RequestContext,
    ) -> LogoutOutcome {
        let now = self.clock.now();

        // 1. `id_token_hint` の検証（G12）。セッションに触れる前に済ませる。
        let hint = self.verify_id_token_hint(tenant, id_token_hint).await;

        // 2. SSO セッションの特定と終了。
        let (user_id, user_sub, sid) =
            if let Some(session_id) = sso_session_id.filter(|s| !s.is_empty()) {
                let hash = crypto::sha256_hex(session_id);
                let session = match self.sso_sessions.find_by_hash(&hash).await {
                    Ok(Some(s)) => s,
                    _ => {
                        // セッション不明または DB エラー → ログアウト済み扱いで続行。
                        return LogoutOutcome::Completed(LogoutResult {
                            user_sub: None,
                            user_id: None,
                            sid: None,
                            backchannel_targets: vec![],
                            frontchannel_uris: vec![],
                            post_logout_redirect_uri: None,
                        });
                    }
                };
                let uid = session.user_id;
                // `sid` は行を消す前に導出する（削除後は `session_hash` しか手元に残らないため、
                // 導出関数は行ではなくハッシュを受ける形にしてある）。
                let sid = session.sid();

                // ユーザーの sub を取得（logout token・`id_token_hint` との突き合わせに使う）。
                let sub = match self.users.find_by_id(uid).await {
                    Ok(Some(u)) => Some(u.sub.to_string()),
                    _ => None,
                };

                // `id_token_hint` の `sub` が今ログインしている利用者と**一致しない限り終了しない**
                // （G12）。hint は「この利用者をログアウトさせたい」という RP の指定であり、別人の
                // セッションを落とすのは指定に反する。同じブラウザを共有していて別の人がログイン
                // し直した後に、前の利用者ぶんのログアウト要求が届く経路が現実に存在する。
                // 利用者行を読めず `sub` が引けなかった場合も一致を確認できないため終了しない
                // （hint を送っていない要求は従来どおり無条件に終了する）。
                if let IdTokenHintOutcome::Verified(verified) = &hint {
                    if sub.as_deref() != Some(verified.subject.as_str()) {
                        self.audit
                            .record(
                                AuditEventType::SsoSessionTerminated,
                                AuditResult::Failure,
                                Some(tenant.tenant_id()),
                                Some(uid),
                                Some(&verified.client_id),
                                Some("id_token_hint_subject_mismatch"),
                                ctx,
                            )
                            .await;
                        // Cookie も消させない（消すと DB にだけ生きたセッションが残る）。
                        return LogoutOutcome::SubjectMismatch;
                    }
                }

                // SSO セッション削除。
                if let Err(e) = self.sso_sessions.delete(&hash).await {
                    tracing::warn!(error = %e, "failed to delete sso session on logout");
                }

                // 未消費の authorization code を失効。
                if let Err(e) = self.codes.revoke_all_active_for_user(uid, now).await {
                    tracing::warn!(error = %e, "failed to revoke active auth codes on logout");
                }

                self.audit
                    .record(
                        AuditEventType::SsoSessionTerminated,
                        AuditResult::Success,
                        Some(tenant.tenant_id()),
                        Some(uid),
                        None,
                        Some("rp_initiated_logout"),
                        ctx,
                    )
                    .await;

                (Some(uid), sub, Some(sid))
            } else {
                (None, None, None)
            };

        // 2. テナントの全クライアントを取得して logout endpoint を持つものを収集
        //    （logout 通知・redirect 検証はフローのテナント内に限る）。
        let clients = match self.clients.list(tenant.tenant_id()).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "failed to list clients for logout notification");
                vec![]
            }
        };

        let backchannel_targets: Vec<BackchannelTarget> = clients
            .iter()
            .filter_map(|c| {
                c.backchannel_logout_uri
                    .as_ref()
                    .map(|uri| BackchannelTarget {
                        client_id: c.client_id.clone(),
                        backchannel_logout_uri: uri.clone(),
                    })
            })
            .collect();

        let issuer = tenant_issuer(&self.base_issuer, tenant.tenant_id());
        let frontchannel_uris: Vec<String> = clients
            .iter()
            .filter_map(|c| {
                c.frontchannel_logout_uri.as_ref().map(|uri| {
                    // OpenID Connect Front-Channel Logout spec: iss を query param に付与。
                    let sep = if uri.contains('?') { '&' } else { '?' };
                    let encoded_iss = percent_encoding::utf8_percent_encode(
                        &issuer,
                        percent_encoding::NON_ALPHANUMERIC,
                    )
                    .to_string();
                    format!("{uri}{sep}iss={encoded_iss}")
                })
            })
            .collect();

        // 3. post_logout_redirect_uri の検証。
        //
        // 照合先の RP は `client_id` パラメータと `id_token_hint` の `aud` から決める（G12）。
        // hint は署名検証を通っている（＝本 IdP が実際にその RP へ発行した ID Token である）ため、
        // 自己申告の `client_id` より強い根拠になる。両方あって食い違う場合はどちらも信用しない。
        let post_logout_redirect_uri = post_logout_redirect_uri
            .filter(|uri| !uri.is_empty())
            .and_then(|uri| {
                let audience = match &hint {
                    // 検証を通らない hint は「誰の・どの RP のログアウトか」を何も示さない。
                    // 登録済み URI へのリダイレクトは RP への応答なので、確かめられない相手へは返さない。
                    IdTokenHintOutcome::Invalid => return None,
                    IdTokenHintOutcome::Verified(v) => Some(v.client_id.as_str()),
                    IdTokenHintOutcome::Absent => None,
                };
                let target = match (client_id_hint.filter(|c| !c.is_empty()), audience) {
                    (Some(param), Some(aud)) if param != aud => return None,
                    (Some(param), _) => Some(param),
                    (None, Some(aud)) => Some(aud),
                    (None, None) => None,
                };
                let allowed = match target {
                    Some(cid) => clients
                        .iter()
                        .find(|c| c.client_id == cid)
                        .is_some_and(|c| c.allows_post_logout_redirect_uri(uri)),
                    // RP を特定できない場合のみ、テナント内のいずれかのクライアントに登録されて
                    // いれば許可する（従来の挙動。`client_id` も `id_token_hint` も送らない RP が
                    // あるため残す）。
                    None => clients
                        .iter()
                        .any(|c| c.allows_post_logout_redirect_uri(uri)),
                };
                allowed.then(|| uri.to_string())
            });

        let _ = user_id; // suppress unused warning
        LogoutOutcome::Completed(LogoutResult {
            user_sub,
            user_id,
            sid,
            backchannel_targets,
            frontchannel_uris,
            post_logout_redirect_uri,
        })
    }

    /// `id_token_hint` を検証する（G12。OIDC RP-Initiated Logout 1.0 §2）。
    ///
    /// **`exp` は見ない。** hint は「以前このセッションで発行された ID Token」を指すもので、
    /// 期限切れが普通である（同 §2 が明示的に許している）。代わりに次を確かめる:
    ///
    /// - `typ` が `JWT`（ID Token）であること —— Access Token（`at+jwt`）を hint として通さない。
    /// - `kid` が本 IdP の署名鍵（退役済みを含む）であり、署名が正しいこと。
    /// - `iss` が**要求テナントの**合成 issuer と一致すること（他テナントの ID Token を
    ///   持ち込んで別テナントの利用者をログアウトさせられないようにする。ADR-0009 §6）。
    ///
    /// 検証に落ちたものは `Invalid` として扱い、`None` には落とさない。呼び出し側で
    /// 「指定が無い」と「指定が信用できない」を区別する必要がある。
    async fn verify_id_token_hint(
        &self,
        tenant: TenantContext,
        id_token_hint: Option<&str>,
    ) -> IdTokenHintOutcome {
        let Some(hint) = id_token_hint.filter(|h| !h.is_empty()) else {
            return IdTokenHintOutcome::Absent;
        };

        let Ok(header) = jsonwebtoken::decode_header(hint) else {
            return IdTokenHintOutcome::Invalid;
        };
        // `typ` は省略可（RFC 7519）だが、本 IdP が出す ID Token は必ず `JWT` を載せる。
        if header.typ.as_deref().is_some_and(|t| t != "JWT") {
            return IdTokenHintOutcome::Invalid;
        }
        let Some(kid) = header.kid else {
            return IdTokenHintOutcome::Invalid;
        };
        let key = match self.signing_keys.find_by_kid(&kid).await {
            Ok(Some(k)) => k,
            Ok(None) => return IdTokenHintOutcome::Invalid,
            Err(e) => {
                tracing::warn!(error = %e, "failed to load signing key for id_token_hint");
                return IdTokenHintOutcome::Invalid;
            }
        };
        let Ok((decoding_key, algorithm)) = jwt::decoding_key_for(&key.algorithm, &key.public_key)
        else {
            return IdTokenHintOutcome::Invalid;
        };

        let mut validation = Validation::new(algorithm);
        // 期限切れの ID Token を hint に使うのは正常な運用（上記）。
        validation.validate_exp = false;
        // `aud` は RP の client_id で、ここでは検証対象ではなく**取り出す値**。
        validation.validate_aud = false;
        validation.required_spec_claims.clear();

        let Ok(decoded) =
            jsonwebtoken::decode::<IdTokenHintClaims>(hint, &decoding_key, &validation)
        else {
            return IdTokenHintOutcome::Invalid;
        };
        let claims = decoded.claims;
        if claims.iss != tenant_issuer(&self.base_issuer, tenant.tenant_id()) {
            return IdTokenHintOutcome::Invalid;
        }
        if claims.sub.is_empty() || claims.aud.is_empty() {
            return IdTokenHintOutcome::Invalid;
        }

        IdTokenHintOutcome::Verified(VerifiedIdTokenHint {
            subject: claims.sub,
            client_id: claims.aud,
        })
    }
}

/// `id_token_hint` から読み取るクレーム。
///
/// 発行時の [`crate::application::token::IdTokenClaims`] とは別に定義する。hint は過去に発行した
/// トークンであり、当時のクレーム構成のまま届く。必須項目を増やすと、古いトークンが「壊れている」
/// ことになってログアウトが通らなくなる。
#[derive(Debug, Deserialize)]
struct IdTokenHintClaims {
    iss: String,
    sub: String,
    aud: String,
}
