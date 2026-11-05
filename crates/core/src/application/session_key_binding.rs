//! SSO セッションを端末の鍵へ結び付ける（Chrome の DBSC。task #887。ADR-0074）。
//!
//! # 流れ
//!
//! 1. **登録**: ログインの応答で web が Chrome に結び付けを求め、Chrome は TPM の中で鍵を作り、公開鍵を
//!    添えた署名を `/dbsc/register` へ送る。web はそれを [`SessionKeyBindingService::register`] へ渡す。
//! 2. **更新**: 短い Cookie（10 分）が切れると、Chrome は `/dbsc/refresh` で鍵の署名を送り直す
//!    （[`SessionKeyBindingService::refresh`]）。
//! 3. **入口の確かめ**: 合う短い Cookie の無い要求は、web が [`SessionKeyBindingService::binding_of`] で
//!    結び付いているかを聞き、結び付いていれば長い Cookie を外す（web 側）。
//!
//! # 長さ
//!
//! 登録と更新のたびに置き直す（[`lifetime_for`]）。結び付いていて、そのログイン状態の端末（ADR-0071 の
//! 端末の印）が登録済みなら `SSO_BOUND_TTL_SECS`、そうでなければ `SSO_ABSOLUTE_TTL_SECS`。
//!
//! # 別の鍵の署名
//!
//! 結び付いたログイン状態へ、登録した鍵と違う鍵の署名（登録のし直しを含む）が来たら、そのログイン状態を
//! 終わらせ（refresh token も。ADR-0044）、監査に残し、知らせる。Cookie が持ち出された印だからである。

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::effective_tenant_settings::EffectiveTenantSettings;
use crate::domain::error::DomainError;
use crate::domain::repositories::{
    RefreshTokenRepository, SessionKeyBindingRepository, SsoSessionRepository,
    UserDeviceRepository, UserRepository,
};
use crate::domain::security_alert::{SecurityAlert, SecurityAlertKind, SecurityAlertSink};
use crate::domain::session_key::{
    lifetime_for, verify_refresh, verify_registration, ProofError, SessionBinding,
    SessionKeyBinding,
};
use crate::domain::sso_session::{self, SsoSession};
use crate::domain::user::User;
use assay_contracts::session_key as contract;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::sync::Arc;

/// 登録・更新の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionKeyOutcome {
    /// 結び付いた・更新できた。`remaining_secs` はログイン状態が切れるまでの秒数（長い Cookie の Max-Age）。
    Bound {
        session_identifier: String,
        remaining_secs: u64,
    },
    /// 署名・challenge・形が合わない（結び付けは変えない）。
    Rejected,
    /// 登録した鍵と違う鍵で署名された。ログイン状態は終わらせた。
    KeyMismatch,
    /// ログイン状態が無い・切れている・識別子が違う。
    SessionGone,
}

pub struct SessionKeyBindingService {
    bindings: Arc<dyn SessionKeyBindingRepository>,
    sso_sessions: Arc<dyn SsoSessionRepository>,
    devices: Arc<dyn UserDeviceRepository>,
    users: Arc<dyn UserRepository>,
    refresh_tokens: Arc<dyn RefreshTokenRepository>,
    settings: Arc<dyn EffectiveTenantSettings>,
    alerts: Arc<dyn SecurityAlertSink>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    /// challenge の HMAC の鍵（`CSRF_SECRET`。用途は contracts の側で分ける）。
    secret: [u8; 32],
}

#[derive(Deserialize)]
struct UnverifiedClaims {
    jti: Option<String>,
}

impl SessionKeyBindingService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bindings: Arc<dyn SessionKeyBindingRepository>,
        sso_sessions: Arc<dyn SsoSessionRepository>,
        devices: Arc<dyn UserDeviceRepository>,
        users: Arc<dyn UserRepository>,
        refresh_tokens: Arc<dyn RefreshTokenRepository>,
        settings: Arc<dyn EffectiveTenantSettings>,
        alerts: Arc<dyn SecurityAlertSink>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        secret: [u8; 32],
    ) -> Self {
        Self {
            bindings,
            sso_sessions,
            devices,
            users,
            refresh_tokens,
            settings,
            alerts,
            audit,
            clock,
            secret,
        }
    }

    /// 結び付いていれば識別子を返す（web の入口の確かめ）。無い・切れたセッションは `None`。
    pub async fn binding_of(&self, sso_session_id: &str) -> Result<Option<String>, DomainError> {
        let session_hash = crypto::sha256_hex(sso_session_id);
        Ok(self
            .bindings
            .find(&session_hash)
            .await?
            .map(|b| b.session_identifier))
    }

    /// 登録（Chrome が公開鍵を添えて送ってきた署名）。
    pub async fn register(
        &self,
        sso_session_id: &str,
        proof: &str,
        ctx: &RequestContext,
    ) -> Result<SessionKeyOutcome, DomainError> {
        let now = self.clock.now();
        let Some((session, user)) = self.live_session(sso_session_id, now).await? else {
            return Ok(SessionKeyOutcome::SessionGone);
        };
        let Some(challenge) = self.fresh_challenge(sso_session_id, proof, now) else {
            self.reject(&user, "stale_challenge", ctx).await;
            return Ok(SessionKeyOutcome::Rejected);
        };
        let key = match verify_registration(proof, &challenge) {
            Ok(key) => key,
            Err(e) => {
                self.reject(&user, e.as_str(), ctx).await;
                return Ok(SessionKeyOutcome::Rejected);
            }
        };
        if let Some(existing) = self.bindings.find(&session.session_hash).await? {
            if existing.key.thumbprint == key.thumbprint {
                // 同じ鍵での登録のし直し（Chrome が再起動した等）。結び付けはそのまま。
                return self.renew(&session, &user, &existing, now).await;
            }
            return self.end_for_mismatch(&session, &user, now, ctx).await;
        }
        let binding = SessionKeyBinding {
            session_identifier: crypto::random_hex(16),
            key,
            bound_at: now,
        };
        if !self.bindings.bind(&session.session_hash, &binding).await? {
            // 同時に別の登録が先に入った。どちらの鍵が正しいか分からないので、入った方を正とする。
            let Some(existing) = self.bindings.find(&session.session_hash).await? else {
                return Ok(SessionKeyOutcome::SessionGone);
            };
            if existing.key.thumbprint != binding.key.thumbprint {
                return self.end_for_mismatch(&session, &user, now, ctx).await;
            }
            return self.renew(&session, &user, &existing, now).await;
        }
        self.audit
            .record(
                AuditEventType::SessionKeyBound,
                AuditResult::Success,
                Some(user.tenant_id),
                Some(user.id),
                None,
                Some(&format!(
                    "alg={} thumbprint={}",
                    binding.key.algorithm.as_str(),
                    binding.key.thumbprint
                )),
                ctx,
            )
            .await;
        self.renew(&session, &user, &binding, now).await
    }

    /// 更新（短い Cookie が切れたときの、登録した鍵での署名）。
    pub async fn refresh(
        &self,
        sso_session_id: &str,
        session_identifier: &str,
        proof: &str,
        ctx: &RequestContext,
    ) -> Result<SessionKeyOutcome, DomainError> {
        let now = self.clock.now();
        let Some((session, user)) = self.live_session(sso_session_id, now).await? else {
            return Ok(SessionKeyOutcome::SessionGone);
        };
        let Some(binding) = self.bindings.find(&session.session_hash).await? else {
            return Ok(SessionKeyOutcome::SessionGone);
        };
        if binding.session_identifier != session_identifier {
            return Ok(SessionKeyOutcome::SessionGone);
        }
        let Some(challenge) = self.fresh_challenge(sso_session_id, proof, now) else {
            // 古い challenge・形の崩れ。web は新しい challenge を出し直す（持ち出しの印とはしない）。
            return Ok(SessionKeyOutcome::Rejected);
        };
        match verify_refresh(proof, &binding.key, &challenge) {
            Ok(()) => {}
            Err(ProofError::BadSignature) => {
                return self.end_for_mismatch(&session, &user, now, ctx).await;
            }
            Err(e) => {
                self.reject(&user, e.as_str(), ctx).await;
                return Ok(SessionKeyOutcome::Rejected);
            }
        }
        self.bindings
            .record_refresh(&session.session_hash, now)
            .await?;
        self.renew(&session, &user, &binding, now).await
    }

    /// 生きているセッションと利用者。
    async fn live_session(
        &self,
        sso_session_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<(SsoSession, User)>, DomainError> {
        let session_hash = crypto::sha256_hex(sso_session_id);
        let Some(session) = self.sso_sessions.find_by_hash(&session_hash).await? else {
            return Ok(None);
        };
        if !session.is_valid_at(now) {
            return Ok(None);
        }
        let Some(user) = self.users.find_by_id(session.user_id).await? else {
            return Ok(None);
        };
        Ok(Some((session, user)))
    }

    /// 署名の `jti` が、このセッションに出した新しい challenge か。そうならその値を返す。
    ///
    /// ここでは署名を確かめない（確かめるのは domain の `verify_*`。`jti` はそこでもう一度照合する）。
    fn fresh_challenge(
        &self,
        sso_session_id: &str,
        proof: &str,
        now: DateTime<Utc>,
    ) -> Option<String> {
        let claims = jsonwebtoken::dangerous::insecure_decode::<UnverifiedClaims>(proof).ok()?;
        let jti = claims.claims.jti?;
        contract::challenge_is_fresh(&self.secret, sso_session_id, &jti, now.timestamp())
            .then_some(jti)
    }

    /// 長さを置き直して、結び付いた結果を返す。
    async fn renew(
        &self,
        session: &SsoSession,
        user: &User,
        binding: &SessionKeyBinding,
        now: DateTime<Utc>,
    ) -> Result<SessionKeyOutcome, DomainError> {
        let lifetime = self.settings.sso_session_lifetime(user.tenant_id).await?;
        let device_registered = match self.devices.session_device(&session.session_hash).await? {
            Some(device) => self.devices.find(user.id, &device).await?.is_some(),
            None => false,
        };
        let (idle, absolute) = lifetime_for(
            session.created_at,
            session.idle_expires_at,
            SessionBinding::DeviceKey,
            device_registered,
            lifetime.absolute,
            lifetime.bound,
        );
        if idle != session.idle_expires_at || absolute != session.absolute_expires_at {
            self.sso_sessions
                .set_lifetime(&session.session_hash, idle, absolute)
                .await?;
        }
        if !(idle > now && absolute > now) {
            // 30 日から戻したら、もう切れていた（端末の登録を取り消した後の古いログイン状態）。
            return Ok(SessionKeyOutcome::SessionGone);
        }
        let remaining = (idle.min(absolute) - now).num_seconds().max(0);
        Ok(SessionKeyOutcome::Bound {
            session_identifier: binding.session_identifier.clone(),
            remaining_secs: u64::try_from(remaining).unwrap_or(0),
        })
    }

    /// 別の鍵の署名が来た: ログイン状態を終わらせ、監査に残し、知らせる。
    async fn end_for_mismatch(
        &self,
        session: &SsoSession,
        user: &User,
        now: DateTime<Utc>,
        ctx: &RequestContext,
    ) -> Result<SessionKeyOutcome, DomainError> {
        self.sso_sessions.delete(&session.session_hash).await?;
        self.refresh_tokens
            .revoke_all_for_session(user.id, &sso_session::sid_of(&session.session_hash), now)
            .await?;
        self.audit
            .record(
                AuditEventType::SessionKeyRejected,
                AuditResult::Failure,
                Some(user.tenant_id),
                Some(user.id),
                None,
                Some("key_mismatch"),
                ctx,
            )
            .await;
        self.alert(user, now, ctx).await;
        Ok(SessionKeyOutcome::KeyMismatch)
    }

    async fn reject(&self, user: &User, reason: &str, ctx: &RequestContext) {
        self.audit
            .record(
                AuditEventType::SessionKeyRejected,
                AuditResult::Failure,
                Some(user.tenant_id),
                Some(user.id),
                None,
                Some(reason),
                ctx,
            )
            .await;
    }

    /// 知らせる。ADR-0071 の端末の知らせと違い、組織の設定に関わらず送る（盗みの強い印のため）。
    async fn alert(&self, user: &User, now: DateTime<Utc>, ctx: &RequestContext) {
        let username = user
            .preferred_username
            .clone()
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| format!("利用者 {}", &user.sub.simple().to_string()[..8]));
        self.alerts
            .send(SecurityAlert {
                kind: SecurityAlertKind::SessionKeyMismatch,
                tenant_id: user.tenant_id,
                user_id: user.id,
                username,
                occurred_at: now,
                country: None,
                ip_address: ctx.ip_address.clone(),
                user_agent: ctx.user_agent.clone(),
                group_key: format!("key-{}", &user.sub.simple().to_string()[..16]),
            })
            .await;
    }
}
