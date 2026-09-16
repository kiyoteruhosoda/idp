//! アプリの名簿を答える（ADR-0057）。RP の定期照合（ADR-0049 の I7）が読む。
//!
//! # 何を答えるか
//!
//! 「**このアプリを使ってよい利用者**」であって、テナントの利用者一覧ではない。割り当てのモードに
//! 関わらず同じ形で答え、⚠ **モードは RP に知らせない**（ADR-0054）。
//!
//! # 規則は 1 つ
//!
//! 可否は [`Application::roster_state`] が決め、その中身は判定（code の発行地点）と同じ
//! [`Application::admits`] である。リポジトリは事実だけを返す ——⚠ 一覧が判定と食い違うと、
//! 「名簿に居るのに入れない」「居ないのに入れる」が起きる。
//!
//! # 差分は無い
//!
//! ⚠ **`updated_since` を持たない。** 外した割り当ては行ごと消えるので差分に出てこず、足した
//! 割り当ては `users.updated_at` を動かさない ——照会がいちばん拾いたい変化が、いちばん伝わらない。
//! 照合は全件で回し、RP が持っている `sub` の消息は [`RosterQuery::Subjects`] で聞く。

use crate::domain::application::{Application, ApplicationUser, ApplicationUserState};
use crate::domain::paging::{Page, PageRequest, PagedResult};
use crate::domain::repositories::{ApplicationRepository, ApplicationUserQuery};
use crate::domain::tenant_context::TenantContext;
use crate::domain::values::AssignmentMode;
use std::sync::Arc;
use uuid::Uuid;

/// 1 ページの既定件数。
pub const DEFAULT_PAGE_SIZE: i64 = 50;
/// 1 ページの上限件数（超過分は丸める）。
pub const MAX_PAGE_SIZE: i64 = 200;
/// 一度に消息を聞ける `sub` の上限。
///
/// ⚠ **URI の長さで決めている。** `sub` は 36 文字なので、100 件で約 3.7KB ——前段（nginx・
/// cloudflared）の要求行の上限（既定 8KB）に対して安全側に収まる。足りなければ分けて聞く。
pub const MAX_SUBJECTS: usize = 100;

#[derive(Debug, PartialEq, Eq)]
pub enum ApplicationUserDirectoryError {
    /// その `client_id` に対応するアプリが無い（未登録・移行漏れ・binding が外れている）。
    ///
    /// ⚠ **空の名簿を返さない。** 「誰も使えない」と答えると RP は全員を止める。判定側が同じ
    /// 場合に素通しにしているのと同じ理由である（ADR-0054）。
    NotBound,
    /// 一度に聞ける `sub` の上限を超えた。
    TooManySubjects,
    Internal(String),
}

/// 何を聞かれているか。
pub enum RosterQuery {
    /// このアプリの候補を 1 ページ分（`EVERYONE` ならテナントのメンバー、`INDIVIDUAL` なら
    /// 割り当てのある利用者）。
    Page,
    /// RP が持っている `sub` の消息。⚠ **`unknown`（消えた）を答えられるのはこちらだけ**である
    /// ——消えた人は、いない以上、候補の一覧には現れない。
    Subjects(Vec<Uuid>),
}

pub struct ApplicationUserDirectoryService {
    applications: Arc<dyn ApplicationRepository>,
    roster: Arc<dyn ApplicationUserQuery>,
}

impl ApplicationUserDirectoryService {
    pub fn new(
        applications: Arc<dyn ApplicationRepository>,
        roster: Arc<dyn ApplicationUserQuery>,
    ) -> Self {
        Self {
            applications,
            roster,
        }
    }

    /// OIDC の `client_id` から名簿を引く。
    ///
    /// 宛先を `client_id` で指すのは、⚠ **RP が既に持っている唯一の値**だからである（アプリの
    /// 内部 ID を持たせると、アプリを作り直した日に古い ID のまま静かに別の名簿を読む）。解決は
    /// 判定と同じ経路（アプリ ↔ binding ↔ client）を通る。
    pub async fn for_oidc_client(
        &self,
        tenant: TenantContext,
        client_id: &str,
        query: RosterQuery,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<PagedResult<ApplicationUser>, ApplicationUserDirectoryError> {
        let application = self
            .applications
            .find_by_oidc_client_id(tenant.tenant_id(), client_id)
            .await
            .map_err(|e| ApplicationUserDirectoryError::Internal(e.to_string()))?
            .ok_or(ApplicationUserDirectoryError::NotBound)?;

        let page = PageRequest::clamped(limit, offset, DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE);
        let items = match query {
            RosterQuery::Page => self.candidates(tenant, &application, page).await?,
            RosterQuery::Subjects(subs) => self.subjects(tenant, &application, &subs, page).await?,
        };
        Ok(PagedResult::new(items, page))
    }

    /// 候補を 1 ページ分。⚠ **モードで引く表が変わる**（判定が `EVERYONE` で割り当てを引かないのと
    /// 同じ分かれ方。ADR-0054）。
    async fn candidates(
        &self,
        tenant: TenantContext,
        application: &Application,
        page: PageRequest,
    ) -> Result<Page<ApplicationUser>, ApplicationUserDirectoryError> {
        let facts = match application.assignment_mode {
            AssignmentMode::Everyone => {
                self.roster
                    .list_tenant_members(tenant.tenant_id(), page)
                    .await
            }
            AssignmentMode::Individual => {
                self.roster
                    .list_assigned(tenant.tenant_id(), application.id, page)
                    .await
            }
        }
        .map_err(|e| ApplicationUserDirectoryError::Internal(e.to_string()))?;

        Ok(Page::new(
            facts
                .items
                .into_iter()
                .map(|row| ApplicationUser {
                    sub: row.sub,
                    state: application.roster_state(row.facts),
                })
                .collect(),
            facts.total,
        ))
    }

    /// 聞かれた `sub` の消息。⚠ **聞かれた `sub` は必ず 1 行で返す**（返ってこない `sub` があると、
    /// 呼び出し側は「消えた」と「答えそびれた」を区別できない）。
    async fn subjects(
        &self,
        tenant: TenantContext,
        application: &Application,
        subs: &[Uuid],
        page: PageRequest,
    ) -> Result<Page<ApplicationUser>, ApplicationUserDirectoryError> {
        if subs.len() > MAX_SUBJECTS {
            return Err(ApplicationUserDirectoryError::TooManySubjects);
        }
        let facts = self
            .roster
            .facts_for_subs(tenant.tenant_id(), application.id, subs)
            .await
            .map_err(|e| ApplicationUserDirectoryError::Internal(e.to_string()))?;

        let mut answers: Vec<ApplicationUser> = subs
            .iter()
            .map(|sub| {
                let state = facts
                    .iter()
                    .find(|row| row.sub == *sub)
                    // 行が無い ＝ このテナントの利用者ではない。
                    .map_or(ApplicationUserState::Unknown, |row| {
                        application.roster_state(row.facts)
                    });
                ApplicationUser { sub: *sub, state }
            })
            .collect();
        // 候補の一覧と同じ並び（`sub` 昇順）に揃える。要求の順に返すと、同じ問い合わせでも
        // 並びが変わる。
        answers.sort_by_key(|user| user.sub);
        answers.dedup_by_key(|user| user.sub);
        Ok(Page::from_all(answers, page))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::application::{
        ApplicationAssignment, ApplicationBinding, ApplicationUserFacts, AssignedUser,
    };
    use crate::domain::error::Result as DomainResult;
    use crate::domain::repositories::SubjectFacts;
    use crate::domain::tenant::TenantId;
    use crate::domain::values::{ApplicationStatus, UserStatus};
    use async_trait::async_trait;
    use chrono::{DateTime, TimeZone, Utc};

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 16, 0, 0, 0).unwrap()
    }

    fn tenant_id() -> TenantId {
        TenantId::from(Uuid::from_u128(2))
    }

    fn application(mode: AssignmentMode, status: ApplicationStatus) -> Application {
        Application {
            id: Uuid::from_u128(1),
            tenant_id: tenant_id(),
            display_name: "photonest".to_string(),
            status,
            assignment_mode: mode,
            created_at: now(),
            updated_at: now(),
        }
    }

    fn facts(user_status: UserStatus, active_member: bool, assigned: bool) -> ApplicationUserFacts {
        ApplicationUserFacts {
            user_status,
            active_member,
            assigned,
        }
    }

    /// 1 件のアプリと、決め打ちの事実を返すフェイク。
    struct Fake {
        application: Option<Application>,
        rows: Vec<SubjectFacts>,
    }

    #[async_trait]
    impl ApplicationRepository for Fake {
        async fn create(&self, _a: &Application) -> DomainResult<()> {
            Ok(())
        }
        async fn find_by_id(&self, _t: TenantId, _id: Uuid) -> DomainResult<Option<Application>> {
            Ok(self.application.clone())
        }
        async fn find_by_oidc_client_id(
            &self,
            _t: TenantId,
            _c: &str,
        ) -> DomainResult<Option<Application>> {
            Ok(self.application.clone())
        }
        async fn find_by_saml_entity_id(
            &self,
            _t: TenantId,
            _e: &str,
        ) -> DomainResult<Option<Application>> {
            Ok(None)
        }
        async fn list(&self, _t: TenantId) -> DomainResult<Vec<Application>> {
            Ok(Vec::new())
        }
        async fn update(
            &self,
            _t: TenantId,
            _id: Uuid,
            _n: &str,
            _s: ApplicationStatus,
            _m: AssignmentMode,
            _u: DateTime<Utc>,
        ) -> DomainResult<bool> {
            Ok(false)
        }
        async fn delete(&self, _t: TenantId, _id: Uuid) -> DomainResult<bool> {
            Ok(false)
        }
        async fn list_bindings(&self, _id: Uuid) -> DomainResult<Vec<ApplicationBinding>> {
            Ok(Vec::new())
        }
        async fn add_binding(&self, _b: &ApplicationBinding) -> DomainResult<()> {
            Ok(())
        }
        async fn remove_binding(&self, _a: Uuid, _b: Uuid) -> DomainResult<bool> {
            Ok(false)
        }
        async fn is_assigned(&self, _a: Uuid, _u: Uuid) -> DomainResult<bool> {
            Ok(false)
        }
        async fn list_assigned_users(&self, _a: Uuid) -> DomainResult<Vec<AssignedUser>> {
            Ok(Vec::new())
        }
        async fn count_assignments(&self, _a: Uuid) -> DomainResult<i64> {
            Ok(0)
        }
        async fn assign(&self, _a: &ApplicationAssignment) -> DomainResult<()> {
            Ok(())
        }
        async fn unassign(&self, _a: Uuid, _u: Uuid) -> DomainResult<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl ApplicationUserQuery for Fake {
        async fn list_tenant_members(
            &self,
            _t: TenantId,
            page: PageRequest,
        ) -> DomainResult<Page<SubjectFacts>> {
            Ok(Page::from_all(self.rows.clone(), page))
        }
        async fn list_assigned(
            &self,
            _t: TenantId,
            _a: Uuid,
            page: PageRequest,
        ) -> DomainResult<Page<SubjectFacts>> {
            Ok(Page::from_all(self.rows.clone(), page))
        }
        async fn facts_for_subs(
            &self,
            _t: TenantId,
            _a: Uuid,
            subs: &[Uuid],
        ) -> DomainResult<Vec<SubjectFacts>> {
            Ok(self
                .rows
                .iter()
                .filter(|row| subs.contains(&row.sub))
                .copied()
                .collect())
        }
    }

    fn service(fake: Fake) -> ApplicationUserDirectoryService {
        let fake = Arc::new(fake);
        ApplicationUserDirectoryService::new(fake.clone(), fake)
    }

    fn context() -> TenantContext {
        TenantContext::new(tenant_id())
    }

    /// binding が無い client には**空の名簿を返さない**。返すと RP が全員を止める。
    #[tokio::test]
    async fn a_client_without_an_application_is_not_an_empty_roster() {
        let svc = service(Fake {
            application: None,
            rows: Vec::new(),
        });
        let err = svc
            .for_oidc_client(context(), "client-a", RosterQuery::Page, None, None)
            .await
            .unwrap_err();
        assert_eq!(err, ApplicationUserDirectoryError::NotBound);
    }

    /// 聞かれた `sub` は、assay に居なくても必ず 1 行で返る（＝消えた）。
    #[tokio::test]
    async fn a_subject_that_is_gone_comes_back_as_unknown() {
        let here = Uuid::from_u128(10);
        let gone = Uuid::from_u128(11);
        let svc = service(Fake {
            application: Some(application(
                AssignmentMode::Individual,
                ApplicationStatus::Active,
            )),
            rows: vec![SubjectFacts {
                sub: here,
                facts: facts(UserStatus::Active, true, true),
            }],
        });
        let result = svc
            .for_oidc_client(
                context(),
                "client-a",
                RosterQuery::Subjects(vec![here, gone]),
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(result.page.total, 2);
        assert_eq!(
            result.page.items,
            vec![
                ApplicationUser {
                    sub: here,
                    state: ApplicationUserState::Allowed
                },
                ApplicationUser {
                    sub: gone,
                    state: ApplicationUserState::Unknown
                },
            ]
        );
    }

    /// 止まっているアカウントは、割り当てがあっても `blocked`（⚠ 結び付きは残す側）。
    #[tokio::test]
    async fn a_disabled_account_is_blocked_even_when_assigned() {
        let sub = Uuid::from_u128(10);
        let svc = service(Fake {
            application: Some(application(
                AssignmentMode::Individual,
                ApplicationStatus::Active,
            )),
            rows: vec![SubjectFacts {
                sub,
                facts: facts(UserStatus::Disabled, true, true),
            }],
        });
        let result = svc
            .for_oidc_client(context(), "client-a", RosterQuery::Page, None, None)
            .await
            .unwrap();
        assert_eq!(result.page.items[0].state, ApplicationUserState::Blocked);
    }

    /// 止めたアプリは、候補が消えるのではなく**全員が `blocked`** で返る
    /// ——「引けなかった」と「誰も使えない」を取り違えさせない。
    #[tokio::test]
    async fn a_disabled_application_blocks_everyone_without_emptying_the_roster() {
        let sub = Uuid::from_u128(10);
        let svc = service(Fake {
            application: Some(application(
                AssignmentMode::Everyone,
                ApplicationStatus::Disabled,
            )),
            rows: vec![SubjectFacts {
                sub,
                facts: facts(UserStatus::Active, true, false),
            }],
        });
        let result = svc
            .for_oidc_client(context(), "client-a", RosterQuery::Page, None, None)
            .await
            .unwrap();
        assert_eq!(result.page.total, 1);
        assert_eq!(result.page.items[0].state, ApplicationUserState::Blocked);
    }

    /// 「全員」のアプリでは、参加中でないメンバー（招待中・一時停止）は `blocked`。
    #[tokio::test]
    async fn everyone_mode_blocks_members_who_are_not_active() {
        let sub = Uuid::from_u128(10);
        let svc = service(Fake {
            application: Some(application(
                AssignmentMode::Everyone,
                ApplicationStatus::Active,
            )),
            rows: vec![SubjectFacts {
                sub,
                facts: facts(UserStatus::Active, false, false),
            }],
        });
        let result = svc
            .for_oidc_client(context(), "client-a", RosterQuery::Page, None, None)
            .await
            .unwrap();
        assert_eq!(result.page.items[0].state, ApplicationUserState::Blocked);
    }

    #[tokio::test]
    async fn too_many_subjects_is_refused() {
        let svc = service(Fake {
            application: Some(application(
                AssignmentMode::Individual,
                ApplicationStatus::Active,
            )),
            rows: Vec::new(),
        });
        let subs: Vec<Uuid> = (0..=MAX_SUBJECTS as u128).map(Uuid::from_u128).collect();
        let err = svc
            .for_oidc_client(
                context(),
                "client-a",
                RosterQuery::Subjects(subs),
                None,
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err, ApplicationUserDirectoryError::TooManySubjects);
    }
}
