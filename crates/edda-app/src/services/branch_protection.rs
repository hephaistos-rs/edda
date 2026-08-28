//! `BranchProtectionService` — set / delete branch-protection rules.
//! Owner/Admin tier (`check_administer`): a rule constrains what *anyone*,
//! collaborators included, may do to a branch.

use edda_auth::AuthorizationService;
use edda_db::{BranchProtectionRepo, DbPool};
use edda_domain::{ActorContext, BranchProtectionRuleId, Repository};

use super::ServiceError;
use crate::AppState;

#[derive(Clone)]
pub struct BranchProtectionService {
    pool: DbPool,
    authz: AuthorizationService,
}

impl BranchProtectionService {
    pub fn new(pool: DbPool, authz: AuthorizationService) -> Self {
        Self { pool, authz }
    }

    #[must_use]
    pub fn from_state(state: &AppState) -> Self {
        Self::new(state.pool.clone(), state.authz.clone())
    }

    pub async fn set(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
        branch: &str,
        required_approvals: i64,
    ) -> Result<(), ServiceError> {
        let repository = self.administer_checked(actor, owner, name).await?;
        if branch.trim().is_empty() || required_approvals < 0 {
            return Err(ServiceError::Validation(
                "a branch name and a non-negative required-approvals count are needed".to_string(),
            ));
        }
        BranchProtectionRepo::insert(
            &self.pool,
            BranchProtectionRuleId::new(),
            repository.id,
            branch.trim(),
            required_approvals,
        )
        .await?;
        Ok(())
    }

    pub async fn delete(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
        rule_id: BranchProtectionRuleId,
    ) -> Result<(), ServiceError> {
        let repository = self.administer_checked(actor, owner, name).await?;
        if !BranchProtectionRepo::delete(&self.pool, repository.id, rule_id).await? {
            return Err(ServiceError::NotFound);
        }
        Ok(())
    }

    async fn administer_checked(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
    ) -> Result<Repository, ServiceError> {
        let repository = self.authz.repository_by_name(owner, name).await?;
        self.authz.check_administer(actor, &repository).await?;
        Ok(repository)
    }
}
