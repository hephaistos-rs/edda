//! `BranchProtectionService` — set / list / delete branch-protection
//! rules. Owner/Admin tier (`check_administer`): a rule constrains what
//! *anyone*, collaborators included, may do to a matched branch.

use edda_auth::AuthorizationService;
use edda_db::{BranchProtectionRepo, BranchProtectionSettings, DbPool};
use edda_domain::{
    AccessSubject, ActorContext, BranchProtectionRule, BranchProtectionRuleId, Repository,
};

use super::ServiceError;
use crate::AppState;

/// One rule plus its push-allowlist rendered back to usernames (team
/// entries are surfaced once the Phase 11 UI lands).
pub struct BranchProtectionView {
    pub rule: BranchProtectionRule,
    pub push_allowlist_usernames: Vec<String>,
}

/// Everything `set` writes for one `(repository, pattern)` rule.
pub struct SetBranchProtectionInput {
    pub pattern: String,
    pub settings: BranchProtectionSettings,
    /// Usernames permitted to push directly to a matched branch despite
    /// the rule. Unknown usernames are rejected as a validation error.
    pub push_allowlist_usernames: Vec<String>,
}

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

    pub async fn list(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
    ) -> Result<Vec<BranchProtectionView>, ServiceError> {
        let repository = self.authz.repository_by_name(owner, name).await?;
        self.authz.check_read(actor, &repository).await?;
        let rules =
            BranchProtectionRepo::list_for_repository_with_allowlist(&self.pool, repository.id)
                .await?;

        let mut views = Vec::with_capacity(rules.len());
        for rule in rules {
            let mut usernames = Vec::new();
            for subject in &rule.push_allowlist {
                if let AccessSubject::User(user_id) = subject {
                    if let Some(row) = edda_db::UserRepo::find_by_id(&self.pool, *user_id).await? {
                        usernames.push(row.user.username);
                    }
                }
            }
            views.push(BranchProtectionView {
                rule,
                push_allowlist_usernames: usernames,
            });
        }
        Ok(views)
    }

    pub async fn set(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
        input: SetBranchProtectionInput,
    ) -> Result<(), ServiceError> {
        let repository = self.administer_checked(actor, owner, name).await?;
        if input.pattern.trim().is_empty() || input.settings.required_approvals < 0 {
            return Err(ServiceError::Validation(
                "a branch pattern and a non-negative required-approvals count are needed"
                    .to_string(),
            ));
        }

        let mut subjects = Vec::with_capacity(input.push_allowlist_usernames.len());
        for username in &input.push_allowlist_usernames {
            let user = edda_db::UserRepo::find_by_username(&self.pool, username)
                .await?
                .ok_or_else(|| ServiceError::Validation(format!("no such user: {username}")))?;
            subjects.push(AccessSubject::User(user.id));
        }

        let rule_id = BranchProtectionRepo::upsert_by_pattern(
            &self.pool,
            BranchProtectionRuleId::new(),
            repository.id,
            input.pattern.trim(),
            &input.settings,
        )
        .await?;
        BranchProtectionRepo::replace_allowlist(&self.pool, rule_id, &subjects).await?;
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
