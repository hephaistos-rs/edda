//! The authorization *service*: fetches whatever `edda-domain`'s pure
//! authorization functions need (via `edda-db`) and calls them. This
//! module must never decide an outcome itself, only assemble the inputs
//! a decision in `edda_domain::access` needs.

use edda_db::{BranchProtectionRepo, DbPool, RepoAccessRepo, RepositoryRepo};
use edda_domain::{
    can_administer_repository, can_manage_repository_danger_zone, can_merge_pull_request,
    can_read_repository, can_write_repository, ActorContext, AuthzError, PrReview, Repository,
};

#[derive(Clone)]
pub struct AuthorizationService {
    pool: DbPool,
}

impl AuthorizationService {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Resolves the `{owner_username}/{repo_name}` form used in URLs and
    /// clone paths. Returns `NotFound` for both "the string is malformed"
    /// and "the repository genuinely doesn't exist" — this function makes
    /// no visibility/access decision of its own, so it's safe for a
    /// caller to call this before ever checking `can_read`/`can_write`.
    pub async fn repository_by_name(
        &self,
        owner_username: &str,
        name: &str,
    ) -> Result<Repository, AuthzError> {
        RepositoryRepo::find_by_owner_username_and_name(&self.pool, owner_username, name)
            .await
            .map_err(|_| AuthzError::NotFound)?
            .ok_or(AuthzError::NotFound)
    }

    async fn access_for(
        &self,
        actor: &ActorContext,
        repository: &Repository,
    ) -> Result<Option<edda_domain::RepoAccess>, AuthzError> {
        match actor.user_id() {
            Some(user_id) => RepoAccessRepo::find(&self.pool, repository.id, user_id)
                .await
                .map_err(|_| AuthzError::NotFound),
            None => Ok(None),
        }
    }

    pub async fn check_read(
        &self,
        actor: &ActorContext,
        repository: &Repository,
    ) -> Result<(), AuthzError> {
        let access = self.access_for(actor, repository).await?;
        can_read_repository(actor, repository, access.as_ref())
    }

    pub async fn check_write(
        &self,
        actor: &ActorContext,
        repository: &Repository,
    ) -> Result<(), AuthzError> {
        let access = self.access_for(actor, repository).await?;
        can_write_repository(actor, repository, access.as_ref())
    }

    pub async fn check_administer(
        &self,
        actor: &ActorContext,
        repository: &Repository,
    ) -> Result<(), AuthzError> {
        let access = self.access_for(actor, repository).await?;
        can_administer_repository(actor, repository, access.as_ref())
    }

    pub async fn check_danger_zone(
        &self,
        actor: &ActorContext,
        repository: &Repository,
    ) -> Result<(), AuthzError> {
        let access = self.access_for(actor, repository).await?;
        can_manage_repository_danger_zone(actor, repository, access.as_ref())
    }

    /// Whether `actor` may merge a pull request targeting `target_branch`
    /// of `repository`, given `reviews` (every review ever submitted on
    /// it — this method reduces to latest-per-reviewer itself, so callers
    /// don't need to). Fetches `target_branch`'s `BranchProtectionRule`,
    /// if any, then delegates to `edda_domain::can_merge_pull_request`.
    pub async fn check_merge_pull_request(
        &self,
        actor: &ActorContext,
        repository: &Repository,
        target_branch: &str,
        reviews: &[PrReview],
    ) -> Result<(), AuthzError> {
        let access = self.access_for(actor, repository).await?;
        let protection =
            BranchProtectionRepo::find_for_branch(&self.pool, repository.id, target_branch)
                .await
                .map_err(|_| AuthzError::NotFound)?;
        can_merge_pull_request(
            actor,
            repository,
            protection.as_ref(),
            reviews,
            access.as_ref(),
        )
    }

    /// Every `refs/heads/{branch}` a direct push to `repository` may not
    /// touch, for `actor` — empty if `actor` administers the repository
    /// (branch-protection's direct-push block doesn't apply to Admin+;
    /// see `edda_domain::branch_protection`'s module doc comment), else
    /// every protected branch's ref name. Used by `edda-git`'s receive-
    /// pack path (`edda-git` itself has no `edda-db`/`edda-domain`
    /// dependency — see that crate's own doc comment on
    /// `apply_receive_pack`'s `protected_refs` parameter for why this
    /// resolution happens here instead).
    pub async fn protected_ref_names(
        &self,
        actor: &ActorContext,
        repository: &Repository,
    ) -> Result<std::collections::HashSet<String>, AuthzError> {
        if self.check_administer(actor, repository).await.is_ok() {
            return Ok(std::collections::HashSet::new());
        }
        let rules = BranchProtectionRepo::list_for_repository(&self.pool, repository.id)
            .await
            .map_err(|_| AuthzError::NotFound)?;
        Ok(rules
            .into_iter()
            .map(|rule| format!("refs/heads/{}", rule.branch))
            .collect())
    }
}
