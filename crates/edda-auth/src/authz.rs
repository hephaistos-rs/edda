//! The authorization *service*: fetches whatever `edda-domain`'s pure
//! authorization functions need (via `edda-db`) and calls them. This
//! module must never decide an outcome itself, only assemble the inputs
//! a decision in `edda_domain::access` needs.

use edda_db::{
    BranchProtectionRepo, DbPool, OrganizationRepo, RepoAccessRepo, RepositoryRepo, TeamMemberRepo,
};
use edda_domain::{
    can_administer_repository, can_manage_repository_danger_zone, can_merge_pull_request,
    can_open_cross_repo_pull_request, can_read_repository, can_write_repository,
    effective_repo_role, ActorContext, AuthzError, OrganizationId, PrReview, Repository,
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

    /// The actor's *effective* access on `repository`: the maximum of any
    /// direct grant and any grant reachable through team membership
    /// (`edda_domain::effective_repo_role`, an extension of the
    /// "fetch, then decide" split — see that function's own doc comment).
    /// Wrapped back into a `RepoAccess` so every pure decision function in
    /// `edda_domain::access` stays unchanged: this is the "assembled
    /// input," not a raw database row, so its `subject` doesn't
    /// necessarily name the specific grant that produced the winning role
    /// (a team grant can win over no direct grant at all).
    async fn access_for(
        &self,
        actor: &ActorContext,
        repository: &Repository,
    ) -> Result<Option<edda_domain::RepoAccess>, AuthzError> {
        let Some(user_id) = actor.user_id() else {
            return Ok(None);
        };
        let direct = RepoAccessRepo::find(
            &self.pool,
            repository.id,
            edda_domain::AccessSubject::User(user_id),
        )
        .await
        .map_err(|_| AuthzError::NotFound)?
        .map(|access| access.role);
        let team_roles = RepoAccessRepo::team_roles_for_user(&self.pool, repository.id, user_id)
            .await
            .map_err(|_| AuthzError::NotFound)?;
        let effective = effective_repo_role(direct, &team_roles);
        Ok(effective.map(|role| edda_domain::RepoAccess {
            repository_id: repository.id,
            subject: edda_domain::AccessSubject::User(user_id),
            role,
        }))
    }

    /// Whether `actor` administers `organization_id` — currently exactly
    /// "is a member of its Owners team" (`OrganizationRepo::insert`
    /// creates that team alongside the organization itself; there is no
    /// separate, more general org-admin concept). Used to
    /// gate organization-level actions: creating a team, creating a
    /// repository under the organization, managing team membership.
    pub async fn check_administer_organization(
        &self,
        actor: &ActorContext,
        organization_id: OrganizationId,
    ) -> Result<(), AuthzError> {
        let Some(user_id) = actor.user_id() else {
            return Err(AuthzError::NotFound);
        };
        let teams =
            TeamMemberRepo::teams_for_user_in_organization(&self.pool, organization_id, user_id)
                .await
                .map_err(|_| AuthzError::NotFound)?;
        if teams.iter().any(|team| team.name == "Owners") {
            Ok(())
        } else {
            Err(AuthzError::Forbidden)
        }
    }

    /// Resolves an `{owner}` URL segment to an `Organization`, the same
    /// "either kind of not-found is the same NotFound" contract
    /// `repository_by_name` follows.
    pub async fn organization_by_name(
        &self,
        name: &str,
    ) -> Result<edda_domain::Organization, AuthzError> {
        OrganizationRepo::find_by_name(&self.pool, name)
            .await
            .map_err(|_| AuthzError::NotFound)?
            .ok_or(AuthzError::NotFound)
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

    /// Whether `actor` may open a cross-repository (fork-sourced) pull
    /// request proposing changes *from* `source` *into* `target`. Fetches
    /// `actor`'s effective access on each and delegates to
    /// `edda_domain::can_open_cross_repo_pull_request` (write on the fork +
    /// read on upstream). Same-repository pull requests don't come through
    /// here — they're a plain `check_write` on the one repository.
    pub async fn check_open_cross_repo_pull_request(
        &self,
        actor: &ActorContext,
        source: &Repository,
        target: &Repository,
    ) -> Result<(), AuthzError> {
        let source_access = self.access_for(actor, source).await?;
        let target_access = self.access_for(actor, target).await?;
        can_open_cross_repo_pull_request(
            actor,
            source,
            source_access.as_ref(),
            target,
            target_access.as_ref(),
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
