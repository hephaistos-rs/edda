//! Repository access control: the four-tier role model, and the pure
//! functions that decide whether a given actor may read/write/administer/
//! manage-danger-zone a repository. This is the
//! functional core of authorization: every function here takes
//! already-fetched state and makes no I/O of its own. `edda-auth::authz`
//! is the thin async layer that fetches that state (via `edda-db`) and
//! calls into this module; nothing outside this module decides an
//! authorization outcome.

use serde::{Deserialize, Serialize};

use crate::branch_protection::BranchProtectionRule;
use crate::ids::{RepositoryId, TeamId, UserId};
use crate::pull_request::{latest_reviews, PrReview, ReviewState};
use crate::repository::Repository;

/// Ranked low-to-high so `role >= minimum` is a valid permission check —
/// derived `Ord` follows declaration order, which is why the order here
/// matters as much as the variant names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RepoRole {
    Read,
    Write,
    Admin,
    Owner,
}

impl RepoRole {
    /// The lowercase form `edda-db` stores in `repo_access.role` (and the
    /// matching `CHECK` constraint's literal values) — kept as an explicit
    /// mapping here, not a `Display`/`FromStr` pair, so it's obviously a
    /// storage-format concern rather than a user-facing rendering.
    pub const fn as_db_str(self) -> &'static str {
        match self {
            RepoRole::Read => "read",
            RepoRole::Write => "write",
            RepoRole::Admin => "admin",
            RepoRole::Owner => "owner",
        }
    }

    pub fn from_db_str(value: &str) -> Option<Self> {
        match value {
            "read" => Some(RepoRole::Read),
            "write" => Some(RepoRole::Write),
            "admin" => Some(RepoRole::Admin),
            "owner" => Some(RepoRole::Owner),
            _ => None,
        }
    }
}

/// Who a `repo_access` grant is made to — an individual account, or a
/// `Team`, so an organization can grant its repositories to a group of
/// people at once instead of one `RepoAccess` row per member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessSubject {
    User(UserId),
    Team(TeamId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepoAccess {
    pub repository_id: RepositoryId,
    pub subject: AccessSubject,
    pub role: RepoRole,
}

/// Which repositories a bearer-token identity may act against. `All` is
/// what every token issued today gets — unscoped, so this type changes
/// nothing about what an existing token can do. `PublicOnly`/`Specific`
/// exist so a future token-creation UI can narrow a *new* token's reach
/// without a further domain change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RepositoryScope {
    All,
    PublicOnly,
    Specific(Vec<RepositoryId>),
}

impl RepositoryScope {
    pub fn permits(&self, repository: &Repository) -> bool {
        match self {
            RepositoryScope::All => true,
            RepositoryScope::PublicOnly => !repository.is_private(),
            RepositoryScope::Specific(ids) => ids.contains(&repository.id),
        }
    }
}

/// A personal access token's *operation* scope — orthogonal to
/// [`RepositoryScope`] (which repositories) — narrowing which *kinds* of
/// operation a token may perform. `All` is what every token issued before
/// scopes existed carries, so this changes nothing about an existing
/// token; `RepoRead`/`RepoWrite` let a token-creation UI issue a
/// deliberately limited token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenScope {
    All,
    RepoRead,
    RepoWrite,
}

impl TokenScope {
    /// Whether a token with `self` may perform an operation that requires
    /// `required` (`RepoRead` or `RepoWrite`). `RepoWrite` implies
    /// `RepoRead`; `All` implies everything.
    #[must_use]
    pub fn permits(self, required: TokenScope) -> bool {
        // A total order: All > RepoWrite > RepoRead.
        fn rank(scope: TokenScope) -> u8 {
            match scope {
                TokenScope::RepoRead => 0,
                TokenScope::RepoWrite => 1,
                TokenScope::All => 2,
            }
        }
        rank(self) >= rank(required)
    }
}

/// Who is asking, resolved uniformly regardless of which credential kind
/// they authenticated with (session cookie, bearer token, or a repo-scoped
/// SSH deploy key) — see `edda-auth` for how each resolves into one of
/// these variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActorContext {
    Anonymous,
    User(UserId),
    Token {
        user_id: UserId,
        /// Which repositories this token may act against.
        scope: RepositoryScope,
        /// Which kinds of operation this token may perform.
        token_scope: TokenScope,
    },
    /// An SSH deploy key: authenticates as one repository, not a user.
    DeployKey {
        repository_id: RepositoryId,
        /// `true` → clone/fetch only; `false` → also push.
        read_only: bool,
    },
}

impl ActorContext {
    /// The acting user, or `None` for an anonymous request or a deploy key
    /// (which has no user identity).
    pub fn user_id(&self) -> Option<UserId> {
        match self {
            ActorContext::Anonymous | ActorContext::DeployKey { .. } => None,
            ActorContext::User(id) => Some(*id),
            ActorContext::Token { user_id, .. } => Some(*user_id),
        }
    }

    /// Whether this actor's PAT operation scope permits `required`. A
    /// session `User` and a deploy key are not PAT-scoped, so they always
    /// pass this axis — a deploy key's own read/write limit is enforced by
    /// [`can_read_repository`] / [`can_write_repository`].
    #[must_use]
    pub fn permits_token_scope(&self, required: TokenScope) -> bool {
        match self {
            ActorContext::Token { token_scope, .. } => token_scope.permits(required),
            _ => true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthzError {
    /// The target either doesn't exist, or its existence must not be
    /// distinguishable from "doesn't exist" for this actor (a private
    /// repository the actor has no grant on). Callers map this to an
    /// HTTP 404, never a 403.
    #[error("not found")]
    NotFound,
    /// The actor's identity — and the target's existence — are already
    /// known to them; they simply lack the permission this operation
    /// needs.
    #[error("forbidden")]
    Forbidden,
}

/// `access` is the actor's `RepoAccess` grant on `repository`, if any,
/// already fetched by the caller.
pub fn can_read_repository(
    actor: &ActorContext,
    repository: &Repository,
    access: Option<&RepoAccess>,
) -> Result<(), AuthzError> {
    // A deploy key acts as exactly one repository: it may always read that
    // one (public or private), and nothing else.
    if let ActorContext::DeployKey { repository_id, .. } = actor {
        return if *repository_id == repository.id {
            Ok(())
        } else {
            Err(AuthzError::NotFound)
        };
    }
    if !repository.is_private() {
        return Ok(());
    }
    match access {
        Some(_) if token_scope_permits(actor, repository) => Ok(()),
        _ => Err(AuthzError::NotFound),
    }
}

pub fn can_write_repository(
    actor: &ActorContext,
    repository: &Repository,
    access: Option<&RepoAccess>,
) -> Result<(), AuthzError> {
    require_role(actor, repository, access, RepoRole::Write)
}

pub fn can_administer_repository(
    actor: &ActorContext,
    repository: &Repository,
    access: Option<&RepoAccess>,
) -> Result<(), AuthzError> {
    require_role(actor, repository, access, RepoRole::Admin)
}

/// Owner-only "danger zone" actions: delete, transfer, visibility change —
/// deliberately a stricter tier than `can_administer_repository`, matching
/// the four-tier model's own split between Admin and Owner. Any
/// collaborator (Admin included) may administer a repository, but only
/// its Owner may perform these irreversible or identity-changing actions.
pub fn can_manage_repository_danger_zone(
    actor: &ActorContext,
    repository: &Repository,
    access: Option<&RepoAccess>,
) -> Result<(), AuthzError> {
    require_role(actor, repository, access, RepoRole::Owner)
}

/// The single centralized instance-administration check (user management,
/// the admin UI/API) — every caller passes the already-resolved actor's
/// `User::is_admin` flag rather than re-deriving admin-ness itself, so
/// there is exactly one place that decides what "admin" means, matching
/// the same discipline `can_administer_repository` already applies to
/// repository-scoped roles. Deliberately takes a plain `bool`, not a
/// `User`, so `edda-domain` doesn't need to know the shape of a session
/// or token to make this decision — the caller has already resolved *who
/// is asking* before reaching here.
pub fn require_instance_admin(actor_is_admin: bool) -> Result<(), AuthzError> {
    if actor_is_admin {
        Ok(())
    } else {
        Err(AuthzError::Forbidden)
    }
}

/// Whether `actor` may merge a pull request into `repository`, given
/// `protection` (the target branch's rule, if any) and the PR's
/// `reviews`. This is strictly the *authorization* half of "can this PR
/// be merged" — write access, plus the target branch's required-approval
/// count if it's protected. Whether the PR's own state actually permits
/// merging (already merged/closed, or has real git conflicts) is a
/// business-rule/state-machine question, not an authorization one, and is
/// the caller's responsibility to check separately (matching
/// `AuthzError`'s own two-variant shape, which has no room to distinguish
/// "you may never do this" from "this particular PR can't be merged right
/// now").
///
/// A branch-protection rule's `required_approvals` is enforced uniformly
/// — including for `RepoRole::Admin`/`Owner` actors — since a merge is a
/// content-safety gate the rule exists specifically to enforce, unlike
/// direct-push blocking (see `edda_git`'s own protected-branch check),
/// where an admin bypass matches how mainstream git hosts default that
/// specific control.
pub fn can_merge_pull_request(
    actor: &ActorContext,
    repository: &Repository,
    protection: Option<&BranchProtectionRule>,
    reviews: &[PrReview],
    access: Option<&RepoAccess>,
) -> Result<(), AuthzError> {
    can_write_repository(actor, repository, access)?;

    let Some(rule) = protection else {
        return Ok(());
    };
    let approvals = latest_reviews(reviews)
        .into_iter()
        .filter(|review| review.state == ReviewState::Approved)
        .count();
    if (approvals as i64) < rule.required_approvals {
        return Err(AuthzError::Forbidden);
    }
    Ok(())
}

/// Whether `actor` may open a pull request that proposes changes *from*
/// `source` (a branch in a fork they pushed to) *into* `target` (the
/// upstream they want their work merged into). The contributor model:
/// **write on the source** — it's their fork, and they must be able to
/// point a proposal at its branches — plus only **read on the target** —
/// they must be able to see what they're proposing to change, but need no
/// write there, since the maintainer is the one who merges.
/// `source_access`/`target_access` are `actor`'s already-fetched grants on
/// each repository, exactly as every other function in this module takes
/// its `access`.
///
/// Same-repository pull requests are the `source.id == target.id` case and
/// are authorized by `can_write_repository` on that one repository
/// instead; this function is only for the cross-repository (fork) path.
/// Read-on-target is checked first so an actor who can't even see `target`
/// gets the same `NotFound` a direct read would give, never a hint that a
/// private upstream exists.
pub fn can_open_cross_repo_pull_request(
    actor: &ActorContext,
    source: &Repository,
    source_access: Option<&RepoAccess>,
    target: &Repository,
    target_access: Option<&RepoAccess>,
) -> Result<(), AuthzError> {
    can_read_repository(actor, target, target_access)?;
    can_write_repository(actor, source, source_access)?;
    Ok(())
}

fn token_scope_permits(actor: &ActorContext, repository: &Repository) -> bool {
    match actor {
        ActorContext::Token { scope, .. } => scope.permits(repository),
        _ => true,
    }
}

fn require_role(
    actor: &ActorContext,
    repository: &Repository,
    access: Option<&RepoAccess>,
    minimum: RepoRole,
) -> Result<(), AuthzError> {
    let not_permitted = || {
        if repository.is_private() {
            AuthzError::NotFound
        } else {
            AuthzError::Forbidden
        }
    };

    // A deploy key is asked for `Write` or higher here (reads never reach
    // `require_role`). It may push to its own repository only when it is
    // not read-only, and can never administer.
    if let ActorContext::DeployKey {
        repository_id,
        read_only,
    } = actor
    {
        let ok = *repository_id == repository.id && !*read_only && minimum <= RepoRole::Write;
        return if ok { Ok(()) } else { Err(not_permitted()) };
    }

    let Some(access) = access else {
        return Err(not_permitted());
    };
    if !token_scope_permits(actor, repository) {
        return Err(not_permitted());
    }
    if access.role >= minimum {
        Ok(())
    } else {
        Err(AuthzError::Forbidden)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo(visibility: Visibility) -> Repository {
        use crate::repository::RepositoryOwner;
        Repository {
            id: RepositoryId::new(),
            owner: RepositoryOwner::User(UserId::new()),
            name: "demo".to_string(),
            description: None,
            visibility,
            forked_from: None,
        }
    }

    fn access(repository_id: RepositoryId, user_id: UserId, role: RepoRole) -> RepoAccess {
        RepoAccess {
            repository_id,
            subject: AccessSubject::User(user_id),
            role,
        }
    }

    use crate::repository::Visibility;

    #[test]
    fn anyone_can_read_a_public_repo() {
        let public = repo(Visibility::Public);
        assert!(can_read_repository(&ActorContext::Anonymous, &public, None).is_ok());
        assert!(can_read_repository(&ActorContext::User(UserId::new()), &public, None).is_ok());
    }

    #[test]
    fn a_private_repo_hides_its_existence_from_actors_without_a_grant() {
        let private = repo(Visibility::Private);
        let err = can_read_repository(&ActorContext::Anonymous, &private, None).unwrap_err();
        assert_eq!(err, AuthzError::NotFound);
    }

    #[test]
    fn a_private_repo_is_readable_with_any_role_grant() {
        let private = repo(Visibility::Private);
        let user = UserId::new();
        let grant = access(private.id, user, RepoRole::Read);
        assert!(can_read_repository(&ActorContext::User(user), &private, Some(&grant)).is_ok());
    }

    #[test]
    fn a_deploy_key_acts_only_on_its_own_repository() {
        let mine = repo(Visibility::Private);
        let other = repo(Visibility::Private);
        let rw = ActorContext::DeployKey {
            repository_id: mine.id,
            read_only: false,
        };
        let ro = ActorContext::DeployKey {
            repository_id: mine.id,
            read_only: true,
        };

        // Read + write on its own repo for a read-write key; read only for
        // a read-only key.
        assert!(can_read_repository(&rw, &mine, None).is_ok());
        assert!(can_write_repository(&rw, &mine, None).is_ok());
        assert!(can_read_repository(&ro, &mine, None).is_ok());
        assert_eq!(
            can_write_repository(&ro, &mine, None).unwrap_err(),
            AuthzError::NotFound
        );

        // Nothing at all on any other repo, and never admin.
        assert_eq!(
            can_read_repository(&rw, &other, None).unwrap_err(),
            AuthzError::NotFound
        );
        assert_eq!(
            can_administer_repository(&rw, &mine, None).unwrap_err(),
            AuthzError::NotFound
        );
        assert!(rw.user_id().is_none());
    }

    #[test]
    fn a_read_scoped_token_may_not_perform_a_write_operation() {
        let actor_read = ActorContext::Token {
            user_id: UserId::new(),
            scope: RepositoryScope::All,
            token_scope: TokenScope::RepoRead,
        };
        assert!(actor_read.permits_token_scope(TokenScope::RepoRead));
        assert!(!actor_read.permits_token_scope(TokenScope::RepoWrite));

        // `All` and a plain session user pass every axis.
        assert!(ActorContext::User(UserId::new()).permits_token_scope(TokenScope::RepoWrite));
        assert!(TokenScope::All.permits(TokenScope::RepoWrite));
    }

    #[test]
    fn write_requires_at_least_write_role() {
        let private = repo(Visibility::Private);
        let user = UserId::new();
        let read_only = access(private.id, user, RepoRole::Read);
        assert_eq!(
            can_write_repository(&ActorContext::User(user), &private, Some(&read_only))
                .unwrap_err(),
            AuthzError::Forbidden
        );

        let writer = access(private.id, user, RepoRole::Write);
        assert!(can_write_repository(&ActorContext::User(user), &private, Some(&writer)).is_ok());
    }

    #[test]
    fn danger_zone_requires_owner_not_admin() {
        let repository = repo(Visibility::Public);
        let user = UserId::new();
        let admin = access(repository.id, user, RepoRole::Admin);
        assert_eq!(
            can_manage_repository_danger_zone(&ActorContext::User(user), &repository, Some(&admin))
                .unwrap_err(),
            AuthzError::Forbidden
        );

        let owner = access(repository.id, user, RepoRole::Owner);
        assert!(can_manage_repository_danger_zone(
            &ActorContext::User(user),
            &repository,
            Some(&owner)
        )
        .is_ok());
    }

    #[test]
    fn a_public_only_token_cannot_write_to_a_private_repo_even_with_a_grant() {
        let private = repo(Visibility::Private);
        let user = UserId::new();
        let owner = access(private.id, user, RepoRole::Owner);
        let actor = ActorContext::Token {
            user_id: user,
            scope: RepositoryScope::PublicOnly,
            token_scope: TokenScope::All,
        };
        assert_eq!(
            can_write_repository(&actor, &private, Some(&owner)).unwrap_err(),
            AuthzError::NotFound
        );
    }

    fn review(state: ReviewState) -> PrReview {
        PrReview {
            id: crate::ids::PrReviewId::new(),
            pull_request_id: crate::ids::PullRequestId::new(),
            reviewer_id: UserId::new(),
            state,
            body: None,
            created_at: 0,
        }
    }

    #[test]
    fn an_unprotected_branch_needs_no_approvals_to_merge() {
        let repository = repo(Visibility::Public);
        let user = UserId::new();
        let writer = access(repository.id, user, RepoRole::Write);
        assert!(can_merge_pull_request(
            &ActorContext::User(user),
            &repository,
            None,
            &[],
            Some(&writer)
        )
        .is_ok());
    }

    #[test]
    fn a_protected_branch_blocks_a_merge_short_of_its_required_approvals() {
        let repository = repo(Visibility::Public);
        let user = UserId::new();
        let writer = access(repository.id, user, RepoRole::Write);
        let rule = crate::branch_protection::BranchProtectionRule {
            repository_id: repository.id,
            pattern: "main".to_string(),
            required_approvals: 1,
            ..Default::default()
        };

        let err = can_merge_pull_request(
            &ActorContext::User(user),
            &repository,
            Some(&rule),
            &[],
            Some(&writer),
        )
        .unwrap_err();
        assert_eq!(err, AuthzError::Forbidden);

        assert!(can_merge_pull_request(
            &ActorContext::User(user),
            &repository,
            Some(&rule),
            &[review(ReviewState::Approved)],
            Some(&writer),
        )
        .is_ok());
    }

    #[test]
    fn only_a_reviewers_latest_verdict_counts_toward_required_approvals() {
        let repository = repo(Visibility::Public);
        let user = UserId::new();
        let writer = access(repository.id, user, RepoRole::Write);
        let rule = crate::branch_protection::BranchProtectionRule {
            repository_id: repository.id,
            pattern: "main".to_string(),
            required_approvals: 1,
            ..Default::default()
        };
        let reviewer = UserId::new();
        let reviews = vec![
            PrReview {
                created_at: 1,
                ..review(ReviewState::Approved)
            },
            PrReview {
                reviewer_id: reviewer,
                created_at: 2,
                ..review(ReviewState::ChangesRequested)
            },
        ];
        // Both reviews are actually the same reviewer's, with the later
        // (changes-requested) verdict superseding the earlier approval.
        let reviews: Vec<PrReview> = reviews
            .into_iter()
            .map(|r| PrReview {
                reviewer_id: reviewer,
                ..r
            })
            .collect();

        let err = can_merge_pull_request(
            &ActorContext::User(user),
            &repository,
            Some(&rule),
            &reviews,
            Some(&writer),
        )
        .unwrap_err();
        assert_eq!(err, AuthzError::Forbidden);
    }

    #[test]
    fn a_cross_repo_pull_request_needs_write_on_the_fork_and_read_on_upstream() {
        let upstream = repo(Visibility::Public);
        let fork = repo(Visibility::Public);
        let contributor = UserId::new();
        let actor = ActorContext::User(contributor);
        let fork_write = access(fork.id, contributor, RepoRole::Write);

        // Write on the fork + (implicit) read on the public upstream → ok,
        // even with no grant at all on upstream.
        assert!(can_open_cross_repo_pull_request(
            &actor,
            &fork,
            Some(&fork_write),
            &upstream,
            None,
        )
        .is_ok());

        // Only read on the "source" (e.g. they can see the fork but it
        // isn't theirs) → refused.
        let fork_read = access(fork.id, contributor, RepoRole::Read);
        assert_eq!(
            can_open_cross_repo_pull_request(&actor, &fork, Some(&fork_read), &upstream, None)
                .unwrap_err(),
            AuthzError::Forbidden
        );

        // Cannot see a private upstream at all → NotFound, and the check
        // never gets as far as looking at the fork.
        let private_upstream = repo(Visibility::Private);
        assert_eq!(
            can_open_cross_repo_pull_request(
                &actor,
                &fork,
                Some(&fork_write),
                &private_upstream,
                None,
            )
            .unwrap_err(),
            AuthzError::NotFound
        );
    }

    #[test]
    fn a_specific_scope_token_is_limited_to_its_listed_repositories() {
        let repo_a = repo(Visibility::Public);
        let repo_b = repo(Visibility::Public);
        let user = UserId::new();
        let grant_a = access(repo_a.id, user, RepoRole::Write);
        let grant_b = access(repo_b.id, user, RepoRole::Write);
        let actor = ActorContext::Token {
            user_id: user,
            scope: RepositoryScope::Specific(vec![repo_a.id]),
            token_scope: TokenScope::All,
        };

        assert!(can_write_repository(&actor, &repo_a, Some(&grant_a)).is_ok());
        assert_eq!(
            can_write_repository(&actor, &repo_b, Some(&grant_b)).unwrap_err(),
            AuthzError::Forbidden
        );
    }
}
