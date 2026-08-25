//! Repository access control: the four-tier role model, and the pure
//! functions that decide whether a given actor may read/write/administer/
//! manage-danger-zone a repository. This is the
//! functional core of authorization: every function here takes
//! already-fetched state and makes no I/O of its own. `edda-auth::authz`
//! is the thin async layer that fetches that state (via `edda-db`) and
//! calls into this module; nothing outside this module decides an
//! authorization outcome.

use serde::{Deserialize, Serialize};

use crate::ids::{RepositoryId, UserId};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepoAccess {
    pub repository_id: RepositoryId,
    pub user_id: UserId,
    pub role: RepoRole,
}

/// Which repositories a bearer-token identity may act against. `All` is
/// what every token issued today gets — unscoped, matching a personal
/// access token's pre-restructuring behavior exactly, so introducing this
/// type changes nothing about what an existing-shaped token can do.
/// `PublicOnly`/`Specific` exist so a future token-creation UI can narrow
/// a *new* token's reach without a further domain change.
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

/// Who is asking, resolved uniformly regardless of which credential kind
/// they authenticated with (session cookie or bearer token) — see
/// `edda-auth::authn` for how each resolves into one of these variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActorContext {
    Anonymous,
    User(UserId),
    Token {
        user_id: UserId,
        scope: RepositoryScope,
    },
}

impl ActorContext {
    pub fn user_id(&self) -> Option<UserId> {
        match self {
            ActorContext::Anonymous => None,
            ActorContext::User(id) => Some(*id),
            ActorContext::Token { user_id, .. } => Some(*user_id),
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
        }
    }

    fn access(repository_id: RepositoryId, user_id: UserId, role: RepoRole) -> RepoAccess {
        RepoAccess {
            repository_id,
            user_id,
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
        };
        assert_eq!(
            can_write_repository(&actor, &private, Some(&owner)).unwrap_err(),
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
        };

        assert!(can_write_repository(&actor, &repo_a, Some(&grant_a)).is_ok());
        assert_eq!(
            can_write_repository(&actor, &repo_b, Some(&grant_b)).unwrap_err(),
            AuthzError::Forbidden
        );
    }
}
