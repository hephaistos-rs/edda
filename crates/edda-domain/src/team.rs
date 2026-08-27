//! Teams: an organization's unit of grouped repository access. A team
//! grants its members a default `RepoRole` on every repository it's
//! attached to (via a `repo_access` row targeting `AccessSubject::Team`,
//! `edda_domain::access`), overridable per `TeamUnit` — only the `Code`
//! unit is currently wired into repository authorization (see
//! `Team::code_role`); the rest of the unit list exists so a later change
//! scoping team access to issues/PRs/releases individually is additive,
//! not a schema change.

use crate::access::RepoRole;
use crate::ids::{OrganizationId, TeamId, UserId};

/// A team's default permission level, and the value a `TeamUnitPermission`
/// override is drawn from. Widened from `RepoRole` with an extra `None`
/// variant — unlike a repository access grant (which only exists when
/// there's something to grant), a team can legitimately have no default
/// repository access at all (e.g. an organization's Wiki-only team).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TeamPermission {
    None,
    Read,
    Write,
    Admin,
}

impl TeamPermission {
    pub const fn as_db_str(self) -> &'static str {
        match self {
            TeamPermission::None => "none",
            TeamPermission::Read => "read",
            TeamPermission::Write => "write",
            TeamPermission::Admin => "admin",
        }
    }

    pub fn from_db_str(value: &str) -> Option<Self> {
        match value {
            "none" => Some(TeamPermission::None),
            "read" => Some(TeamPermission::Read),
            "write" => Some(TeamPermission::Write),
            "admin" => Some(TeamPermission::Admin),
            _ => None,
        }
    }

    /// The `RepoRole` this permission level maps to for repository-access
    /// purposes — `None` grants nothing. There is no `Admin -> RepoRole::
    /// Owner` mapping: a team is never the sole `Owner` of a repository it
    /// merely has admin-level access to (see `RepositoryRepo::
    /// insert_with_owner_team`'s own doc comment for which team actually
    /// gets the `Owner` grant on an organization-owned repository).
    pub const fn as_repo_role(self) -> Option<RepoRole> {
        match self {
            TeamPermission::None => None,
            TeamPermission::Read => Some(RepoRole::Read),
            TeamPermission::Write => Some(RepoRole::Write),
            TeamPermission::Admin => Some(RepoRole::Admin),
        }
    }
}

/// Forgejo's per-team resource-unit list — modeled in full even though
/// only `Code` is currently wired into an actual authorization decision
/// (see this module's own doc comment).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeamUnit {
    Code,
    Issues,
    PullRequests,
    Releases,
    Wiki,
    Projects,
    Packages,
    Actions,
}

impl TeamUnit {
    pub const fn as_db_str(self) -> &'static str {
        match self {
            TeamUnit::Code => "code",
            TeamUnit::Issues => "issues",
            TeamUnit::PullRequests => "pull_requests",
            TeamUnit::Releases => "releases",
            TeamUnit::Wiki => "wiki",
            TeamUnit::Projects => "projects",
            TeamUnit::Packages => "packages",
            TeamUnit::Actions => "actions",
        }
    }

    pub fn from_db_str(value: &str) -> Option<Self> {
        match value {
            "code" => Some(TeamUnit::Code),
            "issues" => Some(TeamUnit::Issues),
            "pull_requests" => Some(TeamUnit::PullRequests),
            "releases" => Some(TeamUnit::Releases),
            "wiki" => Some(TeamUnit::Wiki),
            "projects" => Some(TeamUnit::Projects),
            "packages" => Some(TeamUnit::Packages),
            "actions" => Some(TeamUnit::Actions),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Team {
    pub id: TeamId,
    pub organization_id: OrganizationId,
    pub name: String,
    pub permission: TeamPermission,
}

impl Team {
    /// The `RepoRole` this team grants its members on a repository it's
    /// attached to — the `Code`-unit override if one has been set,
    /// otherwise the team's own default `permission`. Resolved once, at
    /// the moment a team is attached to a repository (`edda-db`'s
    /// `RepoAccessRepo::grant` for a `Team` subject stores this value
    /// directly, the same as a direct user grant would) — not
    /// re-evaluated live against the team's *current* settings on every
    /// access check, so a permission change made after attachment takes
    /// effect on repositories the team is attached to *after* that
    /// change, not retroactively. Re-attaching (or an explicit "sync"
    /// action, not currently built) is how an existing attachment picks
    /// up a later permission change.
    pub fn code_role(&self, code_unit_override: Option<TeamPermission>) -> Option<RepoRole> {
        code_unit_override.unwrap_or(self.permission).as_repo_role()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TeamUnitPermission {
    pub team_id: TeamId,
    pub unit: TeamUnit,
    pub permission: TeamPermission,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TeamMember {
    pub team_id: TeamId,
    pub user_id: UserId,
}

/// The role a repository-access decision is made against: the maximum of
/// any direct grant a user holds and any grant reachable through team
/// membership — still a pure function once both are already fetched
/// (`edda-auth::AuthorizationService` assembles them from `edda-db`, per
/// `edda_domain::access`'s own "fetch, then decide" split; this is the
/// team-aware extension of that split).
pub fn effective_repo_role(direct: Option<RepoRole>, team_grants: &[RepoRole]) -> Option<RepoRole> {
    team_grants.iter().copied().chain(direct).max()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn team_permission_orders_low_to_high() {
        assert!(TeamPermission::None < TeamPermission::Read);
        assert!(TeamPermission::Read < TeamPermission::Write);
        assert!(TeamPermission::Write < TeamPermission::Admin);
    }

    #[test]
    fn team_permission_none_grants_no_repo_role() {
        assert_eq!(TeamPermission::None.as_repo_role(), None);
        assert_eq!(TeamPermission::Write.as_repo_role(), Some(RepoRole::Write));
    }

    #[test]
    fn a_code_unit_override_takes_priority_over_the_team_default() {
        let team = Team {
            id: TeamId::new(),
            organization_id: OrganizationId::new(),
            name: "docs".to_string(),
            permission: TeamPermission::Read,
        };
        assert_eq!(team.code_role(None), Some(RepoRole::Read));
        assert_eq!(
            team.code_role(Some(TeamPermission::Write)),
            Some(RepoRole::Write)
        );
        assert_eq!(team.code_role(Some(TeamPermission::None)), None);
    }

    #[test]
    fn effective_role_is_the_maximum_of_direct_and_every_team_grant() {
        assert_eq!(effective_repo_role(None, &[]), None);
        assert_eq!(
            effective_repo_role(Some(RepoRole::Read), &[]),
            Some(RepoRole::Read)
        );
        assert_eq!(
            effective_repo_role(None, &[RepoRole::Write, RepoRole::Read]),
            Some(RepoRole::Write)
        );
        assert_eq!(
            effective_repo_role(Some(RepoRole::Write), &[RepoRole::Owner]),
            Some(RepoRole::Owner)
        );
        assert_eq!(
            effective_repo_role(Some(RepoRole::Admin), &[RepoRole::Read]),
            Some(RepoRole::Admin)
        );
    }
}
