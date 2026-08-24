use crate::ids::{RepositoryId, UserId};

/// Who owns a repository. `User` is the only reachable variant until
/// organizations exist (plan.local.md §17 Phase 7) — kept as an enum now,
/// not a plain `UserId` column, so that a future `Organization` variant is
/// an additive change to this type rather than a breaking one everywhere
/// `RepositoryOwner` is matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepositoryOwner {
    User(UserId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    Public,
    Private,
}

impl Visibility {
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Visibility::Public => "public",
            Visibility::Private => "private",
        }
    }

    pub fn from_db_str(value: &str) -> Option<Self> {
        match value {
            "public" => Some(Visibility::Public),
            "private" => Some(Visibility::Private),
            _ => None,
        }
    }
}

impl RepositoryOwner {
    /// `repositories.owner_type`'s stored value — only `"user"` is
    /// reachable until organizations exist (plan.local.md §17 Phase 7).
    pub const fn owner_type_db_str(self) -> &'static str {
        match self {
            RepositoryOwner::User(_) => "user",
        }
    }

    pub fn owner_id(self) -> uuid::Uuid {
        match self {
            RepositoryOwner::User(id) => id.as_uuid(),
        }
    }
}

/// A repository's identity of record — the persisted metadata `edda-db`
/// owns. Its `id`, not its `{owner}/{name}` URL/clone-path form (derived,
/// and could change if the owning account is ever transferred in a later
/// phase), is what every other entity (pull requests, issues, access
/// grants) references. See plan.local.md §4.2/§16 (smell S5) for why this
/// replaced the pre-restructuring filesystem-path-derived identity model.
///
/// Deliberately excludes anything only `gix` can answer (default branch,
/// branch count, emptiness, last commit) — those live in `edda-git`'s own
/// `RepoSummary`, computed live from the actual git repository, and a
/// caller that needs both joins the two rather than this type caching a
/// git-derived value that could drift from the repository it describes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repository {
    pub id: RepositoryId,
    pub owner: RepositoryOwner,
    pub name: String,
    pub description: Option<String>,
    pub visibility: Visibility,
}

impl Repository {
    pub fn is_private(&self) -> bool {
        matches!(self.visibility, Visibility::Private)
    }
}
