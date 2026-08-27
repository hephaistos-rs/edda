use crate::ids::{OrganizationId, RepositoryId, UserId};

/// Who owns a repository — an individual account, or an `Organization`.
/// Kept as an enum, not a plain id column, so an owner that's neither or
/// ambiguously both is unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepositoryOwner {
    User(UserId),
    Organization(OrganizationId),
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
    /// `repositories.owner_type`'s stored value.
    pub const fn owner_type_db_str(self) -> &'static str {
        match self {
            RepositoryOwner::User(_) => "user",
            RepositoryOwner::Organization(_) => "organization",
        }
    }

    pub fn owner_id(self) -> uuid::Uuid {
        match self {
            RepositoryOwner::User(id) => id.as_uuid(),
            RepositoryOwner::Organization(id) => id.as_uuid(),
        }
    }
}

/// A repository's identity of record — the persisted metadata `edda-db`
/// owns. Its `id`, not its `{owner}/{name}` URL/clone-path form (derived,
/// and could change if the owning account is ever transferred), is what
/// every other entity (pull requests, issues, access
/// grants) references — a stable identity that survives an owner rename
/// or transfer, unlike a filesystem-path-derived identity would.
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
    /// The repository this one was forked from, if any. One-directional
    /// only ("what is this a fork of," not "list every fork of X" — an
    /// index on this column would support that query too, if it becomes
    /// a real need); the fork itself is otherwise an ordinary independent
    /// `Repository` row with its own access grants.
    pub forked_from: Option<RepositoryId>,
}

impl Repository {
    pub fn is_private(&self) -> bool {
        matches!(self.visibility, Visibility::Private)
    }
}
