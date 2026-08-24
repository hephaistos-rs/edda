//! Edda's pure functional core: entities, invariants, and the
//! authorization/business-rule decisions built on top of them. No I/O, no
//! framework types — see this crate's `Cargo.toml` for the dependency
//! rule that keeps it that way. See plan.local.md §2.1/§3.3/§7.

pub mod access;
pub mod ids;
pub mod repository;
pub mod token;
pub mod user;
pub mod validation;

pub use access::{
    can_administer_repository, can_manage_repository_danger_zone, can_read_repository,
    can_write_repository, ActorContext, AuthzError, RepoAccess, RepoRole, RepositoryScope,
};
pub use ids::{AccessTokenId, RepositoryId, UserId};
pub use repository::{Repository, RepositoryOwner, Visibility};
pub use token::AccessToken;
pub use user::User;
