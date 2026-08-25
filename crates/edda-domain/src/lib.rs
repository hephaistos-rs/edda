//! Edda's pure functional core: entities, invariants, and the
//! authorization/business-rule decisions built on top of them. No I/O, no
//! framework types — see this crate's `Cargo.toml` for the dependency
//! rule that keeps it that way.

pub mod access;
pub mod ids;
pub mod lfs;
pub mod repository;
pub mod ssh_key;
pub mod token;
pub mod user;
pub mod validation;

pub use access::{
    can_administer_repository, can_manage_repository_danger_zone, can_read_repository,
    can_write_repository, ActorContext, AuthzError, RepoAccess, RepoRole, RepositoryScope,
};
pub use ids::{AccessTokenId, LfsLockId, RepositoryId, SshKeyId, UserId};
pub use lfs::{LfsLock, LfsObject};
pub use repository::{Repository, RepositoryOwner, Visibility};
pub use ssh_key::SshKey;
pub use token::AccessToken;
pub use user::User;
