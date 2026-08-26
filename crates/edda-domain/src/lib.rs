//! Edda's pure functional core: entities, invariants, and the
//! authorization/business-rule decisions built on top of them. No I/O, no
//! framework types — see this crate's `Cargo.toml` for the dependency
//! rule that keeps it that way.

pub mod access;
pub mod branch_protection;
pub mod ids;
pub mod issue;
pub mod lfs;
pub mod oauth_identity;
pub mod pull_request;
pub mod repository;
pub mod ssh_key;
pub mod token;
pub mod user;
pub mod validation;

pub use access::{
    can_administer_repository, can_manage_repository_danger_zone, can_merge_pull_request,
    can_read_repository, can_write_repository, require_instance_admin, ActorContext, AuthzError,
    RepoAccess, RepoRole, RepositoryScope,
};
pub use branch_protection::BranchProtectionRule;
pub use ids::{
    AccessTokenId, AuditEventId, BranchProtectionRuleId, IssueCommentId, IssueId, LabelId,
    LfsLockId, MilestoneId, OAuthIdentityId, PasswordResetTokenId, PrCommentId, PrReviewId,
    PullRequestId, RepositoryId, SshKeyId, TotpRecoveryCodeId, UserId, WebauthnCredentialId,
};
pub use issue::{
    labels_to_unapply_for_scope, scope_of, Issue, IssueComment, IssueState, Label, Milestone,
    MilestoneState,
};
pub use lfs::{LfsLock, LfsObject};
pub use oauth_identity::OAuthIdentity;
pub use pull_request::{
    latest_reviews, CloseReason, DiffAnchor, MergeStrategy, PrComment, PrRef, PrReview, PrState,
    PullRequest, ReviewState,
};
pub use repository::{Repository, RepositoryOwner, Visibility};
pub use ssh_key::SshKey;
pub use token::AccessToken;
pub use user::User;
