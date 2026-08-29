//! Edda's pure functional core: entities, invariants, and the
//! authorization/business-rule decisions built on top of them. No I/O, no
//! framework types — see this crate's `Cargo.toml` for the dependency
//! rule that keeps it that way.

pub mod access;
pub mod branch_protection;
pub mod deploy_key;
pub mod event;
pub mod ids;
pub mod issue;
pub mod job;
pub mod lfs;
pub mod mention;
pub mod notification;
pub mod oauth_identity;
pub mod organization;
pub mod pull_request;
pub mod release;
pub mod repository;
pub mod ssh_key;
pub mod team;
pub mod token;
pub mod user;
pub mod validation;
pub mod webhook;

pub use access::{
    can_administer_repository, can_manage_repository_danger_zone, can_merge_pull_request,
    can_open_cross_repo_pull_request, can_read_repository, can_write_repository,
    require_instance_admin, AccessSubject, ActorContext, AuthzError, RepoAccess, RepoRole,
    RepositoryScope, TokenScope,
};
pub use branch_protection::BranchProtectionRule;
pub use deploy_key::DeployKey;
pub use event::{DomainEvent, DomainEventKind, MentionSource};
pub use ids::{
    AccessTokenId, AuditEventId, BranchProtectionRuleId, DeployKeyId, EventId, IssueCommentId,
    IssueId, JobId, LabelId, LfsLockId, MilestoneId, NotificationId, OAuthIdentityId,
    OrganizationId, PasswordResetTokenId, PrCommentId, PrReviewId, PullRequestId, ReleaseAssetId,
    ReleaseId, RepositoryId, SshKeyId, TeamId, TotpRecoveryCodeId, UserId, WebauthnCredentialId,
    WebhookDeliveryId, WebhookId,
};
pub use issue::{
    labels_to_unapply_for_scope, scope_of, Issue, IssueComment, IssueState, Label, Milestone,
    MilestoneState,
};
pub use job::{next_retry_at, JobKind, JobPayload, JobRecord, JobStatus};
pub use lfs::{LfsLock, LfsObject};
pub use mention::parse_mentions;
pub use notification::{Notification, NotificationKind, NotificationSubject};
pub use oauth_identity::OAuthIdentity;
pub use organization::Organization;
pub use pull_request::{
    latest_reviews, parse_head_ref, CloseReason, DiffAnchor, MergeStrategy, PrComment, PrRef,
    PrReview, PrState, PullRequest, ReviewState,
};
pub use release::{Release, ReleaseAsset};
pub use repository::{Repository, RepositoryOwner, Visibility};
pub use ssh_key::SshKey;
pub use team::{
    effective_repo_role, Team, TeamMember, TeamPermission, TeamUnit, TeamUnitPermission,
};
pub use token::AccessToken;
pub use user::User;
pub use webhook::{is_blocked_ip, Webhook, WebhookDelivery, WebhookEvent};
