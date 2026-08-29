//! Typed entity identifiers. A newtype per entity so a mixed-up argument
//! order (e.g. passing a repository id where a user id is expected) is a
//! compile error instead of a silently-accepted `String`/`Uuid` swap.
//!
//! Deliberately carries no `sqlx` dependency (see this crate's `Cargo.toml`
//! doc comment) — `edda-db` binds/reads these as `TEXT` and converts at its
//! own boundary via `Display`/`FromStr`, so this type stays usable from
//! anywhere in the workspace without pulling a database driver in with it.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

macro_rules! id_type {
    ($name:ident) => {
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// A fresh, time-ordered (UUIDv7) identifier — see the `users`
            /// migration's own comment for why v7 over a random v4 or a
            /// database `AUTOINCREMENT`: time-ordered without leaking a
            /// guessable sequential count.
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            pub fn from_uuid(id: Uuid) -> Self {
                Self(id)
            }

            pub fn as_uuid(&self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(Self(Uuid::parse_str(s)?))
            }
        }
    };
}

id_type!(UserId);
id_type!(RepositoryId);
id_type!(AccessTokenId);
id_type!(SshKeyId);
id_type!(DeployKeyId);
id_type!(LfsLockId);
id_type!(OAuthIdentityId);
id_type!(WebauthnCredentialId);
id_type!(TotpRecoveryCodeId);
id_type!(PasswordResetTokenId);
id_type!(EmailVerificationTokenId);
id_type!(AuditEventId);
id_type!(PullRequestId);
id_type!(PrReviewId);
id_type!(PrCommentId);
id_type!(IssueId);
id_type!(IssueCommentId);
id_type!(LabelId);
id_type!(MilestoneId);
id_type!(BranchProtectionRuleId);
id_type!(CommitStatusId);
id_type!(ReviewRequestId);
id_type!(ReleaseId);
id_type!(ReleaseAssetId);
id_type!(WebhookId);
id_type!(WebhookDeliveryId);
id_type!(NotificationId);
id_type!(JobId);
id_type!(EventId);
id_type!(OrganizationId);
id_type!(TeamId);
