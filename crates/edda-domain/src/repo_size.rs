//! Per-repository size accounting. Refreshed by the `UpdateRepoSize` job
//! after every push (a `du`-style walk of the git dir plus the sum of LFS
//! object sizes) and read by the receive path's quota check.

use crate::ids::RepositoryId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepoSize {
    pub repository_id: RepositoryId,
    pub git_bytes: i64,
    pub lfs_bytes: i64,
    pub computed_at: i64,
}

impl RepoSize {
    #[must_use]
    pub fn total_bytes(&self) -> i64 {
        self.git_bytes.saturating_add(self.lfs_bytes)
    }
}

/// Whether accepting `incoming_bytes` more would push a repository
/// currently holding `current_bytes` past `limit_bytes`. A `None` limit
/// (the feature disabled) never rejects; a non-positive limit is treated
/// as "no limit" too, so a misconfigured `0` doesn't wedge every push.
#[must_use]
pub fn push_would_exceed_quota(
    current_bytes: i64,
    incoming_bytes: i64,
    limit_bytes: Option<i64>,
) -> bool {
    match limit_bytes {
        Some(limit) if limit > 0 => current_bytes.saturating_add(incoming_bytes) > limit,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_limit_never_rejects() {
        assert!(!push_would_exceed_quota(1_000_000, 5_000_000, None));
        assert!(!push_would_exceed_quota(1_000_000, 5_000_000, Some(0)));
    }

    #[test]
    fn a_push_that_crosses_the_limit_is_rejected() {
        assert!(!push_would_exceed_quota(900, 99, Some(1000)));
        assert!(!push_would_exceed_quota(900, 100, Some(1000)));
        assert!(push_would_exceed_quota(900, 101, Some(1000)));
    }
}
