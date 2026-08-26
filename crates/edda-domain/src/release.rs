//! Releases: a named, optionally-published snapshot of one commit, plus
//! the binary assets attached to it. `target_commit` is resolved and
//! stored once at creation time — a tag can move (retagging), a release
//! must not silently follow it, matching real-world release semantics
//! (a published release is an immutable reference point, not a live view
//! of wherever its tag currently points).

use crate::ids::{ReleaseAssetId, ReleaseId, RepositoryId, UserId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub id: ReleaseId,
    pub repository_id: RepositoryId,
    pub tag_name: String,
    /// The commit `tag_name` pointed at when this release was created —
    /// see this module's doc comment for why it's captured, not derived
    /// live from the tag on every read.
    pub target_commit: String,
    pub name: String,
    /// Markdown, rendered at read time — same convention as every other
    /// long-form text field in this workspace (`PullRequest::body`,
    /// `Issue::body`).
    pub body: Option<String>,
    pub draft: bool,
    pub prerelease: bool,
    /// `None` while `draft` — a draft release is only visible to
    /// collaborators with write access, matching Forgejo's own confirmed
    /// draft-release visibility model.
    pub published_at: Option<i64>,
    pub author_id: UserId,
    pub created_at: i64,
}

impl Release {
    /// A draft release is a collaborator-only staging area; anyone who can
    /// read the repository may see a published (non-draft) one, regardless
    /// of `prerelease` (a prerelease is still a real, publicly visible
    /// release — only `draft` gates visibility).
    pub fn is_visible_to_readers(&self) -> bool {
        !self.draft
    }
}

/// One binary file attached to a release. `storage_key` is an opaque
/// filesystem-relative path (mirroring `LfsObject::storage_key`'s own
/// pattern) — this crate never assumes anything about the storage layer
/// beyond "some string `edda-git`'s `RepoStore` can resolve."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseAsset {
    pub id: ReleaseAssetId,
    pub release_id: ReleaseId,
    pub filename: String,
    pub size_bytes: i64,
    /// The uploader's claimed content type — stored for display only.
    /// Never trusted for how Edda itself serves the file back (see
    /// `edda_http`'s release-asset download handler): a client-supplied
    /// `Content-Type` of `text/html` must not make Edda serve the asset in
    /// a way a browser would render as HTML.
    pub content_type: String,
    pub storage_key: String,
    pub created_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(draft: bool) -> Release {
        Release {
            id: ReleaseId::new(),
            repository_id: RepositoryId::new(),
            tag_name: "v1.0.0".to_string(),
            target_commit: "a".repeat(40),
            name: "v1.0.0".to_string(),
            body: None,
            draft,
            prerelease: false,
            published_at: if draft { None } else { Some(0) },
            author_id: UserId::new(),
            created_at: 0,
        }
    }

    #[test]
    fn only_a_non_draft_release_is_visible_to_ordinary_readers() {
        assert!(!release(true).is_visible_to_readers());
        assert!(release(false).is_visible_to_readers());
    }
}
