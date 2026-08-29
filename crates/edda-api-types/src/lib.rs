//! The `/api/v1` wire contract — every request and response DTO shared by
//! the server (`edda-app`, which serializes them) and the web UI
//! (`edda-web`, which deserializes them). One definition per shape, so the
//! two ends cannot drift.
//!
//! This crate is deliberately dependency-free apart from `serde`: it must
//! compile for `wasm32-unknown-unknown` as cheaply as for the server, and
//! `edda-web` depends on it without pulling in a single server-side crate.
//!
//! Nothing here has behaviour. `From<DomainEntity>` conversions live in
//! `edda-app` (which owns both the domain types and these), never here.

#![allow(clippy::module_name_repetitions)]

use serde::{Deserialize, Serialize};

// ─────────────────────────────── errors ───────────────────────────────

/// The body of every non-2xx `/api/v1` response: `{ "error": { "code",
/// "message" } }`. `code` is a stable machine string; `message` is a
/// human sentence safe to show a user (server internals never leak into
/// it — see `edda-app`'s `ServiceError::client_message`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiError {
    pub error: ApiErrorDetail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiErrorDetail {
    pub code: String,
    pub message: String,
}

// ──────────────────────────────── user ────────────────────────────────

/// The signed-in account, as returned by `GET /api/auth/me`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CurrentUser {
    pub id: String,
    pub username: String,
    pub email: String,
    pub is_admin: bool,
}

// ────────────────────────────── repositories ──────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoDto {
    pub owner: String,
    pub name: String,
    pub description: Option<String>,
    pub default_branch: Option<String>,
    pub branch_count: usize,
    pub is_empty: bool,
    pub is_private: bool,
    /// Whether the requesting user owns this repository (drives whether
    /// the UI shows danger-zone settings). `false` for anonymous.
    pub is_owner: bool,
    pub last_commit: Option<CommitDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitDto {
    pub summary: String,
    pub author_name: String,
    pub unix_seconds: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateRepoRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub private: bool,
    /// Organization namespace to create under; `None` → the caller's own.
    #[serde(default)]
    pub owner: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateRepoRequest {
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetVisibilityRequest {
    pub private: bool,
}

/// `POST /api/v1/repos/{owner}/{repo}/fork` — the new fork's location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkedRepoDto {
    pub owner: String,
    pub name: String,
}

// ─────────────────────────── repo browsing ────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeEntryDto {
    pub name: String,
    pub is_dir: bool,
    pub size: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobDto {
    pub name: String,
    pub size: u64,
    pub is_binary: bool,
    pub content: Option<String>,
    /// Server-rendered HTML for `content`: a README gets
    /// markdown-to-sanitized-HTML, any other text file gets syntax
    /// highlighting. `None` for binary content and oversized files (the
    /// UI falls back to plain-text `content`).
    pub rendered_html: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitLogEntryDto {
    pub id: String,
    pub summary: String,
    pub author_name: String,
    pub unix_seconds: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffLineKind {
    Context,
    Added,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffLineDto {
    pub kind: DiffLineKind,
    /// Syntax-highlighted markup for this one line's text (not a whole
    /// `<pre><code>` block — the UI renders each line as its own row).
    pub html: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffHunkDto {
    pub old_start: u32,
    pub old_lines: u32,
    pub new_start: u32,
    pub new_lines: u32,
    pub lines: Vec<DiffLineDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDiffDto {
    pub old_path: Option<String>,
    pub new_path: Option<String>,
    pub is_binary: bool,
    /// The file was renamed/copied (`old_path` differs from `new_path`);
    /// `hunks` still carries any content change.
    #[serde(default)]
    pub is_rename: bool,
    /// The file is too large to diff — `hunks` is empty and the UI shows
    /// "diff too large" instead.
    #[serde(default)]
    pub is_too_large: bool,
    pub hunks: Vec<DiffHunkDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchMatchDto {
    pub path: String,
    pub line_number: u32,
    pub line: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlameHunkDto {
    /// 1-based first line of the run.
    pub start_line: u32,
    pub line_count: u32,
    pub commit_id: String,
    pub summary: String,
    pub author_name: String,
    pub author_unix_seconds: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlameDto {
    /// In file order; the hunks partition `1..=lines.len()`.
    pub hunks: Vec<BlameHunkDto>,
    /// The blamed file's lines (newline-stripped) — one per blamed line.
    pub lines: Vec<String>,
}

// ─────────────────────────── pull requests ────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullRequestDto {
    pub number: i64,
    pub title: String,
    pub body_html: Option<String>,
    pub author_username: String,
    /// The account that owns the repository the source branch lives in.
    /// Equal to the target repository's owner for a same-repository PR;
    /// different for a cross-repository (fork-sourced) one — the UI shows
    /// `{source_owner}:{source_branch}` when it differs.
    pub source_owner: String,
    pub source_branch: String,
    pub target_branch: String,
    /// `true` when the source branch lives in a *different* repository
    /// than the target (a fork-sourced pull request).
    pub is_cross_repo: bool,
    pub state: PrStateDto,
    pub created_at: i64,
}

/// Internally tagged on `status` (`open` / `draft` / `merged` / `closed`)
/// so the wire form is a flat object the UI matches on directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PrStateDto {
    Open,
    Draft,
    Merged {
        merged_at: i64,
        merge_commit: String,
    },
    Closed {
        closed_at: i64,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrCommentDto {
    pub author_username: String,
    pub body_html: String,
    pub anchor_file_path: Option<String>,
    pub anchor_line_start: Option<u32>,
    pub anchor_line_end: Option<u32>,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrReviewDto {
    pub reviewer_username: String,
    pub state: String,
    pub body_html: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullRequestDetailDto {
    pub pull_request: PullRequestDto,
    pub comments: Vec<PrCommentDto>,
    pub reviews: Vec<PrReviewDto>,
    /// Whether the caller may currently merge this PR — resolved
    /// server-side (branch protection, review count, write access) so the
    /// UI never reimplements that decision.
    pub can_merge: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatePullRequest {
    pub title: String,
    #[serde(default)]
    pub body: Option<String>,
    /// The account owning the fork the source branch lives in, for a
    /// cross-repository pull request. `None` (or equal to the target
    /// owner) means a same-repository PR. `source_branch` may also carry
    /// the `owner:branch` form, which the server splits when this is unset.
    #[serde(default)]
    pub source_owner: Option<String>,
    pub source_branch: String,
    pub target_branch: String,
    #[serde(default)]
    pub draft: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommentAnchorInput {
    pub file_path: String,
    pub line_start: u32,
    pub line_end: u32,
    pub commit_sha: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddCommentRequest {
    pub body: String,
    #[serde(default)]
    pub anchor: Option<CommentAnchorInput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitReviewRequest {
    /// `approved` / `changes_requested` / `commented`.
    pub state: String,
    #[serde(default)]
    pub body: Option<String>,
}

/// `POST` endpoints that open a numbered entity (PR, issue) answer with
/// its new per-repository number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatedNumberDto {
    pub number: i64,
}

/// `POST /api/v1/repos/{owner}/{repo}/pulls/{number}/merge`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergedPullDto {
    pub merge_commit: String,
}

// ────────────────────────── branch protection ─────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchProtectionDto {
    pub id: String,
    /// A branch-name glob (`main`, `release/*`). Field kept as `branch`
    /// for wire stability even though it is matched as a pattern.
    pub branch: String,
    pub required_approvals: i64,
    pub require_linear_history: bool,
    pub require_signed_commits: bool,
    pub dismiss_stale_reviews: bool,
    pub require_up_to_date: bool,
    /// External CI check contexts that must each be green before a PR
    /// targeting a matched branch may merge.
    pub required_status_checks: Vec<String>,
    /// Usernames allowed to push directly to a matched branch despite the
    /// rule (team allowlist entries are surfaced separately once the
    /// Phase 11 UI lands).
    pub push_allowlist_usernames: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateBranchProtectionRequest {
    pub branch: String,
    #[serde(default)]
    pub required_approvals: i64,
    #[serde(default)]
    pub require_linear_history: bool,
    #[serde(default)]
    pub require_signed_commits: bool,
    #[serde(default)]
    pub dismiss_stale_reviews: bool,
    #[serde(default)]
    pub require_up_to_date: bool,
    #[serde(default)]
    pub required_status_checks: Vec<String>,
    #[serde(default)]
    pub push_allowlist_usernames: Vec<String>,
}

// ─────────────────────────────── issues ───────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueDto {
    pub number: i64,
    pub title: String,
    pub body_html: Option<String>,
    pub author_username: String,
    pub state: IssueStateDto,
    pub milestone_title: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum IssueStateDto {
    Open,
    Closed { closed_at: i64, reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueCommentDto {
    pub author_username: String,
    pub body_html: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabelDto {
    pub id: String,
    pub name: String,
    pub color: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MilestoneDto {
    pub id: String,
    pub title: String,
    pub description: Option<String>,
    pub due_on: Option<i64>,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueDetailDto {
    pub issue: IssueDto,
    pub comments: Vec<IssueCommentDto>,
    pub labels: Vec<LabelDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateIssueRequest {
    pub title: String,
    #[serde(default)]
    pub body: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BodyRequest {
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateLabelRequest {
    pub name: String,
    pub color: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyLabelRequest {
    pub label_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateMilestoneRequest {
    pub title: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub due_on: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetMilestoneRequest {
    #[serde(default)]
    pub milestone_id: Option<String>,
}

// ────────────────────────────── releases ──────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseAssetDto {
    pub filename: String,
    pub size_bytes: i64,
    pub content_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseDto {
    pub tag_name: String,
    pub target_commit: String,
    pub name: String,
    pub body_html: Option<String>,
    pub draft: bool,
    pub prerelease: bool,
    pub published_at: Option<i64>,
    pub author_username: String,
    pub created_at: i64,
    pub assets: Vec<ReleaseAssetDto>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseFlags {
    pub draft: bool,
    pub prerelease: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateReleaseRequest {
    pub tag_name: String,
    /// Branch or commit the tag should point at if it doesn't exist yet.
    pub target: String,
    pub title: String,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub prerelease: bool,
}

/// `POST /api/v1/repos/{owner}/{repo}/releases` answers with the tag it
/// created or resolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatedReleaseDto {
    pub tag_name: String,
}

// ────────────────────────────── webhooks ──────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookDto {
    pub id: String,
    pub target_url: String,
    pub events: Vec<String>,
    pub active: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookDeliveryDto {
    pub event: String,
    pub response_status: Option<i32>,
    pub attempt_count: i32,
    pub delivered: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateWebhookRequest {
    pub target_url: String,
    /// Wire event names, e.g. `pull_request.merged`.
    pub events: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatedWebhookDto {
    pub id: String,
    /// Shown once — the caller must copy it now.
    pub secret: String,
}

// ─────────────────────────── orgs & teams ─────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationDto {
    pub name: String,
    pub display_name: Option<String>,
    /// Whether the requesting user administers this organization (member
    /// of its Owners team). `false` for anonymous.
    pub is_admin: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateOrgRequest {
    pub name: String,
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamDto {
    pub name: String,
    pub permission: String,
    pub code_permission_override: Option<String>,
    pub members: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamSummaryDto {
    pub name: String,
    pub permission: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamGrantDto {
    pub team_name: String,
    pub role: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateTeamRequest {
    pub name: String,
    /// A `TeamPermission` db string (`read` / `write` / `admin`).
    pub permission: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionRequest {
    pub permission: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberRequest {
    pub username: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachTeamRequest {
    pub team_org: String,
    pub team_name: String,
}

// ──────────────────────────── collaborators ───────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollaboratorDto {
    pub user_id: String,
    pub email: String,
    pub role: String,
    pub added_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddCollaboratorRequest {
    pub email: String,
}

// ──────────────────────────── deploy keys ─────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeployKeyDto {
    pub id: String,
    pub fingerprint: String,
    pub public_key: String,
    pub title: String,
    pub read_only: bool,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateDeployKeyRequest {
    pub title: String,
    pub public_key: String,
    /// Default `true` — a deploy key is read-only unless asked otherwise.
    #[serde(default = "default_true")]
    pub read_only: bool,
}

fn default_true() -> bool {
    true
}

// ──────────────────────────── notifications ───────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationDto {
    pub id: String,
    pub kind: String,
    pub subject_type: String,
    pub subject_id: String,
    pub read: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailNotificationsRequest {
    pub enabled: bool,
}
