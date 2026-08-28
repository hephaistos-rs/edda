//! Issues: `Issue`/`IssueComment`/`Label`/`Milestone`. `Issue` shares its
//! per-repository numbering sequence with `PullRequest` (see that
//! module's doc comment) — `#5` may resolve to either within one
//! repository, matching every mainstream git host's own numbering.

use crate::ids::{IssueCommentId, IssueId, LabelId, MilestoneId, RepositoryId, UserId};
use crate::pull_request::CloseReason;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssueState {
    Open,
    Closed { closed_at: i64, reason: CloseReason },
}

impl IssueState {
    pub fn is_open(&self) -> bool {
        matches!(self, IssueState::Open)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    pub id: IssueId,
    pub repository_id: RepositoryId,
    pub number: i64,
    pub title: String,
    pub body: Option<String>,
    pub author_id: UserId,
    pub state: IssueState,
    pub milestone_id: Option<MilestoneId>,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueComment {
    pub id: IssueCommentId,
    pub issue_id: IssueId,
    pub author_id: UserId,
    pub body: String,
    pub created_at: i64,
}

/// A label applied to issues/pull requests within one repository. Not
/// organization-scoped — kept as a plain `repository_id` column rather
/// than a polymorphic owner pair; widening it later is additive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label {
    pub id: LabelId,
    pub repository_id: RepositoryId,
    pub name: String,
    /// A `#rrggbb`-shaped string, validated by `edda-app` at the API
    /// boundary (this crate has no business rejecting malformed color
    /// strings — it isn't a security or invariant concern here the way
    /// e.g. a username charset is).
    pub color: String,
    pub description: Option<String>,
    pub archived_at: Option<i64>,
}

/// A label's scope: everything before the last `/` in its name, or
/// `None` if it has no `/` at all. Purely derived from `name` — never
/// stored as its own column, so a label rename can't drift the two out
/// of sync (see `at_most_one_label_per_scope`'s use of this).
pub fn scope_of(name: &str) -> Option<&str> {
    name.rfind('/').map(|index| &name[..index])
}

/// Given a set of labels already applied to some issue/PR and a new
/// label about to be applied, returns the ids of already-applied labels
/// that must be removed first — at most one label per scope may be
/// applied at once. Pure: the caller (`edda-db`) does the actual
/// unapply/apply writes; this only decides which ones.
pub fn labels_to_unapply_for_scope<'a>(
    currently_applied: &'a [Label],
    new_label: &Label,
) -> Vec<&'a Label> {
    let Some(new_scope) = scope_of(&new_label.name) else {
        return Vec::new();
    };
    currently_applied
        .iter()
        .filter(|existing| {
            existing.id != new_label.id && scope_of(&existing.name) == Some(new_scope)
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MilestoneState {
    Open,
    Closed,
}

impl MilestoneState {
    pub const fn as_db_str(self) -> &'static str {
        match self {
            MilestoneState::Open => "open",
            MilestoneState::Closed => "closed",
        }
    }

    pub fn from_db_str(value: &str) -> Option<Self> {
        match value {
            "open" => Some(MilestoneState::Open),
            "closed" => Some(MilestoneState::Closed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Milestone {
    pub id: MilestoneId,
    pub repository_id: RepositoryId,
    pub title: String,
    pub description: Option<String>,
    /// Unix-day-seconds, same representation every other timestamp in
    /// this workspace uses — not a `chrono::NaiveDate`, since
    /// `edda-domain` carries no date/time dependency (see this crate's
    /// `Cargo.toml`).
    pub due_on: Option<i64>,
    pub state: MilestoneState,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn label(id: LabelId, name: &str) -> Label {
        Label {
            id,
            repository_id: RepositoryId::new(),
            name: name.to_string(),
            color: "#ffffff".to_string(),
            description: None,
            archived_at: None,
        }
    }

    #[test]
    fn scope_is_everything_before_the_last_slash() {
        assert_eq!(scope_of("priority/high"), Some("priority"));
        assert_eq!(scope_of("area/backend/db"), Some("area/backend"));
        assert_eq!(scope_of("bug"), None);
    }

    #[test]
    fn applying_a_scoped_label_unapplies_any_other_label_in_the_same_scope() {
        let low = label(LabelId::new(), "priority/low");
        let bug = label(LabelId::new(), "bug");
        let high = label(LabelId::new(), "priority/high");

        let currently_applied = vec![low.clone(), bug.clone()];
        let to_unapply = labels_to_unapply_for_scope(&currently_applied, &high);
        assert_eq!(to_unapply, vec![&low]);
    }

    #[test]
    fn an_unscoped_label_never_unapplies_anything() {
        let bug = label(LabelId::new(), "bug");
        let docs = label(LabelId::new(), "docs");
        let currently_applied = vec![bug.clone()];
        assert!(labels_to_unapply_for_scope(&currently_applied, &docs).is_empty());
    }

    #[test]
    fn reapplying_the_same_label_does_not_unapply_itself() {
        let high = label(LabelId::new(), "priority/high");
        let currently_applied = vec![high.clone()];
        assert!(labels_to_unapply_for_scope(&currently_applied, &high).is_empty());
    }
}
