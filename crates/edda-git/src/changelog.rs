//! Auto-changelog for releases (Phase 11): the commits a release's target
//! adds over the previous tag, grouped by Conventional-Commit type, as a
//! Markdown fragment. Pure history inspection built on
//! [`crate::history::added_commits`].

use crate::history::added_commits;
use crate::{open_repo_dir, GitError};

/// One line of a generated changelog.
pub struct ChangelogEntry {
    /// The display heading this entry falls under ("Features", "Bug
    /// Fixes", …).
    pub group: &'static str,
    /// The commit's summary line, with any `type(scope):` prefix stripped.
    pub summary: String,
    /// The abbreviated commit id.
    pub short_id: String,
}

/// Groups in the order they should appear in the rendered changelog.
const GROUP_ORDER: &[&str] = &[
    "Features",
    "Bug Fixes",
    "Performance",
    "Documentation",
    "Refactoring",
    "Tests",
    "Chores",
    "Other Changes",
];

/// Maps a Conventional-Commit `type` to its changelog heading; unknown or
/// prefix-less commits land in "Other Changes".
fn group_for(summary: &str) -> (&'static str, &str) {
    let Some((prefix, rest)) = summary.split_once(':') else {
        return ("Other Changes", summary);
    };
    // Strip an optional `(scope)` and a trailing `!` (breaking-change mark).
    let kind = prefix
        .split_once('(')
        .map_or(prefix, |(k, _)| k)
        .trim_end_matches('!')
        .trim()
        .to_ascii_lowercase();
    let heading = match kind.as_str() {
        "feat" => "Features",
        "fix" => "Bug Fixes",
        "perf" => "Performance",
        "docs" => "Documentation",
        "refactor" => "Refactoring",
        "test" => "Tests",
        "chore" | "build" | "ci" | "style" => "Chores",
        _ => return ("Other Changes", summary),
    };
    (heading, rest.trim())
}

/// The changelog entries between `from_rev` (exclusive — the previous
/// release's tag or commit; `None` for the repository's whole history) and
/// `to_rev` (inclusive — the new release's target), newest commit first.
pub fn changelog_entries(
    store: &dyn crate::store::RepoStore,
    name: &str,
    from_rev: Option<&str>,
    to_rev: &str,
) -> Result<Vec<ChangelogEntry>, GitError> {
    let repo = open_repo_dir(store, name)?;
    let to_id = repo
        .rev_parse_single(to_rev)
        .map_err(|err| GitError::Git(err.to_string()))?
        .detach();
    let from_hex = match from_rev {
        Some(rev) => repo
            .rev_parse_single(rev)
            .map_err(|err| GitError::Git(err.to_string()))?
            .detach()
            .to_string(),
        None => String::new(),
    };

    let added = added_commits(&repo, &from_hex, &to_id.to_string())?;
    let mut entries = Vec::new();
    for id in added.commits {
        let Ok(object) = repo.find_object(id) else {
            continue;
        };
        let Ok(commit) = object.try_into_commit() else {
            continue;
        };
        let Ok(message) = commit.message() else {
            continue;
        };
        // Skip merge commits — they add no reviewable change of their own.
        if commit.parent_ids().count() > 1 {
            continue;
        }
        let summary = message.summary().to_string();
        let (group, cleaned) = group_for(&summary);
        entries.push(ChangelogEntry {
            group,
            summary: cleaned.to_string(),
            short_id: id.to_string().chars().take(9).collect(),
        });
    }
    Ok(entries)
}

/// The generated changelog as a Markdown fragment (`### Heading` sections
/// with `- summary (`abcdef012`)` bullets), or an empty string when there
/// are no non-merge commits in the range.
pub fn changelog_markdown(
    store: &dyn crate::store::RepoStore,
    name: &str,
    from_rev: Option<&str>,
    to_rev: &str,
) -> Result<String, GitError> {
    let entries = changelog_entries(store, name, from_rev, to_rev)?;
    if entries.is_empty() {
        return Ok(String::new());
    }
    let mut out = String::new();
    for heading in GROUP_ORDER {
        let group: Vec<&ChangelogEntry> = entries.iter().filter(|e| e.group == *heading).collect();
        if group.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&format!("### {heading}\n\n"));
        for entry in group {
            out.push_str(&format!("- {} (`{}`)\n", entry.summary, entry.short_id));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{LocalFsStore, RepoStore};
    use crate::{create_repo, force_set_ref, LockRegistry};

    fn tmp(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "edda-git-changelog-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn commit(repo: &gix::Repository, parents: &[gix::ObjectId], msg: &str) -> gix::ObjectId {
        let tree = repo
            .write_object(gix_object::Tree::empty())
            .unwrap()
            .detach();
        let sig = gix_actor::Signature {
            name: "t".into(),
            email: "t@e".into(),
            time: gix::date::Time::new(1_700_000_000, 0),
        };
        repo.write_object(gix_object::Commit {
            tree,
            parents: parents.iter().copied().collect(),
            author: sig.clone(),
            committer: sig,
            encoding: None,
            message: msg.into(),
            extra_headers: Vec::new(),
        })
        .unwrap()
        .detach()
    }

    #[tokio::test]
    async fn the_changelog_groups_conventional_commits_since_the_previous_tag() {
        let root = tmp("groups");
        let store = LocalFsStore::new(root.clone());
        let locks = LockRegistry::new();
        create_repo(&store, &locks, "alice/demo").await.unwrap();
        let repo = gix::open(store.repo_dir("alice/demo")).unwrap();

        let c1 = commit(&repo, &[], "chore: scaffold");
        let c2 = commit(&repo, &[c1], "feat: add the thing");
        let c3 = commit(&repo, &[c2], "fix(parser): handle empty input");
        let c4 = commit(&repo, &[c3], "just some text");
        force_set_ref(&repo, "refs/heads/main", c4).unwrap();

        // Everything since `c1` (exclusive): c2 feat, c3 fix, c4 other.
        let md = changelog_markdown(&store, "alice/demo", Some(&c1.to_string()), "main").unwrap();
        assert!(md.contains("### Features\n\n- add the thing"), "{md}");
        assert!(md.contains("### Bug Fixes\n\n- handle empty input"), "{md}");
        assert!(md.contains("### Other Changes\n\n- just some text"), "{md}");
        assert!(!md.contains("scaffold"), "c1 is excluded: {md}");
        // Features come before Bug Fixes come before Other Changes.
        let f = md.find("Features").unwrap();
        let b = md.find("Bug Fixes").unwrap();
        let o = md.find("Other Changes").unwrap();
        assert!(f < b && b < o);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_range_with_only_merge_commits_produces_an_empty_changelog() {
        let root = tmp("merges");
        let store = LocalFsStore::new(root.clone());
        let locks = LockRegistry::new();
        create_repo(&store, &locks, "alice/demo").await.unwrap();
        let repo = gix::open(store.repo_dir("alice/demo")).unwrap();

        let base = commit(&repo, &[], "feat: base");
        let a = commit(&repo, &[base], "feat: side");
        let merge = commit(&repo, &[base, a], "Merge branch 'side'");
        // Rewrite so the merge is the only commit past `a`.
        force_set_ref(&repo, "refs/heads/main", merge).unwrap();

        let md = changelog_markdown(&store, "alice/demo", Some(&a.to_string()), "main").unwrap();
        assert_eq!(md, "");

        let _ = std::fs::remove_dir_all(&root);
    }
}
