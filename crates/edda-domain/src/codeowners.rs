//! CODEOWNERS parsing and matching — pure. A repository's CODEOWNERS file
//! maps path patterns to the accounts responsible for them; on a push to
//! a pull request's source branch, the receive path turns a match against
//! the PR's changed files into an automatic review request (Phase 10; the
//! management UI is Phase 11).
//!
//! Supported pattern syntax is the practical subset git hosts share:
//! `*` (matches within a path segment), `**` (matches across segments),
//! a leading `/` anchors to the repo root, a trailing `/` matches a
//! directory and everything under it, and a bare name matches that name
//! anywhere. Owners are whitespace-separated `@login` tokens (team
//! (`@org/team`) and raw-email owners are parsed but resolution of them
//! is left to the caller, which only knows how to map a bare `@login`).
//! **Last** matching rule wins, as in git.

/// One `(pattern, owners)` line from a CODEOWNERS file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeOwnersRule {
    pub pattern: String,
    /// Owner tokens with the leading `@` stripped (`alice`, `org/reviewers`).
    pub owners: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CodeOwners {
    rules: Vec<CodeOwnersRule>,
}

impl CodeOwners {
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let mut rules = Vec::new();
        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut tokens = line.split_whitespace();
            let Some(pattern) = tokens.next() else {
                continue;
            };
            let owners: Vec<String> = tokens
                .filter_map(|token| token.strip_prefix('@').map(str::to_string))
                .collect();
            if owners.is_empty() {
                continue;
            }
            rules.push(CodeOwnersRule {
                pattern: pattern.to_string(),
                owners,
            });
        }
        Self { rules }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The owners for `path` — the owners of the **last** rule that
    /// matches, matching git's "last rule wins" precedence. Empty if no
    /// rule matches.
    #[must_use]
    pub fn owners_for(&self, path: &str) -> &[String] {
        self.rules
            .iter()
            .rev()
            .find(|rule| pattern_matches(&rule.pattern, path))
            .map_or(&[], |rule| rule.owners.as_slice())
    }

    /// Every distinct owner login across the last-matching rule for each
    /// path in `paths`, in first-seen order.
    #[must_use]
    pub fn owners_for_paths(&self, paths: &[String]) -> Vec<String> {
        let mut seen = Vec::new();
        for path in paths {
            for owner in self.owners_for(path) {
                if !seen.contains(owner) {
                    seen.push(owner.clone());
                }
            }
        }
        seen
    }
}

/// Whether a CODEOWNERS `pattern` matches repo-relative `path` (no
/// leading slash). See the module docs for the supported subset.
fn pattern_matches(pattern: &str, path: &str) -> bool {
    let anchored = pattern.starts_with('/');
    let dir_pattern = pattern.ends_with('/');
    let core = pattern.trim_start_matches('/').trim_end_matches('/');

    if dir_pattern {
        // `foo/` (or `/foo/`) — the directory and everything under it.
        return if anchored {
            path == core || path.starts_with(&format!("{core}/"))
        } else {
            path == core
                || path.starts_with(&format!("{core}/"))
                || path.contains(&format!("/{core}/"))
                || path.ends_with(&format!("/{core}"))
        };
    }

    if anchored {
        return glob_segmented(core.as_bytes(), path.as_bytes());
    }
    // Unanchored: match the whole path, or any trailing path suffix that
    // begins at a segment boundary.
    let core = core.as_bytes();
    let path = path.as_bytes();
    if glob_segmented(core, path) {
        return true;
    }
    for (idx, byte) in path.iter().enumerate() {
        if *byte == b'/' && glob_segmented(core, &path[idx + 1..]) {
            return true;
        }
    }
    false
}

/// Glob match where `*` does not cross `/` but `**` does; every other byte
/// is literal. Recursive backtracking — CODEOWNERS lines and paths are
/// short.
fn glob_segmented(pattern: &[u8], text: &[u8]) -> bool {
    match pattern {
        [] => text.is_empty(),
        // `**/rest` matches `rest` in this directory or any below it —
        // including the root, so it may consume zero path segments.
        [b'*', b'*', b'/', rest @ ..] => {
            glob_segmented(rest, text) || (!text.is_empty() && glob_segmented(pattern, &text[1..]))
        }
        // A trailing `**` matches the rest of the path, separators included.
        [b'*', b'*'] => true,
        [b'*', rest @ ..] => {
            glob_segmented(rest, text)
                || (!text.is_empty() && text[0] != b'/' && glob_segmented(pattern, &text[1..]))
        }
        [b'?', rest @ ..] => {
            !text.is_empty() && text[0] != b'/' && glob_segmented(rest, &text[1..])
        }
        [b, rest @ ..] => text.first() == Some(b) && glob_segmented(rest, &text[1..]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lines_owners_and_comments() {
        let text = "\
# top level
*         @default-owner
/docs/    @tech-writers @alice
src/*.rs  @rustaceans
";
        let owners = CodeOwners::parse(text);
        assert_eq!(owners.owners_for("README.md"), ["default-owner"]);
        assert_eq!(
            owners.owners_for("docs/guide.md"),
            ["tech-writers", "alice"]
        );
        assert_eq!(owners.owners_for("src/main.rs"), ["rustaceans"]);
        // `src/*.rs` does not cross a directory boundary.
        assert_eq!(owners.owners_for("src/net/main.rs"), ["default-owner"]);
    }

    #[test]
    fn last_matching_rule_wins() {
        let owners = CodeOwners::parse("*.rs @all\nsrc/critical.rs @alice\n");
        assert_eq!(owners.owners_for("src/critical.rs"), ["alice"]);
        assert_eq!(owners.owners_for("src/other.rs"), ["all"]);
    }

    #[test]
    fn double_star_crosses_directories() {
        let owners = CodeOwners::parse("/apps/**/config.toml @ops\n");
        assert_eq!(owners.owners_for("apps/web/config.toml"), ["ops"]);
        assert_eq!(owners.owners_for("apps/web/deep/config.toml"), ["ops"]);
        // `**/` also matches zero directories (git semantics).
        assert_eq!(owners.owners_for("apps/config.toml"), ["ops"]);
        assert!(owners.owners_for("apps/web/other.toml").is_empty());
    }

    #[test]
    fn owners_for_paths_dedupes_in_first_seen_order() {
        let owners = CodeOwners::parse("* @a\ndocs/ @b\n");
        let reviewers = owners.owners_for_paths(&[
            "docs/x.md".to_string(),
            "src/y.rs".to_string(),
            "docs/z.md".to_string(),
        ]);
        assert_eq!(reviewers, vec!["b".to_string(), "a".to_string()]);
    }

    #[test]
    fn an_empty_file_matches_nothing() {
        let owners = CodeOwners::parse("\n  \n# just a comment\n");
        assert!(owners.is_empty());
        assert!(owners.owners_for("anything").is_empty());
    }
}
