//! Cross-reference parsing (Phase 11): the `#5` and `owner/repo#5` tokens,
//! and the issue-closing keywords (`closes #5`, `fixes owner/repo#5`), that
//! appear in issue / pull-request / comment bodies.
//!
//! Pure text analysis and nothing more — resolving a parsed reference to a
//! real repository and issue, rendering it as a link, and closing it when
//! a pull request merges are all the caller's job (`edda-app`'s services),
//! so the parsing rule stays unit-testable with no database. Mirrors
//! [`crate::mention`]'s hand-rolled, dependency-free approach.
//!
//! References inside inline code spans (`` `#5` ``) and fenced code blocks
//! (```` ``` ````/`~~~`) are ignored, matching how a Markdown renderer
//! would treat them.

/// One `#N` or `owner/repo#N` reference found in a body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossReference {
    /// `Some((owner, repo))` for a fully-qualified `owner/repo#5`; `None`
    /// for a bare `#5`, which resolves within the repository the text
    /// belongs to.
    pub repository: Option<(String, String)>,
    /// The issue / pull-request number. Always `>= 1`.
    pub number: i64,
}

/// The keywords that, when they immediately precede a reference, mark the
/// referenced issue to be closed once a pull request carrying the text
/// merges. The full GitHub/GitLab set, lower-cased.
const CLOSING_KEYWORDS: &[&str] = &[
    "close", "closes", "closed", "fix", "fixes", "fixed", "resolve", "resolves", "resolved",
];

struct Ref {
    start: usize,
    end: usize,
    cref: CrossReference,
}

fn is_name_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_'
}

/// Reads an ASCII digit run at `start`, returning `(number, end)` when it
/// is a clean `>= 1` integer not glued to a trailing word character
/// (`#5x` is not a reference). Digit runs longer than an `i64` can hold
/// are rejected rather than truncated.
fn parse_number(bytes: &[u8], start: usize) -> Option<(i64, usize)> {
    let mut end = start;
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end == start || end - start > 18 {
        return None;
    }
    if let Some(&next) = bytes.get(end) {
        if next.is_ascii_alphanumeric() || next == b'_' {
            return None;
        }
    }
    let number: i64 = std::str::from_utf8(&bytes[start..end]).ok()?.parse().ok()?;
    (number >= 1).then_some((number, end))
}

/// Attempts to read an `owner/repo#N` token starting at `start`.
fn parse_qualified(bytes: &[u8], start: usize) -> Option<Ref> {
    let mut i = start;
    while i < bytes.len() && is_name_char(bytes[i]) {
        i += 1;
    }
    let owner = std::str::from_utf8(&bytes[start..i]).ok()?;
    if owner.is_empty() || bytes.get(i) != Some(&b'/') {
        return None;
    }
    let repo_start = i + 1;
    let mut j = repo_start;
    while j < bytes.len() && is_name_char(bytes[j]) {
        j += 1;
    }
    let repo = std::str::from_utf8(&bytes[repo_start..j]).ok()?;
    if repo.is_empty() || bytes.get(j) != Some(&b'#') {
        return None;
    }
    let (number, end) = parse_number(bytes, j + 1)?;
    Some(Ref {
        start,
        end,
        cref: CrossReference {
            repository: Some((owner.to_string(), repo.to_string())),
            number,
        },
    })
}

/// Every `#N` / `owner/repo#N` reference in `body`, in first-seen order,
/// outside code spans and fenced blocks.
fn scan_refs(body: &str) -> Vec<Ref> {
    let bytes = body.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    let mut in_fence = false;
    let mut in_code_span = false;
    let mut at_line_start = true;
    while i < bytes.len() {
        if bytes[i] == b'\n' {
            in_code_span = false;
            at_line_start = true;
            i += 1;
            continue;
        }
        if at_line_start {
            let mut j = i;
            let mut spaces = 0;
            while j < bytes.len() && bytes[j] == b' ' && spaces < 3 {
                j += 1;
                spaces += 1;
            }
            if bytes[j..].starts_with(b"```") || bytes[j..].starts_with(b"~~~") {
                in_fence = !in_fence;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
        }
        at_line_start = false;
        if in_fence {
            i += 1;
            continue;
        }
        if bytes[i] == b'`' {
            in_code_span = !in_code_span;
            i += 1;
            continue;
        }
        if in_code_span {
            i += 1;
            continue;
        }

        let preceded_by_alnum = i > 0 && bytes[i - 1].is_ascii_alphanumeric();
        if bytes[i] == b'#' && !preceded_by_alnum {
            if let Some((number, end)) = parse_number(bytes, i + 1) {
                out.push(Ref {
                    start: i,
                    end,
                    cref: CrossReference {
                        repository: None,
                        number,
                    },
                });
                i = end;
                continue;
            }
        }
        if is_name_char(bytes[i])
            && !preceded_by_alnum
            && bytes.get(i.wrapping_sub(1)) != Some(&b'/')
        {
            if let Some(found) = parse_qualified(bytes, i) {
                i = found.end;
                out.push(found);
                continue;
            }
        }
        i += 1;
    }
    out
}

/// De-duplicates by `(repository, number)`, keeping first-seen order.
fn dedup(refs: impl IntoIterator<Item = CrossReference>) -> Vec<CrossReference> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for cref in refs {
        if seen.insert((cref.repository.clone(), cref.number)) {
            out.push(cref);
        }
    }
    out
}

/// Every distinct cross-reference in `body` — for auto-linking. Order is
/// first appearance.
pub fn parse_cross_references(body: &str) -> Vec<CrossReference> {
    dedup(scan_refs(body).into_iter().map(|r| r.cref))
}

/// Every cross-reference in `body` with its `start..end` byte span — for a
/// linkifier that rewrites each token in place. Not de-duplicated (each
/// occurrence gets its own span) and in source order.
pub fn parse_cross_reference_spans(body: &str) -> Vec<(std::ops::Range<usize>, CrossReference)> {
    scan_refs(body)
        .into_iter()
        .map(|r| (r.start..r.end, r.cref))
        .collect()
}

/// Whether the text immediately before byte offset `pos` is a closing
/// keyword (optionally followed by a `:`), at a word boundary.
fn closing_keyword_ends_at(bytes: &[u8], pos: usize) -> bool {
    let mut end = pos;
    while end > 0 && matches!(bytes[end - 1], b' ' | b'\t') {
        end -= 1;
    }
    if end > 0 && bytes[end - 1] == b':' {
        end -= 1;
        while end > 0 && matches!(bytes[end - 1], b' ' | b'\t') {
            end -= 1;
        }
    }
    let mut start = end;
    while start > 0 && bytes[start - 1].is_ascii_alphabetic() {
        start -= 1;
    }
    if start == end {
        return false;
    }
    if start > 0 && bytes[start - 1].is_ascii_alphanumeric() {
        return false;
    }
    let word = std::str::from_utf8(&bytes[start..end])
        .unwrap_or("")
        .to_ascii_lowercase();
    CLOSING_KEYWORDS.contains(&word.as_str())
}

/// The references a merging pull request should auto-close: those governed
/// by a closing keyword. Supports the list form (`closes #1, #2 and #3` —
/// all three), where a keyword governs a comma/`and`-separated run of
/// references.
pub fn parse_closing_references(body: &str) -> Vec<CrossReference> {
    let bytes = body.as_bytes();
    let refs = scan_refs(body);
    let mut governed = vec![false; refs.len()];
    for idx in 0..refs.len() {
        if closing_keyword_ends_at(bytes, refs[idx].start) {
            governed[idx] = true;
            continue;
        }
        if idx == 0 || !governed[idx - 1] {
            continue;
        }
        // List continuation: only whitespace and one `,` / `and` between
        // the previous (governed) reference and this one.
        let between = std::str::from_utf8(&bytes[refs[idx - 1].end..refs[idx].start])
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if between == "," || between == "and" || between == ", and" {
            governed[idx] = true;
        }
    }
    dedup(
        refs.into_iter()
            .zip(governed)
            .filter_map(|(r, g)| g.then_some(r.cref)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn same(number: i64) -> CrossReference {
        CrossReference {
            repository: None,
            number,
        }
    }

    fn qualified(owner: &str, repo: &str, number: i64) -> CrossReference {
        CrossReference {
            repository: Some((owner.to_string(), repo.to_string())),
            number,
        }
    }

    #[test]
    fn parses_bare_and_qualified_references_in_first_seen_order() {
        assert_eq!(
            parse_cross_references("see #12, then octo/core#3 and #12 again"),
            vec![same(12), qualified("octo", "core", 3)]
        );
    }

    #[test]
    fn a_hash_glued_to_a_word_or_a_bad_number_is_not_a_reference() {
        assert_eq!(parse_cross_references("id#5 and #5x and # 5"), Vec::new());
        assert_eq!(parse_cross_references("issue #0 is not real"), Vec::new());
    }

    #[test]
    fn references_inside_code_are_ignored() {
        assert_eq!(
            parse_cross_references("real #1 but `#2` is code"),
            vec![same(1)]
        );
        let fenced = "before #1\n```\nnot #2 here\n```\nafter #3";
        assert_eq!(parse_cross_references(fenced), vec![same(1), same(3)]);
    }

    #[test]
    fn closing_keywords_select_only_the_governed_references() {
        assert_eq!(parse_closing_references("Closes #12"), vec![same(12)]);
        assert_eq!(
            parse_closing_references("This fixes: octo/core#7, unrelated #9"),
            vec![qualified("octo", "core", 7)]
        );
        assert_eq!(parse_closing_references("mentions #3 only"), Vec::new());
    }

    #[test]
    fn a_closing_keyword_governs_a_comma_and_list() {
        assert_eq!(
            parse_closing_references("resolves #1, #2 and #3\nplus a stray #4"),
            vec![same(1), same(2), same(3)]
        );
    }

    #[test]
    fn closing_keyword_matching_is_case_insensitive_and_boundary_aware() {
        assert_eq!(parse_closing_references("FIXED #8"), vec![same(8)]);
        // `prefixes` ends in `fixes` but is not a closing keyword.
        assert_eq!(parse_closing_references("prefixes #8"), Vec::new());
    }
}
