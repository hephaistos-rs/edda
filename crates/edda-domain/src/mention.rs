//! Pure `@username` mention parsing, shared by any comment surface that
//! wants to fan out `DomainEvent::UserMentioned` — deliberately no I/O
//! (resolving a parsed username to a real, existing `UserId` is the
//! caller's job, via `edda-db`), so the parsing rule itself is unit
//! testable without a database.

/// Every distinct `@username`-shaped token in `text`, in first-seen order,
/// lowercased (usernames are case-insensitive throughout this workspace —
/// same assumption `edda_domain::validation::is_valid_username` encodes).
/// A username's valid charset (`validation::is_valid_username`) is a
/// subset of what this scans for, so a caller resolving these against
/// real accounts naturally drops anything that was never a valid username
/// to begin with — this function doesn't need to duplicate that
/// validation itself.
///
/// An `@` is only a mention start if the byte immediately before it is
/// *not* alphanumeric (start of text, or preceded by whitespace/
/// punctuation) — otherwise `me@example.com` would parse `example` as a
/// mention, which it plainly isn't.
pub fn parse_mentions(text: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut mentions = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let preceded_by_alphanumeric = i > 0 && bytes[i - 1].is_ascii_alphanumeric();
        if bytes[i] == b'@' && !preceded_by_alphanumeric {
            let start = i + 1;
            let mut end = start;
            while end < bytes.len()
                && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'-' || bytes[end] == b'_')
            {
                end += 1;
            }
            if end > start {
                let username = text[start..end].to_lowercase();
                if seen.insert(username.clone()) {
                    mentions.push(username);
                }
                i = end;
                continue;
            }
        }
        i += 1;
    }
    mentions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_mentions_from_prose() {
        assert_eq!(
            parse_mentions("hey @alice, can @bob take a look?"),
            vec!["alice".to_string(), "bob".to_string()]
        );
    }

    #[test]
    fn is_case_insensitive_and_deduplicates() {
        assert_eq!(
            parse_mentions("@Alice already reviewed this, thanks @alice"),
            vec!["alice".to_string()]
        );
    }

    #[test]
    fn a_bare_at_sign_with_no_username_produces_nothing() {
        assert_eq!(
            parse_mentions("me@example.com or just @ alone"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn no_mentions_in_plain_text() {
        assert_eq!(parse_mentions("no mentions here"), Vec::<String>::new());
    }
}
