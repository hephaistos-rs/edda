//! Pure name-validation rules shared by account signup (`edda-auth`) and
//! repository naming (`edda-git`), so both consumers stay backed by
//! exactly one definition of "a valid username" / "a valid repository
//! identity."

/// Charset and shape a username (== a repository owner segment, since a
/// repo's `{owner}/{repo}` identity resolves `owner` to an account
/// username) must satisfy: 1-39 ASCII letters, digits, `-` or `_`,
/// starting and ending with a letter or digit. Same bound GitHub uses for
/// logins; starting/ending on an alnum keeps a username unambiguous next
/// to the `/` that separates it from a repo name in a URL.
pub fn is_valid_username(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 39 {
        return false;
    }
    let is_alnum = |b: u8| b.is_ascii_alphanumeric();
    if !is_alnum(bytes[0]) || !is_alnum(bytes[bytes.len() - 1]) {
        return false;
    }
    bytes.iter().all(|&b| is_alnum(b) || b == b'-' || b == b'_')
}

/// Validates the `{repo}` segment of a `{owner}/{repo}` identity. Repo
/// names become directory names under the git store's root, so this is a
/// security boundary, not just validation: reject anything that could
/// escape the root (`.`, `..`, path separators) or collide with the
/// `.git` suffix the store appends.
pub fn is_valid_repository_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 100
        && name != "."
        && name != ".."
        && !name.starts_with('.')
        && !name.ends_with(".git")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

/// Splits a `{owner}/{repo}` identity string into its two segments,
/// requiring exactly one `/`.
pub fn split_owner_repo(identity: &str) -> Option<(&str, &str)> {
    let (owner, repo) = identity.split_once('/')?;
    if repo.contains('/') {
        return None;
    }
    Some((owner, repo))
}

/// Validates a full `{owner}/{repo}` identity string (used by `edda-git`
/// before it ever meets the filesystem, and by anything resolving a
/// clone-path URL segment back into an owner/repo pair).
pub fn is_valid_repository_identity(identity: &str) -> bool {
    match split_owner_repo(identity) {
        Some((owner, repo)) => is_valid_username(owner) && is_valid_repository_name(repo),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_usernames() {
        assert!(is_valid_username("alice"));
        assert!(is_valid_username("a"));
        assert!(is_valid_username("alice-bob"));
        assert!(is_valid_username("alice_bob"));
        assert!(is_valid_username("a1"));
        assert!(is_valid_username(&"a".repeat(39)));
    }

    #[test]
    fn invalid_usernames() {
        assert!(!is_valid_username(""));
        assert!(!is_valid_username(&"a".repeat(40)));
        assert!(!is_valid_username("-alice"));
        assert!(!is_valid_username("alice-"));
        assert!(!is_valid_username("_alice"));
        assert!(!is_valid_username("alice_"));
        assert!(!is_valid_username("alice bob"));
        assert!(!is_valid_username("alice.bob"));
        assert!(!is_valid_username("alice/bob"));
        assert!(!is_valid_username("alïce"));
    }

    #[test]
    fn valid_owner_repo_identities() {
        assert!(is_valid_repository_identity("alice/my-repo"));
        assert!(is_valid_repository_identity("alice/my.repo_1"));
        assert!(is_valid_repository_identity("a/b"));
        assert!(is_valid_repository_identity(&format!(
            "alice/{}",
            "a".repeat(100)
        )));
    }

    #[test]
    fn invalid_owner_repo_identities() {
        assert!(!is_valid_repository_identity("my-repo"));
        assert!(!is_valid_repository_identity(""));
        assert!(!is_valid_repository_identity("/my-repo"));
        assert!(!is_valid_repository_identity("alice/"));
        assert!(!is_valid_repository_identity("alice/sub/my-repo"));
        assert!(!is_valid_repository_identity("-alice/my-repo"));
        assert!(!is_valid_repository_identity("al ice/my-repo"));
        assert!(!is_valid_repository_identity(&format!(
            "{}/repo",
            "a".repeat(40)
        )));
        assert!(!is_valid_repository_identity("alice/."));
        assert!(!is_valid_repository_identity("alice/.."));
        assert!(!is_valid_repository_identity("alice/.hidden"));
        assert!(!is_valid_repository_identity("alice/repo.git"));
        assert!(!is_valid_repository_identity("alice/repo name"));
        assert!(!is_valid_repository_identity(&format!(
            "alice/{}",
            "a".repeat(101)
        )));
    }
}
