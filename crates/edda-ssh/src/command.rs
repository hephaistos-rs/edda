//! Parses the exec-request command string a git-over-SSH client sends,
//! e.g. `git-upload-pack '/alice/myrepo.git'`. This is SSH-exec-command
//! framing specifically — genuinely distinct from the git wire protocol
//! itself (which starts only *after* this command selects a service and a
//! repository), so it belongs here, not in `edda-git::protocol`.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitService {
    UploadPack,
    ReceivePack,
}

pub struct GitCommand {
    pub service: GitService,
    /// The `{owner}/{repo}` identity, already split from the client's
    /// `/owner/repo.git` (or `owner/repo.git`, or `owner/repo`) path form
    /// — leading slash and trailing `.git` both stripped the same way
    /// `edda-http`'s URL-segment handling does, so both transports resolve
    /// to the exact same identity for the exact same repository.
    pub owner: String,
    pub name: String,
}

/// `data` is the raw exec-request payload (not a pkt-line — SSH's own
/// `exec` channel request carries this as a plain length-prefixed SSH
/// string, already unwrapped by `russh` before `Handler::exec_request`
/// sees it).
pub fn parse(data: &[u8]) -> Option<GitCommand> {
    let text = std::str::from_utf8(data).ok()?;
    let text = text.trim();

    let (service, rest) = if let Some(rest) = text.strip_prefix("git-upload-pack") {
        (GitService::UploadPack, rest)
    } else {
        let rest = text.strip_prefix("git-receive-pack")?;
        (GitService::ReceivePack, rest)
    };

    let path = rest.trim();
    // Real git clients quote the path (`'...'` almost always, sometimes
    // `"..."`) — strip a single matching pair if present, otherwise take
    // the argument as-is.
    let path = match (path.chars().next(), path.chars().next_back()) {
        (Some('\''), Some('\'')) | (Some('"'), Some('"')) if path.len() >= 2 => {
            &path[1..path.len() - 1]
        }
        _ => path,
    };
    let path = path.strip_prefix('/').unwrap_or(path);
    let path = path.strip_suffix(".git").unwrap_or(path);

    let (owner, name) = path.split_once('/')?;
    if owner.is_empty() || name.is_empty() || name.contains('/') {
        return None;
    }

    Some(GitCommand {
        service,
        owner: owner.to_string(),
        name: name.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_quoted_upload_pack_command() {
        let cmd = parse(b"git-upload-pack '/alice/myrepo.git'").unwrap();
        assert_eq!(cmd.service, GitService::UploadPack);
        assert_eq!(cmd.owner, "alice");
        assert_eq!(cmd.name, "myrepo");
    }

    #[test]
    fn parses_double_quoted_receive_pack_command() {
        let cmd = parse(b"git-receive-pack \"/bob/other-repo.git\"").unwrap();
        assert_eq!(cmd.service, GitService::ReceivePack);
        assert_eq!(cmd.owner, "bob");
        assert_eq!(cmd.name, "other-repo");
    }

    #[test]
    fn parses_unquoted_path_without_leading_slash_or_git_suffix() {
        let cmd = parse(b"git-upload-pack alice/myrepo").unwrap();
        assert_eq!(cmd.owner, "alice");
        assert_eq!(cmd.name, "myrepo");
    }

    #[test]
    fn rejects_unknown_commands() {
        assert!(parse(b"/bin/sh -c 'rm -rf /'").is_none());
        assert!(parse(b"git-upload-archive '/alice/myrepo.git'").is_none());
    }

    #[test]
    fn rejects_a_path_missing_the_owner_segment() {
        assert!(parse(b"git-upload-pack '/myrepo.git'").is_none());
    }
}
