//! End-to-end integration tests: a real `russh` client, over a real
//! loopback TCP connection, driving the real `SshServer`/`Connection`
//! this crate ships — no external `ssh`/`git` binary, no mocked
//! transport. This is the SSH-transport equivalent of `edda_git::protocol`'s
//! own `build_pack_excluding_omits_objects_reachable_from_haves` test: real
//! Rust components (`russh`, `gix`, an in-memory `sqlx` pool), a temporary
//! repo directory, no network beyond loopback.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use gix_object::Kind;
use russh::keys::{Algorithm, HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::server::{Config as ServerConfig, Server as _};
use russh::{client, ChannelMsg};

use edda_auth::AuthorizationService;
use edda_db::{RepoAccessRepo, RepositoryRepo, SshKeyRepo, UserRepo};
use edda_domain::{RepoRole, Repository, RepositoryId, RepositoryOwner, UserId, Visibility};
use edda_git::pack::{parse_pack, write_loose_object};
use edda_git::pktline::{read_pkt_line, write_flush, write_pkt_line, PktLine};
use edda_git::store::RepoStore;
use edda_git::LockRegistry;

use crate::{SshServer, SshState};

/// A `RepoStore` rooted at a fresh temp directory, matching
/// `LocalFsStore`'s own `{root}/{owner}/{repo}.git` layout — duplicated
/// rather than reused because `LocalFsStore`'s fields are private and it
/// only ever builds from `EDDA_DATA_DIR`, which a parallel test suite must
/// not touch (see `edda_git::store`'s own test module for the same
/// reasoning).
struct TestStore {
    root: PathBuf,
}

impl RepoStore for TestStore {
    fn repo_dir(&self, name: &str) -> PathBuf {
        match name.split_once('/') {
            Some((owner, repo)) => self.root.join(owner).join(format!("{repo}.git")),
            None => self.root.join(format!("{name}.git")),
        }
    }

    fn list_repo_names(&self) -> std::io::Result<Vec<String>> {
        Ok(Vec::new())
    }
}

impl Drop for TestStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Writes a minimal, real commit object directly (same technique as
/// `edda_git::protocol`'s own test fixture) into a fresh bare repo, and
/// points `refs/heads/main` at it so `advertised_refs` has something to
/// advertise.
fn seed_repo(store: &TestStore, identity: &str) -> gix::ObjectId {
    let git_dir = store.repo_dir(identity);
    if let Some(parent) = git_dir.parent() {
        std::fs::create_dir_all(parent).expect("create repo's parent (owner) directory");
    }
    gix::init_bare(&git_dir).expect("init bare repo");

    let empty_tree = write_loose_object(&git_dir, Kind::Tree, b"").expect("write empty tree");
    let commit_body = format!(
        "tree {empty_tree}\nauthor Test <test@example.com> 1700000000 +0000\ncommitter Test <test@example.com> 1700000000 +0000\n\ninitial commit\n"
    );
    let commit =
        write_loose_object(&git_dir, Kind::Commit, commit_body.as_bytes()).expect("write commit");

    std::fs::write(
        git_dir.join("refs").join("heads").join("main"),
        format!("{commit}\n"),
    )
    .expect("write ref");

    commit
}

fn generate_keypair() -> PrivateKey {
    PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("generate test keypair")
}

struct TestServer {
    addr: std::net::SocketAddr,
    handle: russh::server::RunningServerHandle,
    task: tokio::task::JoinHandle<()>,
}

impl TestServer {
    async fn start(state: SshState) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral loopback port");
        let addr = listener.local_addr().expect("local addr");

        let config = Arc::new(ServerConfig {
            keys: vec![generate_keypair()],
            inactivity_timeout: Some(Duration::from_secs(10)),
            auth_rejection_time: Duration::from_millis(50),
            ..Default::default()
        });

        // `run_on_socket` borrows both the server and the listener for the
        // lifetime of the returned future, which rules out spawning it as
        // a `'static` task the ordinary way (with `server`/`listener` kept
        // in the outer scope). Moving both into the spawned task instead —
        // and handing the `RunningServerHandle` back out through a oneshot
        // — keeps everything the future borrows owned by that same task.
        let (handle_tx, handle_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let mut server = SshServer { state };
            let running = server.run_on_socket(config, &listener);
            let _ = handle_tx.send(running.handle());
            let _ = running.await;
        });
        let handle = handle_rx
            .await
            .expect("server task reports its shutdown handle");

        Self { addr, handle, task }
    }

    async fn stop(self) {
        self.handle.shutdown("test finished".to_string());
        let _ = self.task.await;
    }
}

struct AcceptAnyServerKey;

impl client::Handler for AcceptAnyServerKey {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

async fn connect(addr: std::net::SocketAddr) -> client::Handle<AcceptAnyServerKey> {
    let config = Arc::new(client::Config::default());
    client::connect(config, addr, AcceptAnyServerKey)
        .await
        .expect("ssh handshake")
}

async fn authenticate(session: &mut client::Handle<AcceptAnyServerKey>, key: &PrivateKey) -> bool {
    let hash = session
        .best_supported_rsa_hash()
        .await
        .ok()
        .flatten()
        .flatten();
    session
        .authenticate_publickey(
            "git",
            PrivateKeyWithHashAlg::new(Arc::new(key.clone()), hash),
        )
        .await
        .expect("auth request")
        .success()
}

/// Runs an exec command to completion over a fresh channel, returning
/// everything written to stdout, everything written to stderr, and the
/// exit status (if the server sent one before closing).
async fn exec(
    session: &mut client::Handle<AcceptAnyServerKey>,
    command: &str,
    to_send: Option<Vec<u8>>,
) -> (Vec<u8>, Vec<u8>, Option<u32>) {
    let mut channel = session.channel_open_session().await.expect("open channel");
    channel.exec(true, command).await.expect("exec request");

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit_status = None;
    let mut sent = to_send.is_none();

    loop {
        let Some(msg) = channel.wait().await else {
            break;
        };
        match msg {
            ChannelMsg::Data { data } => {
                stdout.extend_from_slice(&data);
                // Send the client's half (want/have/done) right after the
                // first chunk of server data (the ref advertisement) —
                // mirrors a real client, which reads the advertisement
                // before writing its request.
                if !sent {
                    if let Some(body) = &to_send {
                        channel
                            .data_bytes(body.clone())
                            .await
                            .expect("send request body");
                    }
                    sent = true;
                }
            }
            ChannelMsg::ExtendedData { data, .. } => stderr.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status: code } => exit_status = Some(code),
            ChannelMsg::Eof | ChannelMsg::Close => {}
            _ => {}
        }
    }

    (stdout, stderr, exit_status)
}

/// Splits a ref-advertisement-then-pack-response byte stream at the first
/// flush pkt-line, returning (everything up to and including the flush,
/// everything after).
fn split_at_first_flush(data: &[u8]) -> (&[u8], &[u8]) {
    let mut pos = 0;
    loop {
        match read_pkt_line(data, &mut pos) {
            Some(PktLine::Flush) => return (&data[..pos], &data[pos..]),
            Some(PktLine::Data(_)) => continue,
            None => panic!("no flush pkt-line found in {data:?}"),
        }
    }
}

async fn seeded_state(store_root_suffix: &str) -> (SshState, TestStore, UserId, PrivateKey) {
    let pool = edda_db::test_pool().await;

    let user_id = UserId::new();
    UserRepo::insert(
        &pool,
        user_id,
        "alice",
        "alice@example.com",
        "not-a-real-hash",
    )
    .await
    .expect("insert test user");

    let key = generate_keypair();
    let public_key = key
        .public_key()
        .to_openssh()
        .expect("openssh-encode public key");
    let fingerprint = public_key
        .parse::<russh::keys::PublicKey>()
        .expect("reparse openssh public key")
        .fingerprint(HashAlg::Sha256)
        .to_string();
    SshKeyRepo::insert(
        &pool,
        edda_domain::SshKeyId::new(),
        user_id,
        &fingerprint,
        &public_key,
        "test key",
    )
    .await
    .expect("register test key");

    let store = TestStore {
        root: std::env::temp_dir().join(format!(
            "edda-ssh-test-{store_root_suffix}-{}",
            std::process::id()
        )),
    };
    let _ = std::fs::remove_dir_all(&store.root);

    let state = SshState {
        pool: pool.clone(),
        store: Arc::new(TestStore {
            root: store.root.clone(),
        }),
        locks: Arc::new(LockRegistry::new()),
        authz: AuthorizationService::new(pool),
        max_repo_size_bytes: None,
    };

    (state, store, user_id, key)
}

#[tokio::test]
async fn an_unregistered_key_is_rejected() {
    let (state, _store, _owner, _registered_key) = seeded_state("unregistered-key").await;
    let server = TestServer::start(state).await;

    let mut session = connect(server.addr).await;
    let stranger_key = generate_keypair();
    assert!(
        !authenticate(&mut session, &stranger_key).await,
        "an unregistered key must not authenticate"
    );

    server.stop().await;
}

#[tokio::test]
async fn upload_pack_over_ssh_streams_a_real_pack_for_an_authorized_read() {
    let (state, store, owner, key) = seeded_state("upload-pack-ok").await;
    let commit = seed_repo(&store, "alice/demo");

    let repo_id = RepositoryId::new();
    RepositoryRepo::insert(
        &state.pool,
        &Repository {
            id: repo_id,
            owner: RepositoryOwner::User(owner),
            name: "demo".to_string(),
            description: None,
            visibility: Visibility::Public,
            forked_from: None,
        },
    )
    .await
    .expect("insert repository");
    RepoAccessRepo::grant_owner(
        &state.pool,
        repo_id,
        edda_domain::AccessSubject::User(owner),
    )
    .await
    .expect("grant owner");

    let server = TestServer::start(state).await;
    let mut session = connect(server.addr).await;
    assert!(
        authenticate(&mut session, &key).await,
        "the registered key must authenticate"
    );

    let mut request = Vec::new();
    write_pkt_line(&mut request, format!("want {commit}\n").as_bytes());
    write_flush(&mut request);
    write_pkt_line(&mut request, b"done\n");

    let (stdout, stderr, exit_status) = exec(
        &mut session,
        "git-upload-pack '/alice/demo.git'",
        Some(request),
    )
    .await;

    assert_eq!(
        exit_status,
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&stderr)
    );

    let (ref_advertisement, rest) = split_at_first_flush(&stdout);
    let advertised = String::from_utf8_lossy(ref_advertisement);
    assert!(
        advertised.contains(&commit.to_string()),
        "advertisement should list the seeded commit: {advertised}"
    );

    // `rest` is "NAK\n" as one pkt-line, then the raw pack bytes.
    let mut pos = 0;
    let nak = read_pkt_line(rest, &mut pos).expect("NAK line");
    assert_eq!(nak, PktLine::Data(b"NAK\n"));
    let pack_bytes = &rest[pos..];

    let repo = gix::open(store.root.join("alice").join("demo.git")).expect("open seeded repo");
    let objects = parse_pack(&repo, pack_bytes).expect("the response is a well-formed pack");
    assert!(
        objects
            .iter()
            .any(|object| object.id == commit && object.kind == Kind::Commit),
        "pack should contain the seeded commit"
    );

    server.stop().await;
}

#[tokio::test]
async fn upload_pack_over_ssh_hides_a_private_repo_the_actor_cannot_read() {
    let (state, store, owner, key) = seeded_state("upload-pack-private").await;
    seed_repo(&store, "alice/secret");

    // A second user owns "alice/secret" and holds the only grant on it —
    // `owner`'s own key is used to authenticate (any registered key will
    // do; what matters is which *user* the request resolves to), but the
    // repository belongs to this other user, so `owner` has no access
    // grant on it.
    let other_owner = UserId::new();
    UserRepo::insert(
        &state.pool,
        other_owner,
        "bob",
        "bob@example.com",
        "not-a-real-hash",
    )
    .await
    .expect("insert second test user");
    let repo_id = RepositoryId::new();
    RepositoryRepo::insert(
        &state.pool,
        &Repository {
            id: repo_id,
            owner: RepositoryOwner::User(other_owner),
            name: "secret".to_string(),
            description: None,
            visibility: Visibility::Private,
            forked_from: None,
        },
    )
    .await
    .expect("insert repository");
    RepoAccessRepo::grant_owner(
        &state.pool,
        repo_id,
        edda_domain::AccessSubject::User(other_owner),
    )
    .await
    .expect("grant owner");
    let _ = owner;

    let server = TestServer::start(state).await;
    let mut session = connect(server.addr).await;
    assert!(authenticate(&mut session, &key).await);

    let (_stdout, stderr, exit_status) =
        exec(&mut session, "git-upload-pack '/alice/secret.git'", None).await;

    assert_eq!(exit_status, Some(1));
    assert_eq!(stderr, b"fatal: repository not found\n");

    server.stop().await;
}

#[tokio::test]
async fn upload_pack_over_ssh_rejects_a_nonexistent_repository_identically_to_a_hidden_one() {
    let (state, _store, _owner, key) = seeded_state("upload-pack-missing").await;

    let server = TestServer::start(state).await;
    let mut session = connect(server.addr).await;
    assert!(authenticate(&mut session, &key).await);

    let (_stdout, stderr, exit_status) = exec(
        &mut session,
        "git-upload-pack '/alice/does-not-exist.git'",
        None,
    )
    .await;

    assert_eq!(exit_status, Some(1));
    // Byte-for-byte the same message as the "exists but hidden" case above
    // — an attacker on the wire must not be able to distinguish the two.
    assert_eq!(stderr, b"fatal: repository not found\n");

    server.stop().await;
}

#[tokio::test]
async fn receive_pack_over_ssh_rejects_a_write_without_permission() {
    let (state, store, owner, key) = seeded_state("receive-pack-forbidden").await;
    seed_repo(&store, "alice/demo");

    let repo_id = RepositoryId::new();
    RepositoryRepo::insert(
        &state.pool,
        &Repository {
            id: repo_id,
            owner: RepositoryOwner::User(owner),
            name: "demo".to_string(),
            description: None,
            visibility: Visibility::Public,
            forked_from: None,
        },
    )
    .await
    .expect("insert repository");
    // Read-only grant, not owner/write — a push must still be rejected.
    RepoAccessRepo::grant(
        &state.pool,
        repo_id,
        edda_domain::AccessSubject::User(owner),
        RepoRole::Read,
    )
    .await
    .expect("grant read");

    let server = TestServer::start(state).await;
    let mut session = connect(server.addr).await;
    assert!(authenticate(&mut session, &key).await);

    let (_stdout, stderr, exit_status) =
        exec(&mut session, "git-receive-pack '/alice/demo.git'", None).await;

    assert_eq!(exit_status, Some(1));
    assert_eq!(stderr, b"fatal: repository not found\n");

    server.stop().await;
}
