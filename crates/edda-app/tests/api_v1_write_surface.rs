//! `/api/v1` write surface: drives the ported endpoints through the real
//! `edda_app::router` over a real HTTP server with a bearer token — one
//! per area, plus the auth negatives (no token → 401, a non-collaborator
//! → 403/404). The Dioxus server functions still exist and still serve the
//! UI; this proves the additive `/api/v1` surface works on its own.

use std::net::SocketAddr;
use std::sync::Arc;

use edda_app::{router, AppState};
use edda_auth::{tokens, AuthorizationService, Backend};
use edda_db::{RepoAccessRepo, RepositoryRepo, UserRepo};
use edda_domain::{
    AccessSubject, RepoRole, Repository, RepositoryId, RepositoryOwner, UserId, Visibility,
};
use edda_git::store::{LocalFsStore, RepoStore};
use edda_git::LockRegistry;
use serde_json::json;

async fn spawn_server(state: AppState) -> SocketAddr {
    let session_pool = sqlx::SqlitePool::connect("sqlite::memory:")
        .await
        .expect("session pool");
    let session_store = tower_sessions_sqlx_store::SqliteStore::new(session_pool);
    session_store
        .migrate()
        .await
        .expect("migrate session store");
    let session_layer = tower_sessions::SessionManagerLayer::new(session_store);
    let backend = state.backend.clone();
    let auth_layer = axum_login::AuthManagerLayerBuilder::new(backend, session_layer).build();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let app = router(state).layer(auth_layer);
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    addr
}

fn temp_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "edda-app-api-v1-write-it-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

struct Harness {
    base: String,
    client: reqwest::Client,
    token: String,
    other_token: String,
    pool: edda_db::DbPool,
    store: Arc<dyn RepoStore>,
    locks: Arc<LockRegistry>,
    alice: UserId,
    _store_root: std::path::PathBuf,
}

impl Harness {
    async fn new() -> Self {
        // Webhook creation encrypts its signing secret at rest.
        edda_auth::secret_box::init(Some([0x11; 32]));
        let pool = edda_db::test_pool().await;
        let store_root = temp_dir();
        let store: Arc<dyn RepoStore> = Arc::new(LocalFsStore::new(store_root.clone()));
        let locks = Arc::new(LockRegistry::new());

        let alice = UserId::new();
        UserRepo::insert(&pool, alice, "alice", "alice@example.com", "x")
            .await
            .unwrap();
        let (token, _) = tokens::create(&pool, alice, "ci").await.unwrap();

        let mallory = UserId::new();
        UserRepo::insert(&pool, mallory, "mallory", "mallory@example.com", "x")
            .await
            .unwrap();
        let (other_token, _) = tokens::create(&pool, mallory, "ci").await.unwrap();

        let state = AppState {
            pool: pool.clone(),
            store: store.clone(),
            locks: locks.clone(),
            authz: AuthorizationService::new(pool.clone()),
            backend: Backend::new(pool.clone()),
            config: Default::default(),
        };
        let addr = spawn_server(state).await;
        Self {
            base: format!("http://{addr}"),
            client: reqwest::Client::new(),
            token,
            other_token,
            pool,
            store,
            locks,
            alice,
            _store_root: store_root,
        }
    }

    async fn make_repo(&self, name: &str) -> RepositoryId {
        edda_git::create_repo(self.store.as_ref(), &self.locks, &format!("alice/{name}"))
            .await
            .unwrap();
        let repo = Repository {
            id: RepositoryId::new(),
            owner: RepositoryOwner::User(self.alice),
            name: name.to_string(),
            description: None,
            visibility: Visibility::Public,
            forked_from: None,
        };
        RepositoryRepo::insert_with_owner(&self.pool, &repo, self.alice)
            .await
            .unwrap();
        repo.id
    }

    fn post(&self, path: &str) -> reqwest::RequestBuilder {
        self.client
            .post(format!("{}{path}", self.base))
            .bearer_auth(&self.token)
    }
    fn put(&self, path: &str) -> reqwest::RequestBuilder {
        self.client
            .put(format!("{}{path}", self.base))
            .bearer_auth(&self.token)
    }
    fn delete(&self, path: &str) -> reqwest::RequestBuilder {
        self.client
            .delete(format!("{}{path}", self.base))
            .bearer_auth(&self.token)
    }
    fn get(&self, path: &str) -> reqwest::RequestBuilder {
        self.client
            .get(format!("{}{path}", self.base))
            .bearer_auth(&self.token)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_repository_write_endpoints_round_trip() {
    let h = Harness::new().await;

    // create
    let r = h
        .post("/api/v1/repos")
        .json(&json!({ "name": "proj", "description": "a demo", "private": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "{}", r.text().await.unwrap());
    edda_git::create_repo(h.store.as_ref(), &h.locks, "alice/proj")
        .await
        .ok();

    // update description
    assert_eq!(
        h.client
            .patch(format!("{}/api/v1/repos/alice/proj", h.base))
            .bearer_auth(&h.token)
            .json(&json!({ "description": "updated" }))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );

    // set visibility (owner-only)
    assert_eq!(
        h.put("/api/v1/repos/alice/proj/visibility")
            .json(&json!({ "private": true }))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );

    // GET reflects it
    let body: serde_json::Value = h
        .get("/api/v1/repos/alice/proj")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["is_private"], true);
    assert_eq!(body["description"], "updated");

    // delete
    assert_eq!(
        h.delete("/api/v1/repos/alice/proj")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        h.get("/api/v1/repos/alice/proj")
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_issue_lifecycle_endpoints_round_trip() {
    let h = Harness::new().await;
    h.make_repo("bugs").await;

    let n: i64 = h
        .post("/api/v1/repos/alice/bugs/issues")
        .json(&json!({ "title": "boom" }))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap()["number"]
        .as_i64()
        .unwrap();

    assert_eq!(
        h.post(&format!("/api/v1/repos/alice/bugs/issues/{n}/comments"))
            .json(&json!({ "body": "looking into it" }))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        h.post(&format!("/api/v1/repos/alice/bugs/issues/{n}/close"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    // already closed → 409
    assert_eq!(
        h.post(&format!("/api/v1/repos/alice/bugs/issues/{n}/close"))
            .send()
            .await
            .unwrap()
            .status(),
        409
    );
    assert_eq!(
        h.post(&format!("/api/v1/repos/alice/bugs/issues/{n}/reopen"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );

    // labels + milestones
    assert_eq!(
        h.post("/api/v1/repos/alice/bugs/labels")
            .json(&json!({ "name": "urgent", "color": "#ff0000" }))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        h.post("/api/v1/repos/alice/bugs/milestones")
            .json(&json!({ "title": "v1" }))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );

    let detail: serde_json::Value = h
        .get(&format!("/api/v1/repos/alice/bugs/issues/{n}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(detail["issue"]["state"]["status"], "open");
}

/// The `Actor` extractor accepts a session cookie, not only a bearer
/// token: sign up (which establishes a session), then drive a `/api/v1`
/// read and write with the cookie jar alone — no `Authorization` header.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_api_v1_surface_accepts_a_session_cookie() {
    let h = Harness::new().await;

    let jar = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();

    let signup = jar
        .post(format!("{}/api/auth/signup", h.base))
        .json(&json!({
            "username": "carol",
            "email": "carol@example.com",
            "password": "correct horse battery staple"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(signup.status(), 200, "{}", signup.text().await.unwrap());

    // A cookie-authenticated read.
    let repos = jar
        .get(format!("{}/api/v1/repos", h.base))
        .send()
        .await
        .unwrap();
    assert_eq!(repos.status(), 200);

    // A cookie-authenticated write: create a repo under carol's namespace.
    let created = jar
        .post(format!("{}/api/v1/repos", h.base))
        .json(&json!({ "name": "cookie-made" }))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 200, "{}", created.text().await.unwrap());
    let body: serde_json::Value = created.json().await.unwrap();
    assert_eq!(body["owner"], "carol");
    assert_eq!(body["name"], "cookie-made");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pull_request_endpoints_authorize_and_create() {
    let h = Harness::new().await;
    h.make_repo("code").await;

    let n: i64 = h
        .post("/api/v1/repos/alice/code/pulls")
        .json(&json!({
            "title": "a change",
            "source_branch": "feature",
            "target_branch": "main"
        }))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap()["number"]
        .as_i64()
        .unwrap();

    assert_eq!(
        h.post(&format!("/api/v1/repos/alice/code/pulls/{n}/comments"))
            .json(&json!({ "body": "nice" }))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        h.post(&format!("/api/v1/repos/alice/code/pulls/{n}/reviews"))
            .json(&json!({ "state": "approved" }))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        h.post(&format!("/api/v1/repos/alice/code/pulls/{n}/close"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        h.post(&format!("/api/v1/repos/alice/code/pulls/{n}/reopen"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn webhooks_branch_protection_and_collaborators_round_trip() {
    let h = Harness::new().await;
    let repo_id = h.make_repo("infra").await;

    // webhook create (public target — resolve_and_check allows a public
    // hostname literal that never actually connects) then delete
    let created: serde_json::Value = h
        .post("/api/v1/repos/alice/infra/webhooks")
        .json(&json!({
            "target_url": "https://example.com/hook",
            "events": ["pull_request.merged"]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let webhook_id = created["id"].as_str().unwrap();
    assert!(!created["secret"].as_str().unwrap().is_empty());
    assert_eq!(
        h.delete(&format!("/api/v1/repos/alice/infra/webhooks/{webhook_id}"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );

    // branch protection set + delete
    assert_eq!(
        h.put("/api/v1/repos/alice/infra/branch-protection")
            .json(&json!({ "branch": "main", "required_approvals": 1 }))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let rules = edda_db::BranchProtectionRepo::list_for_repository(&h.pool, repo_id)
        .await
        .unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(
        h.delete(&format!(
            "/api/v1/repos/alice/infra/branch-protection/{}",
            rules[0].id
        ))
        .send()
        .await
        .unwrap()
        .status(),
        200
    );

    // collaborator add / list / remove
    let bob = UserId::new();
    UserRepo::insert(&h.pool, bob, "bob", "bob@example.com", "x")
        .await
        .unwrap();
    assert_eq!(
        h.post("/api/v1/repos/alice/infra/collaborators")
            .json(&json!({ "email": "bob@example.com" }))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let list: serde_json::Value = h
        .get("/api/v1/repos/alice/infra/collaborators")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(list
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["email"] == "bob@example.com"));
    assert_eq!(
        h.delete(&format!("/api/v1/repos/alice/infra/collaborators/{bob}"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn orgs_teams_and_notifications_round_trip() {
    let h = Harness::new().await;

    assert_eq!(
        h.post("/api/v1/orgs")
            .json(&json!({ "name": "acme", "display_name": "Acme" }))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        h.post("/api/v1/orgs/acme/teams")
            .json(&json!({ "name": "devs", "permission": "write" }))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        h.post("/api/v1/orgs/acme/teams/devs/members")
            .json(&json!({ "username": "mallory" }))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        h.delete("/api/v1/orgs/acme/teams/devs/members/mallory")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );

    // email-notification preference toggle
    assert_eq!(
        h.put("/api/v1/user/email-notifications")
            .json(&json!({ "enabled": false }))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert!(
        !edda_db::UserRepo::email_notifications_enabled(&h.pool, h.alice)
            .await
            .unwrap()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn write_endpoints_reject_no_token_and_a_non_collaborator() {
    let h = Harness::new().await;
    h.make_repo("locked").await;

    // no Authorization header at all → 401
    assert_eq!(
        h.client
            .post(format!("{}/api/v1/repos/alice/locked/issues", h.base))
            .json(&json!({ "title": "x" }))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );

    // a valid token for someone with no write grant → 403 (repo is public,
    // so its existence is not hidden)
    assert_eq!(
        h.client
            .post(format!("{}/api/v1/repos/alice/locked/issues", h.base))
            .bearer_auth(&h.other_token)
            .json(&json!({ "title": "x" }))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );

    // grant write, then it works
    let bob = UserId::new();
    UserRepo::insert(&h.pool, bob, "bob2", "bob2@example.com", "x")
        .await
        .unwrap();
    let (bob_token, _) = tokens::create(&h.pool, bob, "ci").await.unwrap();
    let repo = RepositoryRepo::find_by_owner_username_and_name(&h.pool, "alice", "locked")
        .await
        .unwrap()
        .unwrap();
    RepoAccessRepo::grant(&h.pool, repo.id, AccessSubject::User(bob), RepoRole::Write)
        .await
        .unwrap();
    assert_eq!(
        h.client
            .post(format!("{}/api/v1/repos/alice/locked/issues", h.base))
            .bearer_auth(&bob_token)
            .json(&json!({ "title": "x" }))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
}
