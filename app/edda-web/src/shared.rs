//! A narrow bridge between Dioxus's server-function extraction model and
//! the shared instances `edda-http`'s handlers already receive via axum's
//! `State<AppState>`.
//!
//! Dioxus 0.7's `#[get]`/`#[post]` macros extract a fixed, macro-recognized
//! set of things (headers, cookies, and — via the `name: Type` `server_args`
//! syntax — a handful of axum extractor types such as
//! `axum_login::AuthSession<B>`); they do not expose arbitrary
//! `axum::extract::State<T>` the way a hand-written axum handler does,
//! because the underlying router Dioxus builds isn't the same `Router<S>`
//! `edda_http::router` is merged into with its state already applied.
//!
//! Every write path still needs to go through the *same* `LockRegistry`
//! (plan.local.md §16, smell S8) regardless of whether the write is
//! triggered by a server function (this file) or an `edda-http` handler —
//! that correctness property doesn't change just because the extraction
//! mechanism differs. So this module holds the same values `main.rs`
//! passes into `AppState`, set exactly once at startup via
//! [`init`], read only through [`get`]. This is not a reintroduction of
//! the removed `git::repo_lock` static: that one lazily created its
//! contents wherever first touched, with no single owner; this one is
//! populated once, from one place, with values that already have a single
//! owner (`main`'s local variables) — it exists only to work around
//! Dioxus's extraction model, not as this crate's state-management design.

use std::sync::{Arc, OnceLock};

use edda_auth::AuthorizationService;
use edda_db::DbPool;
use edda_git::store::RepoStore;
use edda_git::LockRegistry;

pub struct SharedServerState {
    pub pool: DbPool,
    pub store: Arc<dyn RepoStore>,
    pub locks: Arc<LockRegistry>,
    pub authz: AuthorizationService,
}

static SHARED: OnceLock<SharedServerState> = OnceLock::new();

/// Called once from `main`, before the server starts accepting requests.
pub fn init(state: SharedServerState) {
    if SHARED.set(state).is_err() {
        panic!("shared::init called more than once");
    }
}

pub fn get() -> &'static SharedServerState {
    SHARED
        .get()
        .expect("shared::init must run before any server function executes")
}
