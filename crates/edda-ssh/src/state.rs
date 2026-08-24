use std::sync::Arc;

use edda_auth::AuthorizationService;
use edda_git::store::RepoStore;
use edda_git::LockRegistry;
use sqlx::SqlitePool;

/// Everything an SSH connection handler needs, constructed once by the
/// composition root (`edda-web`) and cloned per-connection. Deliberately
/// the same four fields as `edda_http::AppState` — both are "this
/// transport's dependencies" holders, not a shared abstraction; see
/// plan.local.md's Phase 2 completion report for why a shared struct
/// across the two transport crates isn't warranted here.
#[derive(Clone)]
pub struct SshState {
    pub pool: SqlitePool,
    pub store: Arc<dyn RepoStore>,
    pub locks: Arc<LockRegistry>,
    pub authz: AuthorizationService,
}
