use std::sync::Arc;

use edda_auth::AuthorizationService;
use edda_db::DbPool;
use edda_git::store::RepoStore;
use edda_git::LockRegistry;

/// Everything an SSH connection handler needs, constructed once by the
/// composition root (`edda-web`) and cloned per-connection. Deliberately
/// the same four fields as `edda_http::AppState` — both are "this
/// transport's dependencies" holders, not a shared abstraction: HTTP and
/// SSH have different per-connection lifecycles and framing, so forcing
/// them through one shared struct would only add indirection without
/// removing duplication.
#[derive(Clone)]
pub struct SshState {
    pub pool: DbPool,
    pub store: Arc<dyn RepoStore>,
    pub locks: Arc<LockRegistry>,
    pub authz: AuthorizationService,
}
