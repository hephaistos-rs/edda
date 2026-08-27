use std::sync::Arc;

use edda_auth::{AuthorizationService, Backend};
use edda_db::DbPool;
use edda_git::store::RepoStore;
use edda_git::LockRegistry;

/// Everything an `edda-http` handler needs, constructed once by the
/// composition root (`edda-web`) and shared via axum's `State` extractor
/// — so a handler never calls `LocalFsStore::from_env()` or derives its
/// own `LockRegistry` independently.
#[derive(Clone)]
pub struct AppState {
    pub pool: DbPool,
    pub store: Arc<dyn RepoStore>,
    pub locks: Arc<LockRegistry>,
    pub authz: AuthorizationService,
    pub backend: Backend,
}
