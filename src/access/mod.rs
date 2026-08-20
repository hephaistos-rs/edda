//! Per-repo write access: who besides the repo's owner can push to it, edit
//! its description, or delete it. Deliberately coarse — one `repo_access`
//! row per (repo, user) grants full write access, no finer-grained
//! permission split (e.g. "can push but not delete") yet.
//!
//! Repo identity here is the same filesystem-derived name used everywhere
//! else in Edda (there's no `repos` table) — see the `repo.name` comments in
//! `server/mod.rs` and `git/mod.rs` for why that's an accepted, bounded key
//! rather than an internal id.
pub mod routes;

use sqlx::SqlitePool;

#[derive(Debug, thiserror::Error)]
pub enum AccessError {
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    #[error("only the repo owner can do that")]
    NotOwner,
    #[error("no user with that email")]
    UserNotFound,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CollaboratorInfo {
    pub user_id: String,
    pub email: String,
    pub role: String,
    pub added_at: i64,
}

/// Called once, right after a repo is created — the creator is always its
/// owner. Not re-checked against anything: there's nothing to conflict with
/// for a name that didn't exist a moment ago.
pub async fn grant_owner(pool: &SqlitePool, repo_name: &str, user_id: &str) -> Result<(), AccessError> {
    sqlx::query!("INSERT INTO repo_access (repo_name, user_id, role) VALUES (?, ?, 'owner')", repo_name, user_id).execute(pool).await?;
    Ok(())
}

/// Owner or collaborator — the only two roles, and both carry the same
/// write access today. Also reused, unchanged, as the read-access check for
/// private repos: the same set of people who can push should be able to
/// browse/clone, so there's no separate "has_read_access" predicate.
pub async fn has_write_access(pool: &SqlitePool, repo_name: &str, user_id: &str) -> Result<bool, AccessError> {
    let row = sqlx::query!("SELECT user_id FROM repo_access WHERE repo_name = ? AND user_id = ?", repo_name, user_id).fetch_optional(pool).await?;
    Ok(row.is_some())
}

pub async fn is_owner(pool: &SqlitePool, repo_name: &str, user_id: &str) -> Result<bool, AccessError> {
    let row = sqlx::query!("SELECT user_id FROM repo_access WHERE repo_name = ? AND user_id = ? AND role = 'owner'", repo_name, user_id)
        .fetch_optional(pool)
        .await?;
    Ok(row.is_some())
}

/// Only an owner can grant access to someone else — a collaborator can't
/// deputize further collaborators.
pub async fn add_collaborator(pool: &SqlitePool, repo_name: &str, actor_id: &str, target_email: &str) -> Result<(), AccessError> {
    if !is_owner(pool, repo_name, actor_id).await? {
        return Err(AccessError::NotOwner);
    }
    let target = sqlx::query!("SELECT id FROM users WHERE email = ?", target_email).fetch_optional(pool).await?;
    let Some(target) = target else { return Err(AccessError::UserNotFound) };

    sqlx::query!("INSERT OR IGNORE INTO repo_access (repo_name, user_id, role) VALUES (?, ?, 'collaborator')", repo_name, target.id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list_collaborators(pool: &SqlitePool, repo_name: &str) -> Result<Vec<CollaboratorInfo>, AccessError> {
    let rows = sqlx::query_as!(
        CollaboratorInfo,
        "SELECT repo_access.user_id, users.email, repo_access.role, repo_access.added_at \
         FROM repo_access JOIN users ON users.id = repo_access.user_id \
         WHERE repo_access.repo_name = ? ORDER BY repo_access.added_at",
        repo_name
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// `Ok(true)` if a collaborator (never the owner — that role isn't
/// removable through this path) was actually removed.
pub async fn remove_collaborator(pool: &SqlitePool, repo_name: &str, actor_id: &str, target_user_id: &str) -> Result<bool, AccessError> {
    if !is_owner(pool, repo_name, actor_id).await? {
        return Err(AccessError::NotOwner);
    }
    let result = sqlx::query!("DELETE FROM repo_access WHERE repo_name = ? AND user_id = ? AND role = 'collaborator'", repo_name, target_user_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

/// Called on repo deletion. Without this, a deleted-then-recreated repo of
/// the same name would inherit the old repo's access grants — silently
/// handing write access to people who should never have had it on the new
/// one.
pub async fn revoke_all(pool: &SqlitePool, repo_name: &str) -> Result<(), AccessError> {
    sqlx::query!("DELETE FROM repo_access WHERE repo_name = ?", repo_name).execute(pool).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs `fut` to completion on a fresh, single-threaded runtime — every
    /// test below needs one to await these `async fn`s, but none of them
    /// need `tokio`'s `#[tokio::test]` macro (not a feature this crate
    /// enables) or a multi-threaded scheduler.
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(fut)
    }

    /// An in-memory, fully migrated database — isolated per test, never the
    /// real `EDDA_DATA_DIR`/`data/edda.db`.
    async fn test_pool() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        crate::migrations::run(&pool).await.unwrap();
        pool
    }

    async fn insert_user(pool: &SqlitePool, username: &str) -> String {
        let id = uuid::Uuid::now_v7().to_string();
        let email = format!("{username}@example.com");
        sqlx::query!("INSERT INTO users (id, username, email, password_hash) VALUES (?, ?, ?, 'x')", id, username, email)
            .execute(pool)
            .await
            .unwrap();
        id
    }

    /// The core requirement of this increment: access is keyed by the full
    /// `{owner}/{repo}` identity, so two different owners' repos that happen
    /// to share a repo-name segment (`alice/shared` vs. `bob/shared`) never
    /// leak access into each other.
    #[test]
    fn write_access_is_keyed_by_the_complete_identity() {
        block_on(async {
            let pool = test_pool().await;
            let alice = insert_user(&pool, "alice").await;
            let bob = insert_user(&pool, "bob").await;

            grant_owner(&pool, "alice/shared", &alice).await.unwrap();
            grant_owner(&pool, "bob/shared", &bob).await.unwrap();

            assert!(has_write_access(&pool, "alice/shared", &alice).await.unwrap());
            assert!(!has_write_access(&pool, "alice/shared", &bob).await.unwrap());
            assert!(has_write_access(&pool, "bob/shared", &bob).await.unwrap());
            assert!(!has_write_access(&pool, "bob/shared", &alice).await.unwrap());

            assert!(is_owner(&pool, "alice/shared", &alice).await.unwrap());
            assert!(!is_owner(&pool, "bob/shared", &alice).await.unwrap());
        });
    }

    #[test]
    fn collaborator_grants_are_keyed_by_the_complete_identity() {
        block_on(async {
            let pool = test_pool().await;
            let alice = insert_user(&pool, "alice").await;
            let bob = insert_user(&pool, "bob").await;
            let carol = insert_user(&pool, "carol").await;

            grant_owner(&pool, "alice/shared", &alice).await.unwrap();
            grant_owner(&pool, "bob/shared", &bob).await.unwrap();

            add_collaborator(&pool, "alice/shared", &alice, "carol@example.com").await.unwrap();

            assert!(has_write_access(&pool, "alice/shared", &carol).await.unwrap());
            // Carol was only added to alice/shared — a same-named repo under
            // a different owner must not see her as a collaborator too.
            assert!(!has_write_access(&pool, "bob/shared", &carol).await.unwrap());

            // Only an owner of *that* identity can grant/revoke on it — bob
            // isn't alice/shared's owner, even though he owns bob/shared.
            let err = add_collaborator(&pool, "alice/shared", &bob, "carol@example.com").await;
            assert!(matches!(err, Err(AccessError::NotOwner)));

            let removed = remove_collaborator(&pool, "alice/shared", &alice, &carol).await.unwrap();
            assert!(removed);
            assert!(!has_write_access(&pool, "alice/shared", &carol).await.unwrap());
        });
    }

    #[test]
    fn revoke_all_only_affects_its_own_identity() {
        block_on(async {
            let pool = test_pool().await;
            let alice = insert_user(&pool, "alice").await;
            let bob = insert_user(&pool, "bob").await;

            grant_owner(&pool, "alice/shared", &alice).await.unwrap();
            grant_owner(&pool, "bob/shared", &bob).await.unwrap();

            revoke_all(&pool, "alice/shared").await.unwrap();

            assert!(!has_write_access(&pool, "alice/shared", &alice).await.unwrap());
            assert!(has_write_access(&pool, "bob/shared", &bob).await.unwrap());
        });
    }
}
