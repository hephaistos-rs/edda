//! Runs a blocking `edda-git` read — an object-graph walk or a filesystem
//! traversal, real CPU/FS work rather than I/O — on Tokio's blocking pool
//! instead of an async worker (A9), under a hard request-scoped timeout so
//! a pathological repository can't pin a request indefinitely (M2).
//!
//! A timed-out closure keeps running to completion — a blocking thread
//! can't be cancelled — but it no longer holds up the request or an async
//! worker, and the blocking pool is bounded, so a runaway walk degrades
//! throughput gracefully instead of stalling the runtime.
//!
//! `browse_tree` / `read_blob` / `commit_log` / `commit_diff` /
//! `list_branches` / `list_tags` / `search_tree` / `repo_summary` /
//! `diff_refs` / `blame` are all routed through here — after Phase 7 no
//! `gix` read runs on an async handler task.

use std::time::Duration;

use crate::services::ServiceError;

/// A single git read gets this long before the request gives up on it.
/// Generous — a cold cache over a large history is legitimately slow — but
/// finite.
const GIT_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Runs `f` on the blocking pool, re-entering the caller's span inside it
/// so the `gix` work nests under the request span rather than showing up
/// orphaned, and fails the request with a `Git` error if it either panics
/// or outruns [`GIT_READ_TIMEOUT`].
pub(crate) async fn git_read<T, F>(what: &'static str, f: F) -> Result<T, ServiceError>
where
    F: FnOnce() -> Result<T, edda_git::GitError> + Send + 'static,
    T: Send + 'static,
{
    git_read_within(what, GIT_READ_TIMEOUT, f).await
}

async fn git_read_within<T, F>(
    what: &'static str,
    timeout: Duration,
    f: F,
) -> Result<T, ServiceError>
where
    F: FnOnce() -> Result<T, edda_git::GitError> + Send + 'static,
    T: Send + 'static,
{
    let span = tracing::Span::current();
    let handle = tokio::task::spawn_blocking(move || span.in_scope(f));
    match tokio::time::timeout(timeout, handle).await {
        Ok(Ok(result)) => result.map_err(ServiceError::from),
        Ok(Err(_join)) => Err(ServiceError::Git(edda_git::GitError::Git(format!(
            "{what}: git read task panicked"
        )))),
        Err(_elapsed) => Err(ServiceError::Git(edda_git::GitError::Git(format!(
            "{what}: git read exceeded {}s",
            timeout.as_secs_f64()
        )))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    /// The closure runs on a *blocking* thread, never the caller's async
    /// worker — the whole point of the sweep (A9).
    #[tokio::test]
    async fn the_closure_runs_off_the_async_worker() {
        let caller = std::thread::current().id();
        let ran_on = git_read("probe", move || Ok(std::thread::current().id()))
            .await
            .unwrap();
        assert_ne!(
            ran_on, caller,
            "the read must not run on the calling thread"
        );
    }

    /// A read that outruns its budget fails the request promptly instead
    /// of hanging it (M2). The underlying blocking thread is left to finish
    /// on its own — asserted here via the channel it drains only after the
    /// timeout has already been observed.
    #[tokio::test]
    async fn a_read_over_its_budget_times_out_without_blocking_the_caller() {
        let (tx, rx) = mpsc::channel();
        let started = std::time::Instant::now();
        let err = git_read_within("slow", Duration::from_millis(50), move || {
            std::thread::sleep(Duration::from_millis(400));
            let _ = tx.send(());
            Ok(())
        })
        .await
        .unwrap_err();

        assert!(
            started.elapsed() < Duration::from_millis(300),
            "the caller returned before the closure finished"
        );
        assert!(matches!(
            err,
            ServiceError::Git(edda_git::GitError::Git(ref m)) if m.contains("exceeded")
        ));
        // The spawned closure still completes — a blocking thread can't be
        // cancelled, and that's fine.
        assert!(rx.recv_timeout(Duration::from_secs(2)).is_ok());
    }
}
