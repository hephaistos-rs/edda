//! `@mention` resolution, shared by [`super::pull_request`] and
//! [`super::issue`]: parse a freshly posted comment body, resolve each
//! `@name` to a real account, drop the unresolvable ones and the
//! commenter's own self-mention, and return the distinct user ids left.
//!
//! The caller appends one `DomainEvent::UserMentioned` per returned id
//! *inside its comment-insert transaction*, so the notification/email
//! fan-out is on the outbox and can't be lost — replacing the old
//! `mentions::dispatch_mentions` that enqueued jobs directly after the
//! insert with no transactional tie.

use edda_db::{DbPool, UserRepo};
use edda_domain::{parse_mentions, UserId};

/// The mentioned accounts in `body`, minus `commenter` and minus
/// duplicates, in first-seen order. Unresolvable `@handles` are silently
/// skipped — a typo is not an error.
pub(crate) async fn resolve(
    pool: &DbPool,
    body: &str,
    commenter: UserId,
) -> Result<Vec<UserId>, edda_db::DbError> {
    let mut resolved: Vec<UserId> = Vec::new();
    for username in parse_mentions(body) {
        let Some(user) = UserRepo::find_by_username(pool, &username).await? else {
            continue;
        };
        if user.id != commenter && !resolved.contains(&user.id) {
            resolved.push(user.id);
        }
    }
    Ok(resolved)
}
