//! The `events` outbox table's persistence boundary.
//!
//! An application service calls [`EventRepo::append`] on the *same*
//! `&mut DbTx` it used for the state change, so the event and the change
//! commit together or not at all. `edda-jobs`'s dispatcher then
//! [`fetch_unprocessed`](EventRepo::fetch_unprocessed)s the backlog, fans
//! each row out to `jobs`, and [`mark_processed`](EventRepo::mark_processed)es
//! it — `mark_processed` is a compare-and-swap (`... WHERE processed_at IS
//! NULL`) so two dispatchers can't both claim the same event.

use edda_domain::{DomainEvent, EventId};

use crate::{get_i64, get_string, Backend, DbConn, DbError};

/// One row of the `events` outbox, decoded back into its `DomainEvent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRecord {
    pub id: EventId,
    pub event: DomainEvent,
    pub occurred_at: i64,
}

fn event_to_json(event: &DomainEvent) -> String {
    serde_json::to_string(event).expect("DomainEvent always serializes")
}

fn event_from_json(json: &str) -> DomainEvent {
    serde_json::from_str(json)
        .expect("stored event payload is valid JSON for a known DomainEvent shape")
}

pub struct EventRepo;

impl EventRepo {
    /// Appends one domain event to the outbox, unprocessed. `occurred_at`
    /// is set to now — an event's occurrence time is definitionally the
    /// moment its transaction records it.
    pub async fn append<'c>(
        db: impl DbConn<'c>,
        id: EventId,
        event: &DomainEvent,
    ) -> Result<(), DbError> {
        let mut h = crate::conn::open(db).await?;
        let id_text = id.to_string();
        let occurred_at = crate::now_unix();
        let aggregate_type = event.aggregate_type();
        let aggregate_id = event.aggregate_id().to_string();
        let kind = event.kind().as_db_str();
        let payload_json = event_to_json(event);
        let sql = match h.backend() {
            Backend::Postgres => {
                "INSERT INTO events (id, occurred_at, aggregate_type, aggregate_id, kind, payload_json)
                 VALUES ($1, $2, $3, $4, $5, $6)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO events (id, occurred_at, aggregate_type, aggregate_id, kind, payload_json)
                 VALUES (?, ?, ?, ?, ?, ?)"
            }
        };
        sqlx::query(sql)
            .bind(&id_text)
            .bind(occurred_at)
            .bind(aggregate_type)
            .bind(&aggregate_id)
            .bind(kind)
            .bind(&payload_json)
            .execute(&mut *h.conn())
            .await?;
        Ok(())
    }

    /// Up to `limit` still-unprocessed events, oldest first — the
    /// dispatcher's poll query.
    pub async fn fetch_unprocessed<'c>(
        db: impl DbConn<'c>,
        limit: i64,
    ) -> Result<Vec<EventRecord>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT id, payload_json, occurred_at FROM events
                 WHERE processed_at IS NULL ORDER BY occurred_at LIMIT $1"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, payload_json, occurred_at FROM events
                 WHERE processed_at IS NULL ORDER BY occurred_at LIMIT ?"
            }
        };
        let rows = sqlx::query(sql)
            .bind(limit)
            .fetch_all(&mut *h.conn())
            .await?;
        rows.into_iter()
            .map(|row| {
                Ok(EventRecord {
                    id: get_string(&row, "id")?
                        .parse()
                        .expect("stored event id is a valid UUID"),
                    event: event_from_json(&get_string(&row, "payload_json")?),
                    occurred_at: get_i64(&row, "occurred_at")?,
                })
            })
            .collect()
    }

    /// Marks one event processed, but only if it still is unprocessed —
    /// the compare-and-swap that stops two concurrent dispatchers from
    /// both fanning the same event out. Returns whether this call is the
    /// one that claimed it.
    pub async fn mark_processed<'c>(db: impl DbConn<'c>, id: EventId) -> Result<bool, DbError> {
        let mut h = crate::conn::open(db).await?;
        let processed_at = crate::now_unix();
        let sql = match h.backend() {
            Backend::Postgres => {
                "UPDATE events SET processed_at = $1 WHERE id = $2 AND processed_at IS NULL"
            }
            Backend::Sqlite | Backend::MySql => {
                "UPDATE events SET processed_at = ? WHERE id = ? AND processed_at IS NULL"
            }
        };
        let result = sqlx::query(sql)
            .bind(processed_at)
            .bind(id.to_string())
            .execute(&mut *h.conn())
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use edda_domain::{MentionSource, PullRequestId, RepositoryId, UserId};

    fn sample_event() -> DomainEvent {
        DomainEvent::UserMentioned {
            mentioned_user_id: UserId::new(),
            mentioned_by_user_id: UserId::new(),
            source: MentionSource::PullRequestComment {
                pull_request_id: PullRequestId::new(),
            },
        }
    }

    #[tokio::test]
    async fn an_appended_event_round_trips_and_is_unprocessed() {
        let pool = crate::test_pool().await;
        let id = EventId::new();
        let event = sample_event();
        EventRepo::append(&pool, id, &event).await.unwrap();

        let unprocessed = EventRepo::fetch_unprocessed(&pool, 10).await.unwrap();
        assert_eq!(unprocessed.len(), 1);
        assert_eq!(unprocessed[0].id, id);
        assert_eq!(unprocessed[0].event, event);
    }

    #[tokio::test]
    async fn mark_processed_claims_once_then_the_event_leaves_the_backlog() {
        let pool = crate::test_pool().await;
        let id = EventId::new();
        EventRepo::append(&pool, id, &sample_event()).await.unwrap();

        assert!(EventRepo::mark_processed(&pool, id).await.unwrap());
        // A second claim of the same event does nothing — the CAS guard.
        assert!(!EventRepo::mark_processed(&pool, id).await.unwrap());

        assert!(EventRepo::fetch_unprocessed(&pool, 10)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn fetch_unprocessed_returns_oldest_first_and_respects_the_limit() {
        let pool = crate::test_pool().await;
        let first = EventId::new();
        let second = EventId::new();
        EventRepo::append(&pool, first, &sample_event())
            .await
            .unwrap();
        EventRepo::append(&pool, second, &sample_event())
            .await
            .unwrap();

        let batch = EventRepo::fetch_unprocessed(&pool, 1).await.unwrap();
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].id, first);
    }

    #[tokio::test]
    async fn an_event_appended_inside_a_rolled_back_transaction_never_lands() {
        let pool = crate::test_pool().await;
        let id = EventId::new();
        let mut tx = pool.begin().await.unwrap();
        EventRepo::append(&mut tx, id, &sample_event())
            .await
            .unwrap();
        tx.rollback().await.unwrap();

        assert!(EventRepo::fetch_unprocessed(&pool, 10)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn the_aggregate_columns_are_populated_from_the_event() {
        let pool = crate::test_pool().await;
        let pr_id = PullRequestId::new();
        let event = DomainEvent::PullRequestMerged {
            pull_request_id: pr_id,
            repository_id: RepositoryId::new(),
        };
        EventRepo::append(&pool, EventId::new(), &event)
            .await
            .unwrap();

        // Read the raw columns back through a repo helper query to prove
        // `append` wrote the discriminant/aggregate, not just the blob.
        let mut h = crate::conn::open(&pool).await.unwrap();
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT aggregate_type, aggregate_id, kind FROM events WHERE aggregate_id = $1"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT aggregate_type, aggregate_id, kind FROM events WHERE aggregate_id = ?"
            }
        };
        let row = sqlx::query(sql)
            .bind(pr_id.as_uuid().to_string())
            .fetch_one(&mut *h.conn())
            .await
            .unwrap();
        assert_eq!(get_string(&row, "aggregate_type").unwrap(), "pull_request");
        assert_eq!(get_string(&row, "kind").unwrap(), "pull_request_merged");
    }
}
