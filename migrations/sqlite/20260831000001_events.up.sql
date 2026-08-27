-- Transactional outbox: a state-changing operation writes its
-- `edda_domain::DomainEvent` here in the *same* transaction as the rows it
-- changed (`edda_db::EventRepo::append`), so an event can never be lost
-- because the process died between "commit the change" and "tell the world"
-- — the failure mode the old `edda_jobs::dispatch`-after-commit call had.
--
-- `edda_jobs::spawn_dispatcher` polls `WHERE processed_at IS NULL`, fans each
-- row out to `jobs` rows (webhook deliveries, notifications, emails), and
-- sets `processed_at` — all in one transaction per event, so a crash mid
-- fan-out simply leaves the event unprocessed for the next poll (at-least
-- once), and the job handlers are idempotent (at-most-once effect).
--
-- `payload_json` is a JSON-serialized `DomainEvent`; `kind` is its
-- discriminant (`edda_domain::DomainEventKind`), duplicated into its own
-- column so the dispatcher and operators can filter without parsing every
-- blob. `aggregate_type`/`aggregate_id` locate the entity the event is
-- about (a pull request, an issue) for the same reason — no foreign key,
-- deliberately: events outlive the rows they reference and the integrity
-- stakes are low (plan.local.md §12.2).
CREATE TABLE events (
    id             TEXT PRIMARY KEY NOT NULL,
    occurred_at    INTEGER NOT NULL,
    aggregate_type TEXT NOT NULL,
    aggregate_id   TEXT NOT NULL,
    kind           TEXT NOT NULL,
    payload_json   TEXT NOT NULL,
    processed_at   INTEGER
) STRICT;

-- The dispatcher's hot query: the oldest still-unprocessed events. A
-- partial index keeps it to just the backlog, not the whole (mostly
-- processed) table.
CREATE INDEX idx_events_unprocessed ON events(occurred_at) WHERE processed_at IS NULL;

-- "Every event about this pull request / issue" — operational lookups.
CREATE INDEX idx_events_aggregate ON events(aggregate_type, aggregate_id);
