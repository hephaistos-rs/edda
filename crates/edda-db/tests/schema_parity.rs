//! Schema-parity check (plan.local.md §12.1, §Phase 9).
//!
//! Introspects the freshly-migrated database this run points at
//! (`EDDA_TEST_DATABASE_URL`, or in-memory SQLite by default) and asserts
//! its *logical* schema — every table's columns and their nullability,
//! the explicitly-named `idx_*` indexes, and the foreign-key target
//! edges — matches one canonical description. Run on SQLite +
//! PostgreSQL + MySQL/MariaDB in CI, all three must match the same
//! `EXPECTED` blob, which makes "a schema change must land in all three
//! backends" a mechanical check rather than a review-time discipline.
//!
//! Deliberately *not* compared (documented dialect differences):
//!   * column SQL types (`TEXT` vs `text` vs `varchar(36)`), timestamp
//!     widths, `STRICT`, storage engines, collations;
//!   * MySQL/MariaDB's generated shadow columns (`username_lower`,
//!     `email_lower`, `name_lower`, `owner_marker`) and the extra
//!     foreign-key helper indexes InnoDB creates automatically;
//!   * auto-generated constraint / primary-key / unique-index *names*
//!     (Postgres `*_pkey`, MySQL back-tick names, SQLite `sqlite_autoindex_*`);
//!   * `CHECK` constraint expressions (each backend renders them
//!     differently — `x IN (...)` vs `x = ANY (ARRAY[...])`).
//!
//! To regenerate `EXPECTED` after an intended schema change, run:
//!   SCHEMA_PARITY_PRINT=1 cargo test -p edda-db --test schema_parity -- --nocapture
//! against each backend and reconcile (they must already agree).

use std::collections::BTreeSet;

use edda_db::Backend;

#[tokio::test]
async fn the_logical_schema_is_identical_across_backends() {
    let pool = edda_db::test_pool().await;
    let actual = introspect(&pool).await;

    if std::env::var("SCHEMA_PARITY_PRINT").is_ok() {
        eprintln!("---- {:?} ----\n{actual}\n---- end ----", pool.backend());
    }

    assert_eq!(
        actual.trim(),
        EXPECTED.trim(),
        "the {:?} schema drifted from the canonical logical schema — \
         reconcile the three `migrations/<backend>/0001_baseline.up.sql` files, \
         or (if the change is intended and already in all three) regenerate \
         EXPECTED per this file's header",
        pool.backend()
    );
}

/// Indexes whose *shape* is a deliberate, documented per-backend
/// difference: SQLite/Postgres express them as partial indexes, MySQL
/// (no partial-index support) as a plain composite or a generated
/// marker column. Their mere presence is checked (the name appears);
/// their column list is not.
const DIALECT_SPECIFIC_INDEXES: &[&str] = &["idx_events_unprocessed", "idx_repo_access_one_owner"];

/// One normalized, sorted, multi-line rendering of the live schema.
async fn introspect(pool: &edda_db::DbPool) -> String {
    let mut out = String::new();
    let mut tables = table_names(pool).await;
    tables.sort();
    for table in &tables {
        out.push_str(&format!("TABLE {table}\n"));
        let mut cols = columns(pool, table).await;
        cols.sort();
        for (col, nullable) in cols {
            out.push_str(&format!(
                "  col {col} {}\n",
                if nullable { "NULL" } else { "NOT NULL" }
            ));
        }
        for pk in primary_key(pool, table).await {
            out.push_str(&format!("  pk {pk}\n"));
        }
        for (name, unique, cols) in named_indexes(pool, table).await {
            // The case-insensitive-uniqueness indexes (`*_ci`) use a
            // different mechanism on each backend (SQLite `COLLATE
            // NOCASE` column constraint, Postgres `LOWER()` functional
            // index, MySQL generated `*_lower` column) — a documented
            // dialect difference; behavioral coverage is in the crate's
            // own uniqueness tests.
            if name.ends_with("_ci") {
                continue;
            }
            if DIALECT_SPECIFIC_INDEXES.contains(&name.as_str()) {
                out.push_str(&format!("  index {name} <dialect-specific>\n"));
                continue;
            }
            out.push_str(&format!(
                "  index {name} {}({})\n",
                if unique { "UNIQUE " } else { "" },
                cols.join(", ")
            ));
        }
        for (col, target) in foreign_keys(pool, table).await {
            out.push_str(&format!("  fk {col} -> {target}\n"));
        }
    }
    out
}

async fn table_names(pool: &edda_db::DbPool) -> Vec<String> {
    let sql = match pool.backend() {
        Backend::Sqlite => {
            "SELECT name FROM sqlite_master WHERE type = 'table' \
             AND name NOT LIKE 'sqlite_%' AND name <> '_sqlx_migrations' ORDER BY name"
        }
        Backend::Postgres => {
            "SELECT tablename::text FROM pg_tables \
             WHERE schemaname = 'public' AND tablename <> '_sqlx_migrations' ORDER BY tablename"
        }
        Backend::MySql => {
            "SELECT CAST(table_name AS CHAR) FROM information_schema.tables \
             WHERE table_schema = DATABASE() AND table_name <> '_sqlx_migrations' \
             ORDER BY table_name"
        }
    };
    fetch_col(pool, sql).await
}

async fn columns(pool: &edda_db::DbPool, table: &str) -> Vec<(String, bool)> {
    match pool.backend() {
        Backend::Sqlite => {
            let rows = sqlx::query_as::<_, (String, i64)>(&format!(
                "SELECT name, \"notnull\" FROM pragma_table_info('{table}') ORDER BY name"
            ))
            .fetch_all(&pool.any)
            .await
            .unwrap();
            rows.into_iter().map(|(n, nn)| (n, nn == 0)).collect()
        }
        Backend::Postgres => {
            let rows = sqlx::query_as::<_, (String, String)>(
                "SELECT column_name::text, is_nullable::text FROM information_schema.columns \
                 WHERE table_schema = 'public' AND table_name = $1 ORDER BY column_name",
            )
            .bind(table)
            .fetch_all(&pool.any)
            .await
            .unwrap();
            rows.into_iter().map(|(n, nn)| (n, nn == "YES")).collect()
        }
        Backend::MySql => {
            let rows = sqlx::query_as::<_, (String, String, String)>(
                "SELECT CAST(column_name AS CHAR), CAST(is_nullable AS CHAR), \
                        CAST(extra AS CHAR) \
                 FROM information_schema.columns \
                 WHERE table_schema = DATABASE() AND table_name = ? ORDER BY column_name",
            )
            .bind(table)
            .fetch_all(&pool.any)
            .await
            .unwrap();
            rows.into_iter()
                // Skip MySQL/MariaDB's generated shadow columns — a
                // documented dialect difference (see file header).
                .filter(|(_, _, extra)| !extra.to_uppercase().contains("GENERATED"))
                .map(|(n, nn, _)| (n, nn == "YES"))
                .collect()
        }
    }
}

async fn primary_key(pool: &edda_db::DbPool, table: &str) -> Vec<String> {
    let mut cols: Vec<String> = match pool.backend() {
        Backend::Sqlite => {
            let rows = sqlx::query_as::<_, (String, i64)>(&format!(
                "SELECT name, pk FROM pragma_table_info('{table}')"
            ))
            .fetch_all(&pool.any)
            .await
            .unwrap();
            rows.into_iter()
                .filter(|(_, pk)| *pk > 0)
                .map(|(n, _)| n)
                .collect()
        }
        Backend::Postgres => sqlx::query_as::<_, (String,)>(
            "SELECT a.attname::text FROM pg_index i \
             JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey) \
             WHERE i.indrelid = $1::regclass AND i.indisprimary",
        )
        .bind(format!("public.{table}"))
        .fetch_all(&pool.any)
        .await
        .unwrap()
        .into_iter()
        .map(|(c,)| c)
        .collect(),
        Backend::MySql => sqlx::query_as::<_, (String,)>(
            "SELECT CAST(column_name AS CHAR) FROM information_schema.key_column_usage \
             WHERE table_schema = DATABASE() AND table_name = ? AND constraint_name = 'PRIMARY'",
        )
        .bind(table)
        .fetch_all(&pool.any)
        .await
        .unwrap()
        .into_iter()
        .map(|(c,)| c)
        .collect(),
    };
    cols.sort();
    cols
}

/// Only the indexes this project names explicitly (`idx_*`). The
/// backends' auto-created primary-key / unique-constraint / FK-helper
/// indexes carry backend-specific names and are compared (for PK)
/// separately or (for FK helpers) not at all.
async fn named_indexes(pool: &edda_db::DbPool, table: &str) -> Vec<(String, bool, Vec<String>)> {
    let mut result: Vec<(String, bool, Vec<String>)> = match pool.backend() {
        Backend::Sqlite => {
            let idx = sqlx::query_as::<_, (String, i64)>(&format!(
                "SELECT name, \"unique\" FROM pragma_index_list('{table}') WHERE name LIKE 'idx_%'"
            ))
            .fetch_all(&pool.any)
            .await
            .unwrap();
            let mut v = Vec::new();
            for (name, uniq) in idx {
                let cols = sqlx::query_as::<_, (String,)>(&format!(
                    "SELECT name FROM pragma_index_info('{name}')"
                ))
                .fetch_all(&pool.any)
                .await
                .unwrap()
                .into_iter()
                .map(|(c,)| c)
                .collect();
                v.push((name, uniq != 0, cols));
            }
            v
        }
        Backend::Postgres => {
            let rows = sqlx::query_as::<_, (String, String)>(
                "SELECT indexname::text, indexdef::text FROM pg_indexes \
                 WHERE schemaname = 'public' AND tablename = $1 AND indexname LIKE 'idx_%'",
            )
            .bind(table)
            .fetch_all(&pool.any)
            .await
            .unwrap();
            rows.into_iter()
                .map(|(name, def)| {
                    let unique = def.contains("CREATE UNIQUE INDEX");
                    let cols = parse_paren_cols(&def);
                    (name, unique, cols)
                })
                .collect()
        }
        Backend::MySql => {
            let rows = sqlx::query_as::<_, (String, i64, i64, String)>(
                "SELECT CAST(index_name AS CHAR), non_unique, seq_in_index, \
                        CAST(column_name AS CHAR) \
                 FROM information_schema.statistics \
                 WHERE table_schema = DATABASE() AND table_name = ? AND index_name LIKE 'idx_%' \
                 ORDER BY index_name, seq_in_index",
            )
            .bind(table)
            .fetch_all(&pool.any)
            .await
            .unwrap();
            let mut by_name: std::collections::BTreeMap<String, (bool, Vec<String>)> =
                std::collections::BTreeMap::new();
            for (name, non_unique, _seq, col) in rows {
                let e = by_name.entry(name).or_insert((non_unique == 0, Vec::new()));
                e.1.push(col);
            }
            by_name.into_iter().map(|(n, (u, c))| (n, u, c)).collect()
        }
    };
    result.sort();
    result
}

async fn foreign_keys(pool: &edda_db::DbPool, table: &str) -> Vec<(String, String)> {
    let mut edges: BTreeSet<(String, String)> = BTreeSet::new();
    match pool.backend() {
        Backend::Sqlite => {
            let rows = sqlx::query_as::<_, (String, String)>(&format!(
                "SELECT \"from\", \"table\" FROM pragma_foreign_key_list('{table}')"
            ))
            .fetch_all(&pool.any)
            .await
            .unwrap();
            edges.extend(rows);
        }
        Backend::Postgres => {
            let rows = sqlx::query_as::<_, (String, String)>(
                "SELECT kcu.column_name::text, ccu.table_name::text \
                 FROM information_schema.table_constraints tc \
                 JOIN information_schema.key_column_usage kcu \
                   ON kcu.constraint_name = tc.constraint_name AND kcu.constraint_schema = tc.constraint_schema \
                 JOIN information_schema.constraint_column_usage ccu \
                   ON ccu.constraint_name = tc.constraint_name AND ccu.constraint_schema = tc.constraint_schema \
                 WHERE tc.constraint_type = 'FOREIGN KEY' AND tc.table_schema = 'public' AND tc.table_name = $1",
            )
            .bind(table)
            .fetch_all(&pool.any)
            .await
            .unwrap();
            edges.extend(rows);
        }
        Backend::MySql => {
            let rows = sqlx::query_as::<_, (String, String)>(
                "SELECT CAST(column_name AS CHAR), CAST(referenced_table_name AS CHAR) \
                 FROM information_schema.key_column_usage \
                 WHERE table_schema = DATABASE() AND table_name = ? \
                   AND referenced_table_name IS NOT NULL",
            )
            .bind(table)
            .fetch_all(&pool.any)
            .await
            .unwrap();
            edges.extend(rows);
        }
    }
    edges.into_iter().collect()
}

async fn fetch_col(pool: &edda_db::DbPool, sql: &str) -> Vec<String> {
    sqlx::query_as::<_, (String,)>(sql)
        .fetch_all(&pool.any)
        .await
        .unwrap()
        .into_iter()
        .map(|(c,)| c)
        .collect()
}

/// Column list from a `CREATE INDEX ... (a, b)` definition (Postgres
/// `indexdef`). Strips any trailing `WHERE` predicate.
fn parse_paren_cols(def: &str) -> Vec<String> {
    let Some(open) = def.find('(') else {
        return Vec::new();
    };
    let Some(close) = def[open..].find(')') else {
        return Vec::new();
    };
    def[open + 1..open + close]
        .split(',')
        .map(|s| s.trim().trim_matches('"').to_string())
        .collect()
}

const EXPECTED: &str = r#"
TABLE access_tokens
  col created_at NOT NULL
  col id NOT NULL
  col last_used_at NULL
  col name NOT NULL
  col repository_scope NOT NULL
  col token_hash NOT NULL
  col token_scope NOT NULL
  col user_id NOT NULL
  pk id
  index idx_access_tokens_user_id (user_id)
  fk user_id -> users
TABLE audit_events
  col actor_id NULL
  col detail_json NULL
  col event_type NOT NULL
  col id NOT NULL
  col occurred_at NOT NULL
  col target_id NULL
  col target_type NULL
  pk id
  index idx_audit_events_actor (actor_id)
  index idx_audit_events_occurred_at (occurred_at)
  fk actor_id -> users
TABLE branch_protection_push_allowlist
  col added_at NOT NULL
  col rule_id NOT NULL
  col subject_team_id NULL
  col subject_user_id NULL
  index idx_bp_allowlist_rule (rule_id)
  index idx_bp_allowlist_team UNIQUE (rule_id, subject_team_id)
  index idx_bp_allowlist_user UNIQUE (rule_id, subject_user_id)
  fk rule_id -> branch_protection_rules
  fk subject_team_id -> teams
  fk subject_user_id -> users
TABLE branch_protection_rules
  col branch NOT NULL
  col dismiss_stale_reviews NOT NULL
  col id NOT NULL
  col repository_id NOT NULL
  col require_linear_history NOT NULL
  col require_signed_commits NOT NULL
  col require_up_to_date NOT NULL
  col required_approvals NOT NULL
  col required_status_checks NOT NULL
  pk id
  index idx_branch_protection_repo_branch UNIQUE (repository_id, branch)
  fk repository_id -> repositories
TABLE commit_statuses
  col commit_sha NOT NULL
  col context NOT NULL
  col created_at NOT NULL
  col description NULL
  col id NOT NULL
  col repository_id NOT NULL
  col state NOT NULL
  col target_url NULL
  col updated_at NOT NULL
  pk id
  index idx_commit_statuses_commit (repository_id, commit_sha)
  index idx_commit_statuses_key UNIQUE (repository_id, commit_sha, context)
  fk repository_id -> repositories
TABLE deploy_keys
  col created_at NOT NULL
  col fingerprint NOT NULL
  col id NOT NULL
  col last_used_at NULL
  col public_key NOT NULL
  col read_only NOT NULL
  col repository_id NOT NULL
  col title NOT NULL
  pk id
  index idx_deploy_keys_repository_id (repository_id)
  fk repository_id -> repositories
TABLE email_verification_tokens
  col created_at NOT NULL
  col expires_at NOT NULL
  col id NOT NULL
  col token_hash NOT NULL
  col used_at NULL
  col user_id NOT NULL
  pk id
  index idx_email_verification_tokens_hash UNIQUE (token_hash)
  index idx_email_verification_tokens_user (user_id)
  fk user_id -> users
TABLE events
  col aggregate_id NOT NULL
  col aggregate_type NOT NULL
  col id NOT NULL
  col kind NOT NULL
  col occurred_at NOT NULL
  col payload_json NOT NULL
  col processed_at NULL
  pk id
  index idx_events_aggregate (aggregate_type, aggregate_id)
  index idx_events_unprocessed <dialect-specific>
TABLE issue_assignees
  col assigned_at NOT NULL
  col assigned_by_id NULL
  col issue_id NOT NULL
  col user_id NOT NULL
  pk issue_id
  pk user_id
  index idx_issue_assignees_user (user_id)
  fk assigned_by_id -> users
  fk issue_id -> issues
  fk user_id -> users
TABLE issue_comments
  col author_id NOT NULL
  col body NOT NULL
  col created_at NOT NULL
  col id NOT NULL
  col issue_id NOT NULL
  pk id
  index idx_issue_comments_issue (issue_id)
  fk author_id -> users
  fk issue_id -> issues
TABLE issue_labels
  col issue_id NOT NULL
  col label_id NOT NULL
  pk issue_id
  pk label_id
  index idx_issue_labels_label (label_id)
  fk issue_id -> issues
  fk label_id -> labels
TABLE issues
  col author_id NOT NULL
  col body NULL
  col close_reason NULL
  col closed_at NULL
  col created_at NOT NULL
  col id NOT NULL
  col milestone_id NULL
  col number NOT NULL
  col repository_id NOT NULL
  col state NOT NULL
  col title NOT NULL
  pk id
  index idx_issues_milestone (milestone_id)
  index idx_issues_repo_number UNIQUE (repository_id, number)
  index idx_issues_repo_state (repository_id, state)
  fk author_id -> users
  fk milestone_id -> milestones
  fk repository_id -> repositories
TABLE jobs
  col attempts NOT NULL
  col created_at NOT NULL
  col id NOT NULL
  col last_error NULL
  col max_attempts NOT NULL
  col payload NOT NULL
  col run_at NOT NULL
  col status NOT NULL
  pk id
  index idx_jobs_status_run_at (status, run_at)
TABLE labels
  col archived_at NULL
  col color NOT NULL
  col description NULL
  col id NOT NULL
  col name NOT NULL
  col repository_id NOT NULL
  pk id
  index idx_labels_repo_name UNIQUE (repository_id, name)
  fk repository_id -> repositories
TABLE lfs_locks
  col created_at NOT NULL
  col id NOT NULL
  col owner_id NOT NULL
  col path NOT NULL
  col repository_id NOT NULL
  pk id
  index idx_lfs_locks_repository_path UNIQUE (repository_id, path)
  fk owner_id -> users
  fk repository_id -> repositories
TABLE lfs_objects
  col created_at NOT NULL
  col oid NOT NULL
  col repository_id NOT NULL
  col size_bytes NOT NULL
  col storage_key NOT NULL
  pk oid
  pk repository_id
  fk repository_id -> repositories
TABLE login_attempts
  col attempt_key NOT NULL
  col failure_count NOT NULL
  col first_failed_at NOT NULL
  col last_failed_at NOT NULL
  col locked_until NULL
  pk attempt_key
TABLE milestones
  col description NULL
  col due_on NULL
  col id NOT NULL
  col repository_id NOT NULL
  col state NOT NULL
  col title NOT NULL
  pk id
  index idx_milestones_repository (repository_id)
  fk repository_id -> repositories
TABLE notifications
  col created_at NOT NULL
  col id NOT NULL
  col kind NOT NULL
  col read_at NULL
  col subject_id NOT NULL
  col subject_type NOT NULL
  col user_id NOT NULL
  pk id
  index idx_notifications_dedupe_lookup (user_id, kind, subject_type, subject_id)
  index idx_notifications_user_read (user_id, read_at)
  fk user_id -> users
TABLE oauth_identities
  col created_at NOT NULL
  col id NOT NULL
  col provider NOT NULL
  col subject_id NOT NULL
  col user_id NOT NULL
  pk id
  index idx_oauth_identities_provider_subject UNIQUE (provider, subject_id)
  index idx_oauth_identities_user (user_id)
  fk user_id -> users
TABLE organizations
  col created_at NOT NULL
  col display_name NULL
  col id NOT NULL
  col name NOT NULL
  col require_2fa NOT NULL
  pk id
TABLE password_reset_tokens
  col created_at NOT NULL
  col expires_at NOT NULL
  col id NOT NULL
  col token_hash NOT NULL
  col used_at NULL
  col user_id NOT NULL
  pk id
  index idx_password_reset_tokens_hash UNIQUE (token_hash)
  index idx_password_reset_tokens_user (user_id)
  fk user_id -> users
TABLE pr_comments
  col anchor_commit_sha NULL
  col anchor_file_path NULL
  col anchor_line_end NULL
  col anchor_line_start NULL
  col author_id NOT NULL
  col body NOT NULL
  col created_at NOT NULL
  col id NOT NULL
  col pull_request_id NOT NULL
  pk id
  index idx_pr_comments_pull_request (pull_request_id)
  fk author_id -> users
  fk pull_request_id -> pull_requests
TABLE pr_reviews
  col body NULL
  col created_at NOT NULL
  col dismissed_at NULL
  col id NOT NULL
  col pull_request_id NOT NULL
  col reviewer_id NOT NULL
  col state NOT NULL
  pk id
  index idx_pr_reviews_pull_request (pull_request_id)
  fk pull_request_id -> pull_requests
  fk reviewer_id -> users
TABLE pull_requests
  col author_id NOT NULL
  col body NULL
  col close_reason NULL
  col closed_at NULL
  col created_at NOT NULL
  col id NOT NULL
  col merge_commit NULL
  col merge_strategy NULL
  col merged_at NULL
  col number NOT NULL
  col repository_id NOT NULL
  col source_branch NOT NULL
  col source_repository_id NOT NULL
  col state NOT NULL
  col target_branch NOT NULL
  col title NOT NULL
  pk id
  index idx_pull_requests_repo_number UNIQUE (repository_id, number)
  index idx_pull_requests_repo_state (repository_id, state)
  fk author_id -> users
  fk repository_id -> repositories
  fk source_repository_id -> repositories
TABLE release_assets
  col content_type NOT NULL
  col created_at NOT NULL
  col filename NOT NULL
  col id NOT NULL
  col release_id NOT NULL
  col size_bytes NOT NULL
  col storage_key NOT NULL
  pk id
  index idx_release_assets_release (release_id)
  fk release_id -> releases
TABLE releases
  col author_id NOT NULL
  col body NULL
  col created_at NOT NULL
  col draft NOT NULL
  col id NOT NULL
  col name NOT NULL
  col prerelease NOT NULL
  col published_at NULL
  col repository_id NOT NULL
  col tag_name NOT NULL
  col target_commit NOT NULL
  pk id
  index idx_releases_repo (repository_id)
  index idx_releases_repo_tag UNIQUE (repository_id, tag_name)
  fk author_id -> users
  fk repository_id -> repositories
TABLE repo_access
  col added_at NOT NULL
  col repository_id NOT NULL
  col role NOT NULL
  col subject_team_id NULL
  col subject_user_id NULL
  index idx_repo_access_one_owner <dialect-specific>
  index idx_repo_access_repository_id (repository_id)
  index idx_repo_access_subject_team (subject_team_id)
  index idx_repo_access_subject_user (subject_user_id)
  index idx_repo_access_team UNIQUE (repository_id, subject_team_id)
  index idx_repo_access_user UNIQUE (repository_id, subject_user_id)
  fk repository_id -> repositories
  fk subject_team_id -> teams
  fk subject_user_id -> users
TABLE repo_number_counters
  col next_number NOT NULL
  col repository_id NOT NULL
  pk repository_id
  fk repository_id -> repositories
TABLE repo_sizes
  col computed_at NOT NULL
  col git_bytes NOT NULL
  col lfs_bytes NOT NULL
  col repository_id NOT NULL
  pk repository_id
  fk repository_id -> repositories
TABLE repositories
  col created_at NOT NULL
  col description NULL
  col forked_from NULL
  col id NOT NULL
  col name NOT NULL
  col owner_org_id NULL
  col owner_user_id NULL
  col visibility NOT NULL
  pk id
  index idx_repositories_forked_from (forked_from)
  index idx_repositories_org_owner_name UNIQUE (owner_org_id, name)
  index idx_repositories_owner_org (owner_org_id)
  index idx_repositories_owner_user (owner_user_id)
  index idx_repositories_user_owner_name UNIQUE (owner_user_id, name)
  fk owner_org_id -> organizations
  fk owner_user_id -> users
TABLE review_requests
  col created_at NOT NULL
  col id NOT NULL
  col pull_request_id NOT NULL
  col reviewer_id NOT NULL
  pk id
  index idx_review_requests_pr (pull_request_id)
  index idx_review_requests_pr_reviewer UNIQUE (pull_request_id, reviewer_id)
  index idx_review_requests_reviewer (reviewer_id)
  fk pull_request_id -> pull_requests
  fk reviewer_id -> users
TABLE ssh_keys
  col created_at NOT NULL
  col fingerprint NOT NULL
  col id NOT NULL
  col last_used_at NULL
  col public_key NOT NULL
  col title NOT NULL
  col user_id NOT NULL
  pk id
  index idx_ssh_keys_user_id (user_id)
  fk user_id -> users
TABLE team_members
  col added_at NOT NULL
  col team_id NOT NULL
  col user_id NOT NULL
  pk team_id
  pk user_id
  index idx_team_members_user_id (user_id)
  fk team_id -> teams
  fk user_id -> users
TABLE team_unit_permissions
  col permission NOT NULL
  col team_id NOT NULL
  col unit NOT NULL
  pk team_id
  pk unit
  fk team_id -> teams
TABLE teams
  col created_at NOT NULL
  col id NOT NULL
  col name NOT NULL
  col organization_id NOT NULL
  col permission NOT NULL
  pk id
  index idx_teams_org_name UNIQUE (organization_id, name)
  fk organization_id -> organizations
TABLE totp_recovery_codes
  col code_hash NOT NULL
  col created_at NOT NULL
  col id NOT NULL
  col used_at NULL
  col user_id NOT NULL
  pk id
  index idx_totp_recovery_codes_hash UNIQUE (code_hash)
  index idx_totp_recovery_codes_user (user_id)
  fk user_id -> users
TABLE totp_secrets
  col activated_at NULL
  col created_at NOT NULL
  col secret_ciphertext NOT NULL
  col user_id NOT NULL
  pk user_id
  fk user_id -> users
TABLE users
  col approved_at NULL
  col created_at NOT NULL
  col disabled_at NULL
  col email NOT NULL
  col email_notifications_enabled NOT NULL
  col email_verified_at NULL
  col id NOT NULL
  col is_admin NOT NULL
  col password_hash NOT NULL
  col username NOT NULL
  pk id
TABLE watches
  col created_at NOT NULL
  col id NOT NULL
  col level NOT NULL
  col subject_id NOT NULL
  col subject_type NOT NULL
  col user_id NOT NULL
  pk id
  index idx_watches_subject (subject_type, subject_id)
  index idx_watches_user_subject UNIQUE (user_id, subject_type, subject_id)
  fk user_id -> users
TABLE webauthn_credentials
  col created_at NOT NULL
  col id NOT NULL
  col label NOT NULL
  col last_used_at NULL
  col passkey_json NOT NULL
  col user_id NOT NULL
  pk id
  index idx_webauthn_credentials_user (user_id)
  fk user_id -> users
TABLE webhook_deliveries
  col attempt_count NOT NULL
  col created_at NOT NULL
  col delivered_at NULL
  col event NOT NULL
  col id NOT NULL
  col payload NOT NULL
  col response_status NULL
  col webhook_id NOT NULL
  pk id
  index idx_webhook_deliveries_webhook (webhook_id)
  fk webhook_id -> webhooks
TABLE webhooks
  col active NOT NULL
  col created_at NOT NULL
  col events NOT NULL
  col id NOT NULL
  col repository_id NOT NULL
  col secret_ciphertext NOT NULL
  col target_url NOT NULL
  pk id
  index idx_webhooks_repository (repository_id)
  fk repository_id -> repositories
"#;
