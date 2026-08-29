//! `branch_protection_rules` (+ `branch_protection_push_allowlist`)
//! persistence. The `branch` column holds a glob **pattern**
//! (`edda_domain::branch_pattern_matches`); `find_matching` is the
//! load-all-then-glob step that turns "which rule applies to branch X"
//! into a domain decision rather than a SQL `WHERE branch = ?`.

use std::collections::HashMap;

use edda_domain::{
    branch_pattern_matches, AccessSubject, BranchProtectionRule, BranchProtectionRuleId,
    RepositoryId, TeamId, UserId,
};

use crate::{get_bool, get_i64, get_opt_string, get_string, Backend, DbConn, DbError};

/// The mutable settings half of a `BranchProtectionRule` — everything
/// `upsert_by_pattern` writes, minus the identity (`id`, `repository_id`,
/// `pattern`) and the separately-managed `push_allowlist`.
#[derive(Debug, Clone, Default)]
pub struct BranchProtectionSettings {
    pub required_approvals: i64,
    pub require_linear_history: bool,
    pub require_signed_commits: bool,
    pub dismiss_stale_reviews: bool,
    pub require_up_to_date: bool,
    pub required_status_checks: Vec<String>,
}

fn status_checks_to_json(checks: &[String]) -> String {
    serde_json::to_string(checks).expect("Vec<String> always serializes")
}

fn status_checks_from_json(json: &str) -> Vec<String> {
    serde_json::from_str(json)
        .expect("stored branch_protection_rules.required_status_checks is valid JSON")
}

fn row_to_rule(row: &sqlx::any::AnyRow) -> Result<BranchProtectionRule, DbError> {
    Ok(BranchProtectionRule {
        id: get_string(row, "id")?
            .parse()
            .expect("stored branch protection rule id is a valid UUID"),
        repository_id: get_string(row, "repository_id")?
            .parse()
            .expect("stored repository id is a valid UUID"),
        pattern: get_string(row, "branch")?,
        required_approvals: get_i64(row, "required_approvals")?,
        require_linear_history: get_bool(row, "require_linear_history")?,
        require_signed_commits: get_bool(row, "require_signed_commits")?,
        dismiss_stale_reviews: get_bool(row, "dismiss_stale_reviews")?,
        require_up_to_date: get_bool(row, "require_up_to_date")?,
        required_status_checks: status_checks_from_json(&get_string(
            row,
            "required_status_checks",
        )?),
        push_allowlist: Vec::new(),
    })
}

const RULE_COLS: &str = "id, repository_id, branch, required_approvals, require_linear_history, \
     require_signed_commits, dismiss_stale_reviews, require_up_to_date, required_status_checks";

pub struct BranchProtectionRepo;

impl BranchProtectionRepo {
    /// Creates the rule for `(repository_id, pattern)` or, if one already
    /// exists for that exact pattern, overwrites its settings. Returns the
    /// rule's id (the passed `id` when a new row was inserted, the existing
    /// row's id otherwise). The `push_allowlist` is managed separately via
    /// [`replace_allowlist`](Self::replace_allowlist).
    pub async fn upsert_by_pattern<'c>(
        db: impl DbConn<'c>,
        id: BranchProtectionRuleId,
        repository_id: RepositoryId,
        pattern: &str,
        settings: &BranchProtectionSettings,
    ) -> Result<BranchProtectionRuleId, DbError> {
        let mut h = crate::conn::open(db).await?;
        let repo_text = repository_id.to_string();
        let checks_json = status_checks_to_json(&settings.required_status_checks);

        let find_sql = match h.backend() {
            Backend::Postgres => {
                "SELECT id FROM branch_protection_rules WHERE repository_id = $1 AND branch = $2"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id FROM branch_protection_rules WHERE repository_id = ? AND branch = ?"
            }
        };
        let existing = sqlx::query(find_sql)
            .bind(&repo_text)
            .bind(pattern)
            .fetch_optional(&mut *h.conn())
            .await?;

        if let Some(row) = existing {
            let existing_id: BranchProtectionRuleId = get_string(&row, "id")?
                .parse()
                .expect("stored branch protection rule id is a valid UUID");
            let update_sql = match h.backend() {
                Backend::Postgres => {
                    "UPDATE branch_protection_rules SET required_approvals = $1, \
                     require_linear_history = $2, require_signed_commits = $3, \
                     dismiss_stale_reviews = $4, require_up_to_date = $5, \
                     required_status_checks = $6 WHERE id = $7"
                }
                Backend::Sqlite | Backend::MySql => {
                    "UPDATE branch_protection_rules SET required_approvals = ?, \
                     require_linear_history = ?, require_signed_commits = ?, \
                     dismiss_stale_reviews = ?, require_up_to_date = ?, \
                     required_status_checks = ? WHERE id = ?"
                }
            };
            sqlx::query(update_sql)
                .bind(settings.required_approvals)
                .bind(i64::from(settings.require_linear_history))
                .bind(i64::from(settings.require_signed_commits))
                .bind(i64::from(settings.dismiss_stale_reviews))
                .bind(i64::from(settings.require_up_to_date))
                .bind(&checks_json)
                .bind(existing_id.to_string())
                .execute(&mut *h.conn())
                .await?;
            return Ok(existing_id);
        }

        let insert_sql = match h.backend() {
            Backend::Postgres => {
                "INSERT INTO branch_protection_rules (id, repository_id, branch, required_approvals, \
                 require_linear_history, require_signed_commits, dismiss_stale_reviews, \
                 require_up_to_date, required_status_checks) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO branch_protection_rules (id, repository_id, branch, required_approvals, \
                 require_linear_history, require_signed_commits, dismiss_stale_reviews, \
                 require_up_to_date, required_status_checks) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
            }
        };
        sqlx::query(insert_sql)
            .bind(id.to_string())
            .bind(&repo_text)
            .bind(pattern)
            .bind(settings.required_approvals)
            .bind(i64::from(settings.require_linear_history))
            .bind(i64::from(settings.require_signed_commits))
            .bind(i64::from(settings.dismiss_stale_reviews))
            .bind(i64::from(settings.require_up_to_date))
            .bind(&checks_json)
            .execute(&mut *h.conn())
            .await?;
        Ok(id)
    }

    /// Every rule for a repository, ordered by pattern. `push_allowlist` is
    /// left empty — use [`list_for_repository_with_allowlist`](Self::list_for_repository_with_allowlist)
    /// when the allowlist matters (the receive path).
    pub async fn list_for_repository<'c>(
        db: impl DbConn<'c>,
        repository_id: RepositoryId,
    ) -> Result<Vec<BranchProtectionRule>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let repo_text = repository_id.to_string();
        let placeholder = match h.backend() {
            Backend::Postgres => "$1",
            Backend::Sqlite | Backend::MySql => "?",
        };
        let sql = format!(
            "SELECT {RULE_COLS} FROM branch_protection_rules \
             WHERE repository_id = {placeholder} ORDER BY branch"
        );
        let rows = sqlx::query(&sql)
            .bind(&repo_text)
            .fetch_all(&mut *h.conn())
            .await?;
        rows.iter().map(row_to_rule).collect()
    }

    /// Every rule for a repository with its `push_allowlist` populated.
    pub async fn list_for_repository_with_allowlist<'c>(
        db: impl DbConn<'c>,
        repository_id: RepositoryId,
    ) -> Result<Vec<BranchProtectionRule>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let mut rules = Self::list_for_repository(&mut h, repository_id).await?;
        if rules.is_empty() {
            return Ok(rules);
        }
        let mut by_rule = Self::allowlist_for_repository(&mut h, repository_id).await?;
        for rule in &mut rules {
            rule.push_allowlist = by_rule.remove(&rule.id).unwrap_or_default();
        }
        Ok(rules)
    }

    /// The rule whose glob pattern matches `branch`, if any — the first
    /// match in pattern order, so an exact `main` rule wins over a broader
    /// `m*` one only if it sorts first (documented as "avoid overlapping
    /// patterns"; a single applicable rule is the intended shape).
    pub async fn find_matching<'c>(
        db: impl DbConn<'c>,
        repository_id: RepositoryId,
        branch: &str,
    ) -> Result<Option<BranchProtectionRule>, DbError> {
        let rules = Self::list_for_repository(db, repository_id).await?;
        Ok(rules
            .into_iter()
            .find(|rule| branch_pattern_matches(&rule.pattern, branch)))
    }

    pub async fn delete<'c>(
        db: impl DbConn<'c>,
        repository_id: RepositoryId,
        id: BranchProtectionRuleId,
    ) -> Result<bool, DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => {
                "DELETE FROM branch_protection_rules WHERE id = $1 AND repository_id = $2"
            }
            Backend::Sqlite | Backend::MySql => {
                "DELETE FROM branch_protection_rules WHERE id = ? AND repository_id = ?"
            }
        };
        let result = sqlx::query(sql)
            .bind(id.to_string())
            .bind(repository_id.to_string())
            .execute(&mut *h.conn())
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Replaces a rule's whole push-allowlist with `subjects` (the way the
    /// settings UI submits it — a full list, not a diff).
    pub async fn replace_allowlist<'c>(
        db: impl DbConn<'c>,
        rule_id: BranchProtectionRuleId,
        subjects: &[AccessSubject],
    ) -> Result<(), DbError> {
        let mut h = crate::conn::open(db).await?;
        let rule_text = rule_id.to_string();

        let delete_sql = match h.backend() {
            Backend::Postgres => "DELETE FROM branch_protection_push_allowlist WHERE rule_id = $1",
            Backend::Sqlite | Backend::MySql => {
                "DELETE FROM branch_protection_push_allowlist WHERE rule_id = ?"
            }
        };
        sqlx::query(delete_sql)
            .bind(&rule_text)
            .execute(&mut *h.conn())
            .await?;

        for subject in subjects {
            let (user_col, team_col) = match subject {
                AccessSubject::User(_) => ("subject_user_id", "subject_team_id"),
                AccessSubject::Team(_) => ("subject_team_id", "subject_user_id"),
            };
            let value = match subject {
                AccessSubject::User(id) => id.to_string(),
                AccessSubject::Team(id) => id.to_string(),
            };
            let insert_sql = match h.backend() {
                Backend::Postgres => format!(
                    "INSERT INTO branch_protection_push_allowlist (rule_id, {user_col}, {team_col}) \
                     VALUES ($1, $2, NULL) ON CONFLICT DO NOTHING"
                ),
                Backend::Sqlite => format!(
                    "INSERT OR IGNORE INTO branch_protection_push_allowlist (rule_id, {user_col}, {team_col}) \
                     VALUES (?, ?, NULL)"
                ),
                Backend::MySql => format!(
                    "INSERT IGNORE INTO branch_protection_push_allowlist (rule_id, {user_col}, {team_col}) \
                     VALUES (?, ?, NULL)"
                ),
            };
            sqlx::query(&insert_sql)
                .bind(&rule_text)
                .bind(value)
                .execute(&mut *h.conn())
                .await?;
        }
        Ok(())
    }

    /// One rule's push-allowlist subjects.
    pub async fn allowlist_for_rule<'c>(
        db: impl DbConn<'c>,
        rule_id: BranchProtectionRuleId,
    ) -> Result<Vec<AccessSubject>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT subject_user_id, subject_team_id FROM branch_protection_push_allowlist \
                 WHERE rule_id = $1"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT subject_user_id, subject_team_id FROM branch_protection_push_allowlist \
                 WHERE rule_id = ?"
            }
        };
        let rows = sqlx::query(sql)
            .bind(rule_id.to_string())
            .fetch_all(&mut *h.conn())
            .await?;
        rows.iter().map(row_to_subject).collect()
    }

    /// Every rule's allowlist for a repository, keyed by rule id — one
    /// query, for the receive path's policy resolution.
    pub async fn allowlist_for_repository<'c>(
        db: impl DbConn<'c>,
        repository_id: RepositoryId,
    ) -> Result<HashMap<BranchProtectionRuleId, Vec<AccessSubject>>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT a.rule_id, a.subject_user_id, a.subject_team_id \
                 FROM branch_protection_push_allowlist a \
                 JOIN branch_protection_rules r ON r.id = a.rule_id \
                 WHERE r.repository_id = $1"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT a.rule_id, a.subject_user_id, a.subject_team_id \
                 FROM branch_protection_push_allowlist a \
                 JOIN branch_protection_rules r ON r.id = a.rule_id \
                 WHERE r.repository_id = ?"
            }
        };
        let rows = sqlx::query(sql)
            .bind(repository_id.to_string())
            .fetch_all(&mut *h.conn())
            .await?;
        let mut out: HashMap<BranchProtectionRuleId, Vec<AccessSubject>> = HashMap::new();
        for row in &rows {
            let rule_id: BranchProtectionRuleId = get_string(row, "rule_id")?
                .parse()
                .expect("stored branch protection rule id is a valid UUID");
            out.entry(rule_id).or_default().push(row_to_subject(row)?);
        }
        Ok(out)
    }
}

fn row_to_subject(row: &sqlx::any::AnyRow) -> Result<AccessSubject, DbError> {
    let user_id = get_opt_string(row, "subject_user_id")?;
    let team_id = get_opt_string(row, "subject_team_id")?;
    match (user_id, team_id) {
        (Some(u), None) => Ok(AccessSubject::User(
            u.parse::<UserId>().expect("stored user id is a valid UUID"),
        )),
        (None, Some(t)) => Ok(AccessSubject::Team(
            t.parse::<TeamId>().expect("stored team id is a valid UUID"),
        )),
        _ => Err(DbError::Other(sqlx::Error::Decode(
            "branch_protection_push_allowlist row has neither or both subject columns set".into(),
        ))),
    }
}
