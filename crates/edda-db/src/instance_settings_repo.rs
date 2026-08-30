//! `instance_settings` persistence — a tiny typed key/value table read
//! once at startup into an in-memory cache (`edda-app`'s
//! `InstanceSettingsService`) and rewritten whole whenever an
//! administrator saves the settings form. The domain
//! `edda_domain::instance_settings` module is the gate for which keys and
//! values are meaningful; this layer just stores strings.

use crate::{get_string, Backend, DbConn, DbError};

pub struct InstanceSettingsRepo;

impl InstanceSettingsRepo {
    /// Every stored override row, as `(setting_key, setting_value)`. The
    /// table has at most a handful of rows, so this is an unfiltered
    /// scan by design.
    pub async fn list<'c>(db: impl DbConn<'c>) -> Result<Vec<(String, String)>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let rows = sqlx::query("SELECT setting_key, setting_value FROM instance_settings")
            .fetch_all(&mut *h.conn())
            .await?;
        rows.iter()
            .map(|row| {
                Ok((
                    get_string(row, "setting_key")?,
                    get_string(row, "setting_value")?,
                ))
            })
            .collect()
    }

    /// One stored override value, or `None` when the key has no row.
    pub async fn get<'c>(db: impl DbConn<'c>, key: &str) -> Result<Option<String>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT setting_value FROM instance_settings WHERE setting_key = $1"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT setting_value FROM instance_settings WHERE setting_key = ?"
            }
        };
        let row = sqlx::query(sql)
            .bind(key)
            .fetch_optional(&mut *h.conn())
            .await?;
        match row {
            Some(row) => Ok(Some(get_string(&row, "setting_value")?)),
            None => Ok(None),
        }
    }

    /// Inserts or overwrites one override row, stamping who changed it
    /// (an admin user id, as text — informational, no foreign key).
    pub async fn upsert<'c>(
        db: impl DbConn<'c>,
        key: &str,
        value: &str,
        updated_by: Option<&str>,
    ) -> Result<(), DbError> {
        let mut h = crate::conn::open(db).await?;
        let now = crate::now_unix();
        let sql = match h.backend() {
            Backend::Postgres => {
                "INSERT INTO instance_settings (setting_key, setting_value, updated_at, updated_by) \
                 VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (setting_key) DO UPDATE \
                   SET setting_value = $2, updated_at = $3, updated_by = $4"
            }
            Backend::Sqlite => {
                "INSERT INTO instance_settings (setting_key, setting_value, updated_at, updated_by) \
                 VALUES (?, ?, ?, ?) \
                 ON CONFLICT (setting_key) DO UPDATE \
                   SET setting_value = excluded.setting_value, updated_at = excluded.updated_at, \
                       updated_by = excluded.updated_by"
            }
            Backend::MySql => {
                "INSERT INTO instance_settings (setting_key, setting_value, updated_at, updated_by) \
                 VALUES (?, ?, ?, ?) \
                 ON DUPLICATE KEY UPDATE \
                   setting_value = VALUES(setting_value), updated_at = VALUES(updated_at), \
                   updated_by = VALUES(updated_by)"
            }
        };
        sqlx::query(sql)
            .bind(key)
            .bind(value)
            .bind(now)
            .bind(updated_by)
            .execute(&mut *h.conn())
            .await?;
        Ok(())
    }

    /// Removes one override row, so the key falls back to its environment
    /// default. Returns whether a row was actually deleted.
    pub async fn delete<'c>(db: impl DbConn<'c>, key: &str) -> Result<bool, DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => "DELETE FROM instance_settings WHERE setting_key = $1",
            Backend::Sqlite | Backend::MySql => {
                "DELETE FROM instance_settings WHERE setting_key = ?"
            }
        };
        let affected = sqlx::query(sql)
            .bind(key)
            .execute(&mut *h.conn())
            .await?
            .rows_affected();
        Ok(affected > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn upsert_then_list_and_get_round_trip_and_delete_falls_back() {
        let pool = crate::test_pool().await;

        assert!(InstanceSettingsRepo::list(&pool).await.unwrap().is_empty());
        assert_eq!(
            InstanceSettingsRepo::get(&pool, "registration_mode")
                .await
                .unwrap(),
            None
        );

        InstanceSettingsRepo::upsert(&pool, "registration_mode", "closed", Some("admin-1"))
            .await
            .unwrap();
        // A second upsert on the same key overwrites, not duplicates.
        InstanceSettingsRepo::upsert(&pool, "registration_mode", "approval", Some("admin-2"))
            .await
            .unwrap();
        InstanceSettingsRepo::upsert(&pool, "welcome_message", "hi", None)
            .await
            .unwrap();

        let mut rows = InstanceSettingsRepo::list(&pool).await.unwrap();
        rows.sort();
        assert_eq!(
            rows,
            vec![
                ("registration_mode".to_string(), "approval".to_string()),
                ("welcome_message".to_string(), "hi".to_string()),
            ]
        );
        assert_eq!(
            InstanceSettingsRepo::get(&pool, "registration_mode")
                .await
                .unwrap()
                .as_deref(),
            Some("approval")
        );

        assert!(InstanceSettingsRepo::delete(&pool, "registration_mode")
            .await
            .unwrap());
        assert!(!InstanceSettingsRepo::delete(&pool, "registration_mode")
            .await
            .unwrap());
        assert_eq!(
            InstanceSettingsRepo::get(&pool, "registration_mode")
                .await
                .unwrap(),
            None
        );
    }
}
