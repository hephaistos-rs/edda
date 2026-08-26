//! `releases`/`release_assets` persistence.

use edda_domain::{Release, ReleaseAsset, ReleaseAssetId, ReleaseId, RepositoryId, UserId};

use crate::{get_bool, get_i64, get_opt_i64, get_opt_string, get_string, Backend, DbPool};

pub struct NewRelease<'a> {
    pub tag_name: &'a str,
    pub target_commit: &'a str,
    pub name: &'a str,
    pub body: Option<&'a str>,
    pub draft: bool,
    pub prerelease: bool,
    pub author_id: UserId,
}

#[derive(Debug, thiserror::Error)]
pub enum InsertReleaseError {
    #[error("a release for this tag already exists")]
    AlreadyExists,
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

#[allow(clippy::too_many_arguments)]
fn row_to_release(
    id: String,
    repository_id: String,
    tag_name: String,
    target_commit: String,
    name: String,
    body: Option<String>,
    draft: bool,
    prerelease: bool,
    published_at: Option<i64>,
    author_id: String,
    created_at: i64,
) -> Release {
    Release {
        id: id.parse().expect("stored release id is a valid UUID"),
        repository_id: repository_id
            .parse()
            .expect("stored repository id is a valid UUID"),
        tag_name,
        target_commit,
        name,
        body,
        draft,
        prerelease,
        published_at,
        author_id: author_id.parse().expect("stored author id is a valid UUID"),
        created_at,
    }
}

const RELEASE_COLUMNS: &str = "id, repository_id, tag_name, target_commit, name, body, draft, prerelease, published_at, author_id, created_at";

fn row_to_release_from_sqlx(row: &sqlx::any::AnyRow) -> Result<Release, sqlx::Error> {
    Ok(row_to_release(
        get_string(row, "id")?,
        get_string(row, "repository_id")?,
        get_string(row, "tag_name")?,
        get_string(row, "target_commit")?,
        get_string(row, "name")?,
        get_opt_string(row, "body")?,
        get_bool(row, "draft")?,
        get_bool(row, "prerelease")?,
        get_opt_i64(row, "published_at")?,
        get_string(row, "author_id")?,
        get_i64(row, "created_at")?,
    ))
}

pub struct ReleaseRepo;

impl ReleaseRepo {
    pub async fn insert(
        pool: &DbPool,
        id: ReleaseId,
        repository_id: RepositoryId,
        new: NewRelease<'_>,
    ) -> Result<(), InsertReleaseError> {
        let id_text = id.to_string();
        let repository_id_text = repository_id.to_string();
        let author_id_text = new.author_id.to_string();
        let draft = if new.draft { 1i64 } else { 0i64 };
        let prerelease = if new.prerelease { 1i64 } else { 0i64 };
        let published_at = if new.draft {
            None
        } else {
            Some(crate::now_unix())
        };
        let created_at = crate::now_unix();

        let sql = match pool.backend {
            Backend::Postgres => {
                "INSERT INTO releases (id, repository_id, tag_name, target_commit, name, body, draft, prerelease, published_at, author_id, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO releases (id, repository_id, tag_name, target_commit, name, body, draft, prerelease, published_at, author_id, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            }
        };
        let result = sqlx::query(sql)
            .bind(&id_text)
            .bind(&repository_id_text)
            .bind(new.tag_name)
            .bind(new.target_commit)
            .bind(new.name)
            .bind(new.body)
            .bind(draft)
            .bind(prerelease)
            .bind(published_at)
            .bind(&author_id_text)
            .bind(created_at)
            .execute(&pool.any)
            .await;

        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
                Err(InsertReleaseError::AlreadyExists)
            }
            Err(err) => Err(InsertReleaseError::Db(err)),
        }
    }

    pub async fn find_by_id(pool: &DbPool, id: ReleaseId) -> Result<Option<Release>, sqlx::Error> {
        let sql = format!(
            "SELECT {RELEASE_COLUMNS} FROM releases WHERE id = {}",
            if pool.backend == Backend::Postgres {
                "$1"
            } else {
                "?"
            }
        );
        let row = sqlx::query(&sql)
            .bind(id.to_string())
            .fetch_optional(&pool.any)
            .await?;
        row.as_ref().map(row_to_release_from_sqlx).transpose()
    }

    pub async fn find_by_repository_and_tag(
        pool: &DbPool,
        repository_id: RepositoryId,
        tag_name: &str,
    ) -> Result<Option<Release>, sqlx::Error> {
        let sql = match pool.backend {
            Backend::Postgres => format!(
                "SELECT {RELEASE_COLUMNS} FROM releases WHERE repository_id = $1 AND tag_name = $2"
            ),
            Backend::Sqlite | Backend::MySql => format!(
                "SELECT {RELEASE_COLUMNS} FROM releases WHERE repository_id = ? AND tag_name = ?"
            ),
        };
        let row = sqlx::query(&sql)
            .bind(repository_id.to_string())
            .bind(tag_name)
            .fetch_optional(&pool.any)
            .await?;
        row.as_ref().map(row_to_release_from_sqlx).transpose()
    }

    /// Newest-published first (drafts last, since they have no
    /// `published_at` to sort by) — the repository's release list view.
    pub async fn list_for_repository(
        pool: &DbPool,
        repository_id: RepositoryId,
    ) -> Result<Vec<Release>, sqlx::Error> {
        let sql = match pool.backend {
            Backend::Postgres => format!(
                "SELECT {RELEASE_COLUMNS} FROM releases WHERE repository_id = $1 ORDER BY published_at IS NULL, published_at DESC, created_at DESC"
            ),
            Backend::Sqlite | Backend::MySql => format!(
                "SELECT {RELEASE_COLUMNS} FROM releases WHERE repository_id = ? ORDER BY published_at IS NULL, published_at DESC, created_at DESC"
            ),
        };
        let rows = sqlx::query(&sql)
            .bind(repository_id.to_string())
            .fetch_all(&pool.any)
            .await?;
        rows.iter().map(row_to_release_from_sqlx).collect()
    }
}

fn row_to_asset(
    id: String,
    release_id: String,
    filename: String,
    size_bytes: i64,
    content_type: String,
    storage_key: String,
    created_at: i64,
) -> ReleaseAsset {
    ReleaseAsset {
        id: id.parse().expect("stored release asset id is a valid UUID"),
        release_id: release_id
            .parse()
            .expect("stored release id is a valid UUID"),
        filename,
        size_bytes,
        content_type,
        storage_key,
        created_at,
    }
}

pub struct ReleaseAssetRepo;

impl ReleaseAssetRepo {
    pub async fn insert(
        pool: &DbPool,
        id: ReleaseAssetId,
        release_id: ReleaseId,
        filename: &str,
        size_bytes: i64,
        content_type: &str,
        storage_key: &str,
    ) -> Result<(), sqlx::Error> {
        let created_at = crate::now_unix();
        let sql = match pool.backend {
            Backend::Postgres => {
                "INSERT INTO release_assets (id, release_id, filename, size_bytes, content_type, storage_key, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO release_assets (id, release_id, filename, size_bytes, content_type, storage_key, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?)"
            }
        };
        sqlx::query(sql)
            .bind(id.to_string())
            .bind(release_id.to_string())
            .bind(filename)
            .bind(size_bytes)
            .bind(content_type)
            .bind(storage_key)
            .bind(created_at)
            .execute(&pool.any)
            .await?;
        Ok(())
    }

    pub async fn list_for_release(
        pool: &DbPool,
        release_id: ReleaseId,
    ) -> Result<Vec<ReleaseAsset>, sqlx::Error> {
        let sql = match pool.backend {
            Backend::Postgres => {
                "SELECT id, release_id, filename, size_bytes, content_type, storage_key, created_at
                 FROM release_assets WHERE release_id = $1 ORDER BY filename"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, release_id, filename, size_bytes, content_type, storage_key, created_at
                 FROM release_assets WHERE release_id = ? ORDER BY filename"
            }
        };
        let rows = sqlx::query(sql)
            .bind(release_id.to_string())
            .fetch_all(&pool.any)
            .await?;
        rows.into_iter()
            .map(|row| {
                Ok(row_to_asset(
                    get_string(&row, "id")?,
                    get_string(&row, "release_id")?,
                    get_string(&row, "filename")?,
                    get_i64(&row, "size_bytes")?,
                    get_string(&row, "content_type")?,
                    get_string(&row, "storage_key")?,
                    get_i64(&row, "created_at")?,
                ))
            })
            .collect()
    }

    pub async fn find_by_release_and_filename(
        pool: &DbPool,
        release_id: ReleaseId,
        filename: &str,
    ) -> Result<Option<ReleaseAsset>, sqlx::Error> {
        let sql = match pool.backend {
            Backend::Postgres => {
                "SELECT id, release_id, filename, size_bytes, content_type, storage_key, created_at
                 FROM release_assets WHERE release_id = $1 AND filename = $2"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, release_id, filename, size_bytes, content_type, storage_key, created_at
                 FROM release_assets WHERE release_id = ? AND filename = ?"
            }
        };
        let row = sqlx::query(sql)
            .bind(release_id.to_string())
            .bind(filename)
            .fetch_optional(&pool.any)
            .await?;
        row.map(|row| {
            Ok(row_to_asset(
                get_string(&row, "id")?,
                get_string(&row, "release_id")?,
                get_string(&row, "filename")?,
                get_i64(&row, "size_bytes")?,
                get_string(&row, "content_type")?,
                get_string(&row, "storage_key")?,
                get_i64(&row, "created_at")?,
            ))
        })
        .transpose()
    }
}
