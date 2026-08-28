//! Release metadata — Dioxus server functions (create/list/get). Asset
//! *bytes* go through `edda_app::release_assets`'s raw axum routes
//! instead (streaming upload/download needs a real request/response
//! body, which Dioxus's `#[get]`/`#[post]` macros don't support — same
//! reasoning as `edda_app::lfs`).

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReleaseAssetDto {
    pub filename: String,
    pub size_bytes: i64,
    pub content_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReleaseDto {
    pub tag_name: String,
    pub target_commit: String,
    pub name: String,
    pub body_html: Option<String>,
    pub draft: bool,
    pub prerelease: bool,
    pub published_at: Option<i64>,
    pub author_username: String,
    pub created_at: i64,
    pub assets: Vec<ReleaseAssetDto>,
}

#[cfg(feature = "server")]
async fn release_dto(
    pool: &edda_db::DbPool,
    release: &edda_domain::Release,
) -> Result<ReleaseDto, ServerFnError> {
    let author_username = edda_db::UserRepo::find_by_id(pool, release.author_id)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?
        .map(|row| row.user.username)
        .ok_or_else(|| ServerFnError::new("that account no longer exists"))?;
    let assets = edda_db::ReleaseAssetRepo::list_for_release(pool, release.id)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(ReleaseDto {
        tag_name: release.tag_name.clone(),
        target_commit: release.target_commit.clone(),
        name: release.name.clone(),
        body_html: release.body.as_deref().map(edda_render::markdown::render),
        draft: release.draft,
        prerelease: release.prerelease,
        published_at: release.published_at,
        author_username,
        created_at: release.created_at,
        assets: assets
            .into_iter()
            .map(|asset| ReleaseAssetDto {
                filename: asset.filename,
                size_bytes: asset.size_bytes,
                content_type: asset.content_type,
            })
            .collect(),
    })
}

/// `draft`/`prerelease` bundled into one struct param rather than two
/// more adjacent top-level `bool`s — two unlabeled booleans in a row at
/// a call site is exactly the kind of easy-to-transpose footgun a small
/// named struct avoids for free.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReleaseFlags {
    pub draft: bool,
    pub prerelease: bool,
}

/// Resolves `tag_name` against the repository's git data if it already
/// exists (a release created against an existing tag), else creates it
/// pointing at `target` (a branch name or commit id) — see
/// `edda_git::tags`'s own doc comment for the resolution rules.
#[allow(clippy::too_many_arguments)]
#[post("/api/repos/:owner/:name/releases", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "release.create", skip_all, err, fields(repo.owner = %owner, repo.name = %name))]
pub async fn create_release(
    owner: String,
    name: String,
    tag_name: String,
    target: String,
    title: String,
    body: Option<String>,
    flags: ReleaseFlags,
) -> Result<String, ServerFnError> {
    let ReleaseFlags { draft, prerelease } = flags;
    let shared = crate::shared::get();
    let (repository, actor) = crate::server::require_write_access(&auth, &owner, &name).await?;
    let user_id = actor
        .user_id()
        .expect("require_write_access only returns ActorContext::User");

    let tag_name = tag_name.trim().to_string();
    let title = title.trim().to_string();
    if tag_name.is_empty() {
        return Err(ServerFnError::new("a tag name is required"));
    }
    if title.is_empty() {
        return Err(ServerFnError::new("a release title is required"));
    }

    let identity = format!("{owner}/{name}");
    let target_commit = match edda_git::resolve_tag(shared.store.as_ref(), &identity, &tag_name) {
        Ok(commit) => commit,
        Err(_) => edda_git::create_tag(shared.store.as_ref(), &identity, &tag_name, &target)
            .map_err(|err| ServerFnError::new(err.to_string()))?,
    };

    let id = edda_domain::ReleaseId::new();
    edda_db::ReleaseRepo::insert(
        &shared.pool,
        id,
        repository.id,
        edda_db::NewRelease {
            tag_name: &tag_name,
            target_commit: &target_commit,
            name: &title,
            body: body.as_deref().filter(|b| !b.trim().is_empty()),
            draft,
            prerelease,
            author_id: user_id,
        },
    )
    .await
    .map_err(|err| ServerFnError::new(err.to_string()))?;

    Ok(tag_name)
}

#[get("/api/repos/:owner/:name/releases", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "release.list", skip_all, err, fields(repo.owner = %owner, repo.name = %name))]
pub async fn list_releases(owner: String, name: String) -> Result<Vec<ReleaseDto>, ServerFnError> {
    let repository = crate::server::require_read_access(&auth, &owner, &name).await?;
    let shared = crate::shared::get();
    let can_write = match &auth.user {
        Some(session_user) => shared
            .authz
            .check_write(
                &edda_domain::ActorContext::User(session_user.user.id),
                &repository,
            )
            .await
            .is_ok(),
        None => false,
    };

    let releases = edda_db::ReleaseRepo::list_for_repository(&shared.pool, repository.id)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    let mut out = Vec::new();
    for release in &releases {
        if release.draft && !can_write {
            continue;
        }
        out.push(release_dto(&shared.pool, release).await?);
    }
    Ok(out)
}

#[get("/api/repos/:owner/:name/releases/:tag_name", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "release.get", skip_all, err, fields(repo.owner = %owner, repo.name = %name))]
pub async fn get_release(
    owner: String,
    name: String,
    tag_name: String,
) -> Result<ReleaseDto, ServerFnError> {
    let repository = crate::server::require_read_access(&auth, &owner, &name).await?;
    let shared = crate::shared::get();
    let release =
        edda_db::ReleaseRepo::find_by_repository_and_tag(&shared.pool, repository.id, &tag_name)
            .await
            .map_err(|err| ServerFnError::new(err.to_string()))?
            .ok_or_else(|| ServerFnError::new("no such release"))?;

    if release.draft {
        let Some(session_user) = &auth.user else {
            return Err(ServerFnError::new("no such release"));
        };
        let actor = edda_domain::ActorContext::User(session_user.user.id);
        shared
            .authz
            .check_write(&actor, &repository)
            .await
            .map_err(|_| ServerFnError::new("no such release"))?;
    }

    release_dto(&shared.pool, &release).await
}
