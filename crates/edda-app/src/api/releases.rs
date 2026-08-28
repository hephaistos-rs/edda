//! `/api/v1/repos/{owner}/{repo}/releases` — release list / detail /
//! create. Asset bytes go through `release_assets`'s streaming routes.

use axum::extract::{Path, State};
use axum::routing::get;
use axum::{Json, Router};

use edda_api_types::{CreateReleaseRequest, CreatedReleaseDto, ReleaseAssetDto, ReleaseDto};
use edda_db::DbPool;
use edda_domain::{ActorContext, Release, RepositoryId};

use super::{read_repo, Actor};
use crate::services::release::NewReleaseInput;
use crate::services::{ReleaseService, ServiceError};
use crate::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/repos/{owner}/{repo}/releases",
            get(list).post(create),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/releases/{tag_name}",
            get(get_one),
        )
}

async fn release_dto(pool: &DbPool, release: &Release) -> Result<ReleaseDto, ServiceError> {
    let author_username = edda_db::UserRepo::find_by_id(pool, release.author_id)
        .await?
        .map(|row| row.user.username)
        .unwrap_or_else(|| "(unknown)".to_string());
    let assets = edda_db::ReleaseAssetRepo::list_for_release(pool, release.id).await?;
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

/// Draft releases are visible only to write collaborators.
async fn caller_can_write(state: &AppState, actor: &ActorContext, repo_id: RepositoryId) -> bool {
    let Some(repository) = edda_db::RepositoryRepo::find_by_id(&state.pool, repo_id)
        .await
        .ok()
        .flatten()
    else {
        return false;
    };
    state.authz.check_write(actor, &repository).await.is_ok()
}

async fn list(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<Vec<ReleaseDto>>, ServiceError> {
    let repository = read_repo(&state, actor.context(), &owner, &repo).await?;
    let can_write = caller_can_write(&state, actor.context(), repository.id).await;
    let releases = edda_db::ReleaseRepo::list_for_repository(&state.pool, repository.id).await?;
    let mut out = Vec::new();
    for release in &releases {
        if release.draft && !can_write {
            continue;
        }
        out.push(release_dto(&state.pool, release).await?);
    }
    Ok(Json(out))
}

async fn get_one(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo, tag_name)): Path<(String, String, String)>,
) -> Result<Json<ReleaseDto>, ServiceError> {
    let repository = read_repo(&state, actor.context(), &owner, &repo).await?;
    let release =
        edda_db::ReleaseRepo::find_by_repository_and_tag(&state.pool, repository.id, &tag_name)
            .await?
            .ok_or(ServiceError::NotFound)?;
    if release.draft && !caller_can_write(&state, actor.context(), repository.id).await {
        return Err(ServiceError::NotFound);
    }
    Ok(Json(release_dto(&state.pool, &release).await?))
}

async fn create(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
    Json(body): Json<CreateReleaseRequest>,
) -> Result<Json<CreatedReleaseDto>, ServiceError> {
    actor.require_user()?;
    let tag_name = ReleaseService::from_state(&state)
        .create(
            actor.context(),
            &owner,
            &repo,
            NewReleaseInput {
                tag_name: body.tag_name,
                target: body.target,
                title: body.title,
                body: body.body,
                draft: body.draft,
                prerelease: body.prerelease,
            },
        )
        .await?;
    Ok(Json(CreatedReleaseDto { tag_name }))
}
