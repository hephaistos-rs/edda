//! `/api/v1/repos/{owner}/{repo}/releases` — release creation. Asset
//! bytes go through `release_assets`'s streaming routes.

use axum::extract::{Path, State};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use super::Actor;
use crate::services::release::NewReleaseInput;
use crate::services::{ReleaseService, ServiceError};
use crate::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/api/v1/repos/{owner}/{repo}/releases", post(create))
}

#[derive(Deserialize)]
pub struct CreateReleaseBody {
    pub tag_name: String,
    /// Branch or commit the tag should point at, if it doesn't exist yet.
    pub target: String,
    pub title: String,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub prerelease: bool,
}

#[derive(Serialize)]
pub struct CreatedReleaseDto {
    pub tag_name: String,
}

async fn create(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
    Json(body): Json<CreateReleaseBody>,
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
