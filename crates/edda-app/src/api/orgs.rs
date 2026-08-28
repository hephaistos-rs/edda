//! `/api/v1/orgs` — organization list / detail / create.

use axum::extract::{Path, State};
use axum::routing::get;
use axum::{Json, Router};

use edda_api_types::{CreateOrgRequest, OrganizationDto};

use super::Actor;
use crate::services::{OrganizationService, ServiceError};
use crate::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/orgs", get(list_mine).post(create))
        .route("/api/v1/orgs/{name}", get(get_one))
}

async fn list_mine(
    State(state): State<AppState>,
    actor: Actor,
) -> Result<Json<Vec<OrganizationDto>>, ServiceError> {
    let user_id = actor.require_user()?;
    let orgs = edda_db::OrganizationRepo::list_for_user(&state.pool, user_id).await?;
    let mut out = Vec::with_capacity(orgs.len());
    for org in orgs {
        let is_admin = state
            .authz
            .check_administer_organization(actor.context(), org.id)
            .await
            .is_ok();
        out.push(OrganizationDto {
            name: org.name,
            display_name: org.display_name,
            is_admin,
        });
    }
    Ok(Json(out))
}

async fn get_one(
    State(state): State<AppState>,
    actor: Actor,
    Path(name): Path<String>,
) -> Result<Json<OrganizationDto>, ServiceError> {
    let organization = state.authz.organization_by_name(&name).await?;
    let is_admin = state
        .authz
        .check_administer_organization(actor.context(), organization.id)
        .await
        .is_ok();
    Ok(Json(OrganizationDto {
        name: organization.name,
        display_name: organization.display_name,
        is_admin,
    }))
}

async fn create(
    State(state): State<AppState>,
    actor: Actor,
    Json(body): Json<CreateOrgRequest>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    OrganizationService::from_state(&state)
        .create(actor.context(), &body.name, body.display_name.as_deref())
        .await?;
    Ok(Json(()))
}
