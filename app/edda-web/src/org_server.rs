//! Organization management — Dioxus server functions, the same pattern
//! `webhook_server`/`release_server` already use. Team management lives in
//! `team_server`; this module only covers the organization entity itself.

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OrganizationDto {
    pub name: String,
    pub display_name: Option<String>,
    /// Whether the requesting user administers this organization (member
    /// of its Owners team) — drives whether the UI shows management
    /// actions (create team, ...). `false` for an anonymous viewer.
    pub is_admin: bool,
}

#[cfg(feature = "server")]
fn require_login(
    auth: &axum_login::AuthSession<edda_auth::Backend>,
) -> Result<edda_domain::UserId, ServerFnError> {
    match &auth.user {
        Some(session_user) => Ok(session_user.user.id),
        None => Err(ServerFnError::new("login required")),
    }
}

#[post("/api/orgs", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "organization.create", skip_all, err, fields(org.name = %name))]
pub async fn create_organization(
    name: String,
    display_name: Option<String>,
) -> Result<(), ServerFnError> {
    let user_id = require_login(&auth)?;
    let shared = crate::shared::get();
    let display_name = display_name.filter(|d| !d.trim().is_empty());
    edda_auth::create_organization(&shared.pool, &name, display_name.as_deref(), user_id)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(())
}

#[get("/api/orgs/:name", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "organization.get", skip_all, err, fields(org.name = %name))]
pub async fn get_organization(name: String) -> Result<OrganizationDto, ServerFnError> {
    let shared = crate::shared::get();
    let organization = shared
        .authz
        .organization_by_name(&name)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    let is_admin = match &auth.user {
        Some(session_user) => {
            let actor = edda_domain::ActorContext::User(session_user.user.id);
            shared
                .authz
                .check_administer_organization(&actor, organization.id)
                .await
                .is_ok()
        }
        None => false,
    };
    Ok(OrganizationDto {
        name: organization.name,
        display_name: organization.display_name,
        is_admin,
    })
}

#[get("/api/orgs", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "organization.list_mine", skip_all, err)]
pub async fn list_my_organizations() -> Result<Vec<OrganizationDto>, ServerFnError> {
    let user_id = require_login(&auth)?;
    let shared = crate::shared::get();
    let actor = edda_domain::ActorContext::User(user_id);
    let orgs = edda_db::OrganizationRepo::list_for_user(&shared.pool, user_id)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    let mut dtos = Vec::with_capacity(orgs.len());
    for org in orgs {
        let is_admin = shared
            .authz
            .check_administer_organization(&actor, org.id)
            .await
            .is_ok();
        dtos.push(OrganizationDto {
            name: org.name,
            display_name: org.display_name,
            is_admin,
        });
    }
    Ok(dtos)
}
