//! Organization creation — the one place `edda_domain::validation::
//! is_valid_username` and the cross-table collision check (organizations
//! share `users.username`'s global identifier namespace) are both applied
//! to a *new* organization name. `edda-db`'s
//! `OrganizationRepo::insert` only enforces uniqueness among organization
//! names themselves (a real `UNIQUE` index); the other half — "not already
//! a username" — has no single database constraint that can span both
//! tables, so it's a check-then-insert here instead, the same trade-off
//! `NotificationRepo::insert_if_new` already accepts elsewhere in this
//! codebase. `signup` performs the same check in the other direction (a
//! new *user* can't collide with an existing organization either).

use edda_db::organization_repo::InsertOrganizationError;
use edda_db::{DbPool, OrganizationRepo, UserRepo};
use edda_domain::validation::is_valid_username;
use edda_domain::{Organization, OrganizationId, TeamId, UserId};

#[derive(Debug, thiserror::Error)]
pub enum CreateOrganizationError {
    #[error("that name is already taken")]
    NameTaken,
    #[error("organization names follow the same rules as usernames: 1-39 characters, start and end with a letter or digit, and contain only letters, digits, '-' or '_'")]
    InvalidName,
    #[error(transparent)]
    Db(#[from] edda_db::DbError),
}

impl From<InsertOrganizationError> for CreateOrganizationError {
    fn from(err: InsertOrganizationError) -> Self {
        match err {
            InsertOrganizationError::NameTaken => CreateOrganizationError::NameTaken,
            InsertOrganizationError::Db(err) => CreateOrganizationError::Db(err),
        }
    }
}

/// Creates an organization and its default Owners team (see
/// `edda_db::OrganizationRepo::insert`'s own doc comment), with
/// `creating_user_id` as the Owners team's first member. Returns the new
/// `Organization` alongside its Owners team's id, since callers
/// immediately need it (`edda-web`'s org-creation server function has
/// nothing else to look it up by yet).
#[tracing::instrument(name = "authentication.create_organization", skip_all, err)]
pub async fn create_organization(
    pool: &DbPool,
    name: &str,
    display_name: Option<&str>,
    creating_user_id: UserId,
) -> Result<(Organization, TeamId), CreateOrganizationError> {
    let name = name.trim();
    if !is_valid_username(name) {
        return Err(CreateOrganizationError::InvalidName);
    }
    if UserRepo::find_by_username(pool, name).await?.is_some() {
        return Err(CreateOrganizationError::NameTaken);
    }

    let id = OrganizationId::new();
    let owners_team_id =
        OrganizationRepo::insert(pool, id, name, display_name, creating_user_id).await?;
    Ok((
        Organization {
            id,
            name: name.to_string(),
            display_name: display_name.map(str::to_string),
        },
        owners_team_id,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn insert_user(pool: &DbPool, username: &str) -> UserId {
        let id = UserId::new();
        UserRepo::insert(
            pool,
            id,
            username,
            &format!("{username}@example.com"),
            "unused",
        )
        .await
        .expect("insert user");
        id
    }

    #[tokio::test]
    async fn creating_an_organization_makes_its_creator_the_sole_owners_team_member() {
        let pool = edda_db::test_pool().await;
        let alice = insert_user(&pool, "alice").await;

        let (org, owners_team_id) = create_organization(&pool, "acme", Some("Acme Corp"), alice)
            .await
            .expect("create organization");
        assert_eq!(org.name, "acme");

        let members = edda_db::TeamMemberRepo::list_members(&pool, owners_team_id)
            .await
            .expect("list owners team members");
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].id, alice);
    }

    /// The org-name/username shared-uniqueness check rejects a collision
    /// in either direction.
    #[tokio::test]
    async fn organization_and_username_namespaces_collide_in_both_directions() {
        let pool = edda_db::test_pool().await;
        let alice = insert_user(&pool, "alice").await;
        let bob = insert_user(&pool, "bob").await;

        // Direction 1: can't create an organization named after an
        // existing user.
        let err = create_organization(&pool, "alice", None, bob)
            .await
            .unwrap_err();
        assert!(matches!(err, CreateOrganizationError::NameTaken));

        // Direction 2: can't sign up a user named after an existing
        // organization.
        create_organization(&pool, "acme", None, alice)
            .await
            .expect("create organization");
        let err = crate::signup::signup(&pool, "acme", "someone@example.com", "password")
            .await
            .unwrap_err();
        assert!(matches!(err, crate::SignupError::UsernameTaken));

        // A genuinely free name still works for both.
        create_organization(&pool, "widgets", None, alice)
            .await
            .expect("create a differently-named organization");
    }

    #[tokio::test]
    async fn two_organizations_cannot_share_a_name_case_insensitively() {
        let pool = edda_db::test_pool().await;
        let alice = insert_user(&pool, "alice").await;
        create_organization(&pool, "acme", None, alice)
            .await
            .expect("create organization");
        let err = create_organization(&pool, "ACME", None, alice)
            .await
            .unwrap_err();
        assert!(matches!(err, CreateOrganizationError::NameTaken));
    }
}
