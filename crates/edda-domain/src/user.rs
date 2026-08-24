use crate::ids::UserId;

/// A user account's identity fields. Deliberately excludes `password_hash`
/// and any other authentication credential: those are `edda-auth`'s
/// concern (it fetches them from `edda-db` directly when verifying a
/// login), not something the rest of the domain — which only ever needs
/// to know *who* a user is, never how they prove it — should have to
/// carry around or accidentally serialize.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: UserId,
    pub username: String,
    pub email: String,
}
