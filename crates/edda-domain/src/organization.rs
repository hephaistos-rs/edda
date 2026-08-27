use crate::ids::OrganizationId;

/// A repository owner that isn't an individual account. Organization
/// `name` shares the global identifier namespace with `User.username` —
/// `alice` can't be both a user and an organization at once, since both
/// resolve the same `{owner}` URL/clone-path segment — enforced by a
/// combined lookup at creation time (`edda-auth`'s signup and
/// organization-creation paths both check both tables), not by this type
/// itself, which has no I/O of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Organization {
    pub id: OrganizationId,
    pub name: String,
    pub display_name: Option<String>,
}
