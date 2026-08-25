//! Authentication (`backend`, `password`, `signup`, `tokens`, `ssh`,
//! `totp`, `oauth`) and authorization (`authz`). `secret_box` is the
//! at-rest encryption used by `totp` to store a recoverable secret;
//! `pending_login` is the short-lived-token bridge between "password
//! verified" and "session established" that a second-factor challenge
//! needs.

pub mod authz;
pub mod backend;
pub mod oauth;
pub mod password;
pub mod pending_login;
pub mod secret_box;
pub mod signup;
pub mod ssh;
pub mod tokens;
pub mod totp;

pub use authz::AuthorizationService;
pub use backend::{AuthError, Backend, Credentials, SessionUser};
pub use signup::{signup, SignupError};

use edda_domain::User;

/// The one shared "is this account allowed to authenticate at all"
/// gate, called from every credential-verification path this workspace
/// has (password/session in `backend::Backend::authenticate`, PAT in
/// `tokens::authenticate`, SSH key in `ssh::authenticate`, OAuth in
/// `oauth`) — so there is exactly one definition of what a disabled
/// account sees, not five slightly-different ad hoc checks. Deliberately
/// takes an already-fetched `&User` rather than re-querying anything;
/// callers already have one by the time they'd call this.
pub fn require_enabled(user: &User) -> Result<(), DisabledAccountError> {
    if user.disabled_at.is_some() {
        Err(DisabledAccountError)
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("this account has been disabled")]
pub struct DisabledAccountError;
