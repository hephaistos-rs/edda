//! Authentication (`backend`, `password`, `signup`, `tokens`, `ssh`,
//! `totp`, `oauth`, `webauthn`) and authorization (`authz`). `secret_box`
//! is the at-rest encryption used by `totp` to store a recoverable
//! secret; `pending_login` is the short-lived-token bridge between
//! "password verified" and "session established" that a second-factor
//! challenge (TOTP or WebAuthn) needs.

pub mod authz;
pub mod backend;
pub mod deploy_keys;
pub mod email_verification;
pub mod login_throttle;
pub mod oauth;
pub mod organization;
pub mod password;
pub mod password_reset;
pub mod pending_login;
pub mod secret_box;
pub mod signing_keys;
pub mod signup;
pub mod ssh;
pub mod tokens;
pub mod totp;
pub mod webauthn;
pub mod webhook_signing;

pub use authz::AuthorizationService;
pub use backend::{AuthError, Backend, Credentials, SessionUser};
pub use organization::{create_organization, CreateOrganizationError};
pub use signup::{signup, SignupError, SignupOutcome};

use edda_domain::{RegistrationPolicy, User};

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

/// Why an account that authenticated correctly still may not proceed —
/// the Phase 9 additions to `require_enabled`'s "may this account act at
/// all" question.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AccountStatusError {
    #[error("this account has been disabled")]
    Disabled,
    #[error("this account is awaiting administrator approval")]
    PendingApproval,
    #[error("verify your email address before you can push or create repositories")]
    EmailUnverified,
}

/// The login gate *beyond* a correct password: a disabled or
/// not-yet-approved account may not establish a session (`Approval`
/// registration mode). Email verification is deliberately **not**
/// checked here — an unverified account may sign in and browse; it just
/// can't push or create (see [`require_verified_for_write`]).
pub fn require_can_authenticate(status: &edda_db::AccountStatus) -> Result<(), AccountStatusError> {
    if status.is_disabled() {
        return Err(AccountStatusError::Disabled);
    }
    if !status.is_approved() {
        return Err(AccountStatusError::PendingApproval);
    }
    Ok(())
}

/// The push / repository-create gate: when the instance's
/// [`RegistrationPolicy`] requires email verification, an account whose
/// email is still unconfirmed is refused.
pub fn require_verified_for_write(
    status: &edda_db::AccountStatus,
    policy: &RegistrationPolicy,
) -> Result<(), AccountStatusError> {
    if policy.require_email_verification && !status.is_email_verified() {
        return Err(AccountStatusError::EmailUnverified);
    }
    Ok(())
}
