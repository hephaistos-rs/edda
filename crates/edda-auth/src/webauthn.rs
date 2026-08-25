//! WebAuthn/passkey second factor. **Deferred**: the actual registration/
//! authentication ceremony (which needs a WebAuthn crypto library) is not
//! implemented in this pass — see the workspace root `Cargo.toml`'s
//! comment next to where `webauthn-rs` would otherwise be listed for why:
//! every available crate at the time of writing pulls in a native
//! OpenSSL dependency this build environment cannot satisfy, for a
//! feature that isn't one of this phase's required exit criteria (TOTP
//! is the required second factor; WebAuthn is an additional, optional
//! one).
//!
//! The persistence layer this feature will eventually sit on top of is
//! already built and tested: `edda_db::WebauthnRepo` and the
//! `webauthn_credentials` table. `list_for_user`/`delete` below are
//! usable today (e.g. so a settings page can show and revoke credentials
//! registered through some other means); registration/authentication are
//! not.

use edda_db::webauthn_repo::WebauthnCredentialRow;
use edda_db::{DbPool, WebauthnRepo};
use edda_domain::{UserId, WebauthnCredentialId};

pub async fn list(pool: &DbPool, user_id: UserId) -> Result<Vec<WebauthnCredentialRow>, sqlx::Error> {
    WebauthnRepo::list_for_user(pool, user_id).await
}

pub async fn revoke(
    pool: &DbPool,
    user_id: UserId,
    id: WebauthnCredentialId,
) -> Result<bool, sqlx::Error> {
    WebauthnRepo::delete(pool, user_id, id).await
}
