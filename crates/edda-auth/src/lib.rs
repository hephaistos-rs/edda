//! Authentication (`backend`, `password`, `signup`, `tokens`, `ssh`) and
//! authorization (`authz`) — see plan.local.md §3.3/§6/§7.

pub mod authz;
pub mod backend;
pub mod password;
pub mod signup;
pub mod ssh;
pub mod tokens;

pub use authz::AuthorizationService;
pub use backend::{AuthError, Backend, Credentials, SessionUser};
pub use signup::{signup, SignupError};
