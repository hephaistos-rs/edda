//! Request-adjacent security mechanisms that aren't authorization
//! decisions (those live in `edda-auth`/`edda-domain`): the SSRF gate for
//! outbound webhook targets, and the CSRF/Origin check on cookie-
//! authenticated state-changing requests.

pub mod origin;
pub mod ssrf;
