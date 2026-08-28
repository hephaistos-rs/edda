//! Request-adjacent security mechanisms that aren't authorization
//! decisions (those live in `edda-auth`/`edda-domain`): the SSRF gate for
//! outbound webhook targets, and — from Phase 5 — the CSRF/Origin check.

pub mod ssrf;
