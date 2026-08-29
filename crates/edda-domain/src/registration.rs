//! Instance registration policy — the pure rules that decide whether a
//! signup is allowed, whether a new account is auto-approved or queued
//! for an admin, and whether an email's domain is on the allowlist. The
//! async glue that consults this (`edda_auth::signup`, the admin
//! approval queue) lives in `edda-auth` / `edda-app`; nothing here does
//! I/O.
//!
//! Sourced from the environment for now (`EDDA_REGISTRATION_MODE`,
//! `EDDA_ALLOWED_EMAIL_DOMAINS`, `EDDA_REQUIRE_EMAIL_VERIFICATION`); the
//! in-DB override (`instance_settings`) is Phase 12.

/// How open the instance is to new self-service accounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RegistrationMode {
    /// Anyone may sign up and is immediately active (today's behaviour).
    #[default]
    Open,
    /// Anyone may sign up, but the account is inactive until an
    /// administrator approves it.
    Approval,
    /// Self-service signup is refused entirely; only an administrator can
    /// create accounts.
    Closed,
}

impl RegistrationMode {
    /// Parses `EDDA_REGISTRATION_MODE` / a stored `instance_settings`
    /// value. Case-insensitive.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "open" => Some(Self::Open),
            "approval" => Some(Self::Approval),
            "closed" => Some(Self::Closed),
            _ => None,
        }
    }

    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Approval => "approval",
            Self::Closed => "closed",
        }
    }
}

/// The full policy, assembled by the config layer and carried on the app
/// state. `Default` is "wide open, no verification" — exactly how the
/// instance behaved before Phase 9.
#[derive(Debug, Clone, Default)]
pub struct RegistrationPolicy {
    pub mode: RegistrationMode,
    /// Lowercased bare domains (`example.com`). Empty = any domain.
    pub allowed_email_domains: Vec<String>,
    /// When set, a new account's email must be confirmed (via
    /// `email_verification_tokens`) before it may push or create
    /// repositories.
    pub require_email_verification: bool,
}

impl RegistrationPolicy {
    /// Whether self-service signup is offered at all.
    #[must_use]
    pub fn permits_signup(&self) -> bool {
        self.mode != RegistrationMode::Closed
    }

    /// Whether a freshly-created account is active immediately (`Open` /
    /// `Closed`-via-admin) or must wait for approval (`Approval`).
    #[must_use]
    pub fn auto_approves(&self) -> bool {
        self.mode != RegistrationMode::Approval
    }

    /// Whether `email`'s domain is acceptable. An empty allowlist accepts
    /// everything; otherwise the part after the last `@` must match one
    /// of the configured domains, case-insensitively.
    #[must_use]
    pub fn email_domain_allowed(&self, email: &str) -> bool {
        if self.allowed_email_domains.is_empty() {
            return true;
        }
        let Some(domain) = email.rsplit('@').next().filter(|d| !d.is_empty()) else {
            return false;
        };
        let domain = domain.to_ascii_lowercase();
        self.allowed_email_domains
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(&domain))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_parses_case_insensitively_and_rejects_junk() {
        assert_eq!(
            RegistrationMode::parse("Open"),
            Some(RegistrationMode::Open)
        );
        assert_eq!(
            RegistrationMode::parse("  APPROVAL "),
            Some(RegistrationMode::Approval)
        );
        assert_eq!(
            RegistrationMode::parse("closed"),
            Some(RegistrationMode::Closed)
        );
        assert_eq!(RegistrationMode::parse("halfway"), None);
    }

    #[test]
    fn default_policy_is_wide_open() {
        let p = RegistrationPolicy::default();
        assert!(p.permits_signup());
        assert!(p.auto_approves());
        assert!(!p.require_email_verification);
        assert!(p.email_domain_allowed("anyone@anywhere.example"));
    }

    #[test]
    fn closed_mode_refuses_signup_but_still_auto_approves_admin_created_accounts() {
        let p = RegistrationPolicy {
            mode: RegistrationMode::Closed,
            ..Default::default()
        };
        assert!(!p.permits_signup());
        assert!(p.auto_approves());
    }

    #[test]
    fn approval_mode_permits_signup_but_does_not_auto_approve() {
        let p = RegistrationPolicy {
            mode: RegistrationMode::Approval,
            ..Default::default()
        };
        assert!(p.permits_signup());
        assert!(!p.auto_approves());
    }

    #[test]
    fn the_domain_allowlist_matches_the_part_after_the_last_at_sign() {
        let p = RegistrationPolicy {
            allowed_email_domains: vec!["example.com".to_string(), "corp.example".to_string()],
            ..Default::default()
        };
        assert!(p.email_domain_allowed("alice@example.com"));
        assert!(p.email_domain_allowed("bob@EXAMPLE.COM"));
        assert!(p.email_domain_allowed("weird@name@corp.example"));
        assert!(!p.email_domain_allowed("mallory@evil.example"));
        assert!(!p.email_domain_allowed("no-at-sign"));
        assert!(!p.email_domain_allowed("trailing@"));
    }
}
