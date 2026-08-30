//! Instance-wide operator settings an administrator may change at runtime
//! without restarting the server (Phase 12). Each field has an
//! environment-derived default; a row in the `instance_settings` table
//! overrides it. This module is the pure gate: the recognised keys, how a
//! stored string parses back to a typed value, and how the two layers
//! combine. The async glue (reading the rows, the `ArcSwap` cache, the
//! admin API) lives in `edda-app`; nothing here does I/O.

use crate::registration::RegistrationMode;
use crate::repository::Visibility;

/// The `instance_settings.setting_key` values this module understands —
/// the shared contract between the storage layer and the admin API.
pub mod keys {
    pub const REGISTRATION_MODE: &str = "registration_mode";
    pub const DEFAULT_REPO_VISIBILITY: &str = "default_repo_visibility";
    pub const WELCOME_MESSAGE: &str = "welcome_message";
    pub const REQUIRE_SIGNIN_TO_VIEW: &str = "require_signin_to_view";
}

/// An instance welcome banner longer than this is rejected — it is a
/// short notice, not a page, and the MySQL column is a bounded
/// `VARCHAR(4096)`.
pub const MAX_WELCOME_MESSAGE_LEN: usize = 4000;

/// The environment-derived baseline, assembled by the config layer from
/// the `EDDA_*` variables. `Default` matches the built-in behaviour when
/// nothing is configured.
#[derive(Debug, Clone)]
pub struct InstanceSettingsDefaults {
    pub registration_mode: RegistrationMode,
    pub default_repo_visibility: Visibility,
    pub require_signin_to_view: bool,
}

impl Default for InstanceSettingsDefaults {
    fn default() -> Self {
        Self {
            registration_mode: RegistrationMode::Open,
            default_repo_visibility: Visibility::Private,
            require_signin_to_view: false,
        }
    }
}

/// The effective settings after stored overrides are applied to the
/// environment baseline — what the request path actually reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceSettings {
    pub registration_mode: RegistrationMode,
    pub default_repo_visibility: Visibility,
    /// A short banner shown on the sign-in / landing surface. `None` when
    /// unset or set to whitespace. No environment counterpart — this
    /// knob only exists in the database.
    pub welcome_message: Option<String>,
    pub require_signin_to_view: bool,
}

impl Default for InstanceSettings {
    /// The effective settings when nothing is configured and nothing is
    /// overridden — the same values [`InstanceSettingsDefaults::default`]
    /// describes. Used to seed the runtime cache before the first
    /// database read (and by tests that never touch settings).
    fn default() -> Self {
        Self::resolve(&InstanceSettingsDefaults::default(), &[])
    }
}

impl InstanceSettings {
    /// The effective settings for `defaults` with `overrides` (the
    /// `(setting_key, setting_value)` rows) applied on top. An override
    /// with an unrecognised key or an unparseable value is ignored — the
    /// baseline value stands — so one bad row can never fail the whole
    /// load.
    #[must_use]
    pub fn resolve(defaults: &InstanceSettingsDefaults, overrides: &[(String, String)]) -> Self {
        let mut settings = Self {
            registration_mode: defaults.registration_mode,
            default_repo_visibility: defaults.default_repo_visibility,
            welcome_message: None,
            require_signin_to_view: defaults.require_signin_to_view,
        };
        for (key, value) in overrides {
            match key.as_str() {
                keys::REGISTRATION_MODE => {
                    if let Some(mode) = RegistrationMode::parse(value) {
                        settings.registration_mode = mode;
                    }
                }
                keys::DEFAULT_REPO_VISIBILITY => {
                    if let Some(visibility) = Visibility::from_db_str(value.trim()) {
                        settings.default_repo_visibility = visibility;
                    }
                }
                keys::WELCOME_MESSAGE => {
                    let trimmed = value.trim();
                    settings.welcome_message = (!trimmed.is_empty()).then(|| trimmed.to_string());
                }
                keys::REQUIRE_SIGNIN_TO_VIEW => {
                    if let Some(flag) = parse_bool(value) {
                        settings.require_signin_to_view = flag;
                    }
                }
                _ => {}
            }
        }
        settings
    }

    /// The `(setting_key, setting_value)` rows that persist this whole
    /// value — what the admin "save settings" path writes. Every field is
    /// written (not just the ones that differ from the environment
    /// default) so the stored state stays a complete, self-describing
    /// snapshot that a later change to an env default cannot silently
    /// move.
    #[must_use]
    pub fn to_rows(&self) -> Vec<(String, String)> {
        vec![
            (
                keys::REGISTRATION_MODE.to_string(),
                self.registration_mode.as_db_str().to_string(),
            ),
            (
                keys::DEFAULT_REPO_VISIBILITY.to_string(),
                self.default_repo_visibility.as_db_str().to_string(),
            ),
            (
                keys::WELCOME_MESSAGE.to_string(),
                self.welcome_message.clone().unwrap_or_default(),
            ),
            (
                keys::REQUIRE_SIGNIN_TO_VIEW.to_string(),
                bool_str(self.require_signin_to_view).to_string(),
            ),
        ]
    }

    /// Rejects a settings value the storage layer would otherwise have to
    /// truncate or that is otherwise nonsensical.
    ///
    /// # Errors
    /// When the welcome message exceeds [`MAX_WELCOME_MESSAGE_LEN`].
    pub fn validate(&self) -> Result<(), String> {
        if let Some(message) = &self.welcome_message {
            if message.chars().count() > MAX_WELCOME_MESSAGE_LEN {
                return Err(format!(
                    "welcome message is {} characters; the maximum is {MAX_WELCOME_MESSAGE_LEN}",
                    message.chars().count()
                ));
            }
        }
        Ok(())
    }
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

const fn bool_str(flag: bool) -> &'static str {
    if flag {
        "true"
    } else {
        "false"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn defaults() -> InstanceSettingsDefaults {
        InstanceSettingsDefaults::default()
    }

    #[test]
    fn with_no_overrides_the_environment_baseline_stands() {
        let s = InstanceSettings::resolve(&defaults(), &[]);
        assert_eq!(s.registration_mode, RegistrationMode::Open);
        assert_eq!(s.default_repo_visibility, Visibility::Private);
        assert_eq!(s.welcome_message, None);
        assert!(!s.require_signin_to_view);
    }

    #[test]
    fn a_stored_row_overrides_the_baseline() {
        let overrides = vec![
            (keys::REGISTRATION_MODE.to_string(), "closed".to_string()),
            (
                keys::DEFAULT_REPO_VISIBILITY.to_string(),
                "public".to_string(),
            ),
            (
                keys::WELCOME_MESSAGE.to_string(),
                "  hello everyone  ".to_string(),
            ),
            (keys::REQUIRE_SIGNIN_TO_VIEW.to_string(), "yes".to_string()),
        ];
        let s = InstanceSettings::resolve(&defaults(), &overrides);
        assert_eq!(s.registration_mode, RegistrationMode::Closed);
        assert_eq!(s.default_repo_visibility, Visibility::Public);
        assert_eq!(s.welcome_message.as_deref(), Some("hello everyone"));
        assert!(s.require_signin_to_view);
    }

    #[test]
    fn an_unrecognised_key_or_bad_value_is_ignored_not_fatal() {
        let overrides = vec![
            ("something_new".to_string(), "whatever".to_string()),
            (keys::REGISTRATION_MODE.to_string(), "halfway".to_string()),
            (
                keys::REQUIRE_SIGNIN_TO_VIEW.to_string(),
                "maybe".to_string(),
            ),
            (keys::WELCOME_MESSAGE.to_string(), "   ".to_string()),
        ];
        let s = InstanceSettings::resolve(&defaults(), &overrides);
        // All fall back to the baseline.
        assert_eq!(s.registration_mode, RegistrationMode::Open);
        assert!(!s.require_signin_to_view);
        assert_eq!(s.welcome_message, None);
    }

    #[test]
    fn to_rows_round_trips_through_resolve() {
        let original = InstanceSettings {
            registration_mode: RegistrationMode::Approval,
            default_repo_visibility: Visibility::Public,
            welcome_message: Some("be nice".to_string()),
            require_signin_to_view: true,
        };
        let rows = original.to_rows();
        let round_tripped = InstanceSettings::resolve(&defaults(), &rows);
        assert_eq!(original, round_tripped);
    }

    #[test]
    fn an_empty_welcome_message_row_round_trips_as_none() {
        let original = InstanceSettings {
            registration_mode: RegistrationMode::Open,
            default_repo_visibility: Visibility::Private,
            welcome_message: None,
            require_signin_to_view: false,
        };
        assert_eq!(
            InstanceSettings::resolve(&defaults(), &original.to_rows()),
            original
        );
    }

    #[test]
    fn validate_rejects_an_over_long_welcome_message() {
        let s = InstanceSettings {
            registration_mode: RegistrationMode::Open,
            default_repo_visibility: Visibility::Private,
            welcome_message: Some("x".repeat(MAX_WELCOME_MESSAGE_LEN + 1)),
            require_signin_to_view: false,
        };
        assert!(s.validate().is_err());
    }
}
