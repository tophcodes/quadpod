//! Authentication-time configuration: an optional trusted-issuer allowlist
//! and an expected audience, both enforced in [`super::authenticate`].

use std::collections::HashSet;

/// Configuration consulted by [`super::authenticate`] before trusting an
/// access token's issuer.
///
/// `trusted_issuers`: if `Some(set)`, an access token whose `iss` is not in
/// `set` is rejected BEFORE any JWKS fetch is attempted — this shrinks the
/// SSRF surface (an untrusted issuer never triggers an outbound request) and
/// is defense-in-depth over the WebID-issuer binding, which remains the
/// primary control. If `None`, any issuer is allowed to proceed to the
/// WebID-issuer binding check (open federation).
///
/// `expected_audience`: if `Some(value)`, an access token whose (verified)
/// `aud` claim does not contain `value` is rejected. If `None`, no audience
/// check is performed (backward-compatible).
#[derive(Clone, Default)]
pub struct AuthConfig {
    pub trusted_issuers: Option<HashSet<String>>,
    pub expected_audience: Option<String>,
}

impl AuthConfig {
    /// Build from environment variables:
    /// - `POD_TRUSTED_ISSUERS`: comma-separated issuer URLs. Unset, empty,
    ///   or containing only blank/empty entries -> `None` (open federation).
    /// - `POD_EXPECTED_AUDIENCE`: a single audience value. Unset -> `None`.
    pub fn from_env() -> Self {
        let trusted_issuers = parse_trusted(std::env::var("POD_TRUSTED_ISSUERS").ok());
        let expected_audience = std::env::var("POD_EXPECTED_AUDIENCE").ok();
        Self {
            trusted_issuers,
            expected_audience,
        }
    }
}

/// Parses `POD_TRUSTED_ISSUERS`'s raw value into the allowlist set.
///
/// An unset variable (`None`) means "not configured" -> `None` (open
/// federation), which is unambiguous. But a SET variable that is empty, or
/// whose entries are all blank after trimming (e.g. `""`, `","`, `" , "`),
/// is almost certainly a misconfiguration (a blanked-out env var, a typo'd
/// separator) rather than a deliberate "trust nobody" — and `Some(∅)` would
/// make every issuer fail `set.contains(..)`, i.e. total auth lockout. So
/// that case is also folded into `None` rather than `Some(HashSet::new())`.
fn parse_trusted(raw: Option<String>) -> Option<HashSet<String>> {
    raw.and_then(|raw| {
        let set: HashSet<String> = raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        if set.is_empty() {
            None
        } else {
            Some(set)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_open_federation() {
        let cfg = AuthConfig::default();
        assert!(cfg.trusted_issuers.is_none());
        assert!(cfg.expected_audience.is_none());
    }

    #[test]
    fn unset_env_yields_none() {
        assert_eq!(parse_trusted(None), None);
    }

    #[test]
    fn empty_env_yields_none_not_empty_set() {
        assert_eq!(parse_trusted(Some(String::new())), None);
    }

    #[test]
    fn separators_only_env_yields_none() {
        assert_eq!(parse_trusted(Some(",,".to_string())), None);
        assert_eq!(parse_trusted(Some(" , , ".to_string())), None);
    }

    #[test]
    fn populated_env_yields_trimmed_set() {
        let expected: HashSet<String> = ["a".to_string(), "b".to_string()].into_iter().collect();
        assert_eq!(parse_trusted(Some("a, b".to_string())), Some(expected));
    }
}
