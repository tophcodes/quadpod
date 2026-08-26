//! Authentication-time configuration: an optional trusted-issuer allowlist
//! and an expected audience, both enforced in [`super::authenticate`].
//!
//! Built from process configuration by [`crate::config::Config::auth_config`],
//! which owns the environment/flag parsing.

use std::collections::HashSet;

/// Configuration consulted by [`super::authenticate`] before trusting an
/// access token's issuer.
///
/// `trusted_issuers`: if `Some(set)`, an access token whose `iss` is not in
/// `set` is rejected BEFORE any JWKS fetch is attempted, this shrinks the
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_open_federation() {
        let cfg = AuthConfig::default();
        assert!(cfg.trusted_issuers.is_none());
        assert!(cfg.expected_audience.is_none());
    }
}
