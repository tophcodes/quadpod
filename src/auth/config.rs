//! Authentication-time configuration: an optional trusted-issuer allowlist
//! and (parsed here, enforced in a later task) an expected audience.

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
/// `expected_audience`: parsed and stored here; enforcement lands in a later
/// task.
#[derive(Clone, Default)]
pub struct AuthConfig {
    pub trusted_issuers: Option<HashSet<String>>,
    pub expected_audience: Option<String>,
}

impl AuthConfig {
    /// Build from environment variables:
    /// - `POD_TRUSTED_ISSUERS`: comma-separated issuer URLs. Unset ->
    ///   `None` (open federation).
    /// - `POD_EXPECTED_AUDIENCE`: a single audience value. Unset -> `None`.
    pub fn from_env() -> Self {
        let trusted_issuers = std::env::var("POD_TRUSTED_ISSUERS").ok().map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        });
        let expected_audience = std::env::var("POD_EXPECTED_AUDIENCE").ok();
        Self {
            trusted_issuers,
            expected_audience,
        }
    }
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
