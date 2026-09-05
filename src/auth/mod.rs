//! Verify-only Solid-OIDC + DPoP authentication.
//!
//! This module verifies credentials presented by callers (a DPoP-bound
//! Solid-OIDC access token) against the published keys of the issuer the
//! token names (which may be this pod itself, when it runs as its own OP
//! (`crate::op`)), and attaches an [`Agent`] to the request. It never issues
//! tokens itself.

pub mod access_token;
pub mod agent;
pub mod authenticate;
mod cache;
pub mod config;
pub mod dpop;
pub mod http_jwks;
pub mod jwks;
pub mod middleware;
pub mod safe_fetch;
pub mod webid_issuer;

#[cfg(test)]
pub mod testsupport;

pub use access_token::{peek_untrusted_issuer, verify_access_token, AccessClaims};
pub use agent::Agent;
pub use authenticate::{authenticate, AuthDeps};
pub use config::AuthConfig;
pub use dpop::{verify_dpop, InMemoryJtiReplayStore, JtiReplayStore};
pub use http_jwks::HttpJwksResolver;
pub use jwks::{Jwks, JwksResolver, StaticJwksResolver};
pub use middleware::auth_layer;
pub use safe_fetch::GuardedClient;
pub use webid_issuer::{HttpWebIdIssuers, StaticWebIdIssuers, WebIdIssuerVerifier, SOLID_OIDC_ISSUER};

use thiserror::Error;

/// Failure modes for credential verification. Any variant here means the
/// caller-presented credentials were rejected; the request must not be
/// treated as authenticated.
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("malformed credential: {0}")]
    Malformed(String),
    #[error("bad signature")]
    BadSignature,
    #[error("expired")]
    Expired,
    #[error("unknown issuer")]
    UnknownIssuer,
    #[error("invalid DPoP proof: {0}")]
    DpopInvalid(String),
    #[error("proof-of-possession binding mismatch")]
    Binding,
    #[error("no signing key available for this token")]
    MissingKey,
    #[error("issuer's signing key is of a type this pod cannot verify")]
    UnsupportedKeyType,
    #[error("blocked outbound fetch: {0}")]
    FetchBlocked(String),
    #[error("webid does not authorize this token's issuer")]
    IssuerNotAuthorized,
    #[error("issuer is not in the trusted-issuer allowlist")]
    UntrustedIssuer,
    #[error("access token audience does not include the expected value")]
    WrongAudience,
}
