//! Verify-only Solid-OIDC + DPoP authentication.
//!
//! This module verifies credentials presented by callers (a DPoP-bound
//! Solid-OIDC access token) against an external IdP's published keys and
//! attaches an [`Agent`] to the request. It never issues tokens itself.

pub mod access_token;
pub mod agent;
pub mod authenticate;
pub mod dpop;
pub mod http_jwks;
pub mod jwks;
pub mod middleware;
pub mod safe_fetch;

#[cfg(test)]
pub mod testsupport;

pub use access_token::{verify_access_token, AccessClaims};
pub use agent::Agent;
pub use authenticate::authenticate;
pub use dpop::verify_dpop;
pub use http_jwks::HttpJwksResolver;
pub use jwks::{Jwks, JwksResolver, StaticJwksResolver};
pub use middleware::auth_layer;

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
    #[error("blocked outbound fetch: {0}")]
    FetchBlocked(String),
}
