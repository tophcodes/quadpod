//! Resolving an issuer's JSON Web Key Set.

use std::collections::HashMap;

use async_trait::async_trait;
use josekit::jwk::Jwk;

use super::AuthError;

/// A set of JWKs published by an issuer.
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// Resolves an issuer's signing keys, so an access token's JWS can be
/// verified against the key that (claims to have) signed it.
#[async_trait]
pub trait JwksResolver: Send + Sync {
    async fn resolve(&self, issuer: &str) -> Result<Jwks, AuthError>;
}

/// An in-memory `JwksResolver` over a fixed issuer -> keys map. Used in
/// hermetic tests (no network) and can back a static production config.
pub struct StaticJwksResolver {
    map: HashMap<String, Jwks>,
}

impl StaticJwksResolver {
    pub fn new(issuer: &str, jwks: Jwks) -> Self {
        let mut map = HashMap::new();
        map.insert(issuer.to_string(), jwks);
        Self { map }
    }
}

#[async_trait]
impl JwksResolver for StaticJwksResolver {
    async fn resolve(&self, issuer: &str) -> Result<Jwks, AuthError> {
        self.map
            .get(issuer)
            .map(|jwks| Jwks {
                keys: jwks.keys.clone(),
            })
            .ok_or(AuthError::UnknownIssuer)
    }
}
