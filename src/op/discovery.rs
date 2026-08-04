//! The OIDC discovery document — what `/.well-known/openid-configuration`
//! serves. `authorization_endpoint` and `token_endpoint` are deliberately
//! absent until they exist (#58); `scopes_supported` carries `webid`, the
//! Solid-OIDC §10 conformance declaration.

use crate::space::StorageSpace;

use super::KeySet;

/// The discovery document for the OP at `space`'s root: `issuer`,
/// `jwks_uri` (`{issuer}.well-known/jwks.json`), `scopes_supported:
/// ["openid", "webid"]`, and `id_token_signing_alg_values_supported` from
/// the key set.
pub fn document(space: &StorageSpace, keys: &KeySet) -> serde_json::Value {
    let _ = (space, keys);
    todo!()
}
