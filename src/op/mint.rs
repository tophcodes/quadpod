//! Minting DPoP-bound access tokens. The claims mirror exactly what
//! `crate::auth::access_token` verifies; there is no HTTP path to this —
//! callers are the pod's own machinery (#23, #49, #58).

use oxigraph::model::NamedNode;

use crate::space::StorageSpace;

use super::KeySet;

/// Access-token lifetime. Fixed, not configurable: short-lived is the
/// design, and no consumer has asked for another value.
pub const ACCESS_TOKEN_TTL_SECS: i64 = 600;

/// A signed access token for `webid`, bound to the DPoP key whose RFC 7638
/// thumbprint is `jkt`. Claims: `iss` (the space root), `sub` and `webid`,
/// `aud: ["solid"]`, `iat` = `now_unix`, `exp` = `iat` +
/// [`ACCESS_TOKEN_TTL_SECS`], `cnf.jkt`, and a random `jti`.
pub fn mint_access_token(
    keys: &KeySet,
    space: &StorageSpace,
    webid: &NamedNode,
    jkt: &str,
    now_unix: i64,
) -> String {
    let _ = (KeySet::sign_jwt, space, webid, jkt, now_unix);
    let _ = keys;
    todo!()
}
