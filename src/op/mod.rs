//! The OP core: the pod's own signing keys and everything a verifier needs
//! to check a signature — the public JWKS, the OIDC discovery document, and
//! minting of DPoP-bound access tokens carrying a `webid` claim.
//!
//! This module issues; `crate::auth` verifies. Nothing here names an HTTP
//! type: the `/.well-known/` routes live in `crate::http` and call in.

pub mod discovery;
pub mod keys;
pub mod mint;

pub use keys::{KeyError, KeySet};
pub use mint::mint_access_token;
