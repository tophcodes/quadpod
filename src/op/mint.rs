//! Minting DPoP-bound access tokens. The claims mirror exactly what
//! `crate::auth::access_token` verifies; there is no HTTP path to this:
//! callers are the pod's own machinery (#23, #49, #58).

use josekit::jwt::JwtPayload;
use oxigraph::model::NamedNode;
use serde_json::json;

use crate::space::{GraphName, StorageSpace};

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
    let issuer = space.root().graph_iri().to_string();
    let mut payload = JwtPayload::new();
    payload.set_issuer(&issuer);
    payload.set_subject(webid.as_str());
    // `set_claim` rather than `set_audience`: the latter collapses a
    // one-element list to a bare JSON string, and the contract above is the
    // array `["solid"]`.
    payload
        .set_claim("aud", Some(json!(["solid"])))
        .expect("set aud claim");
    payload
        .set_claim("webid", Some(json!(webid.as_str())))
        .expect("set webid claim");
    payload
        .set_claim("cnf", Some(json!({ "jkt": jkt })))
        .expect("set cnf claim");
    payload
        .set_claim("jti", Some(json!(uuid::Uuid::new_v4().to_string())))
        .expect("set jti claim");
    // `iat`/`exp` as raw numeric claims, not josekit's `SystemTime`-taking
    // setters: the verifier reads `exp` as `as_i64`, and a `SystemTime`
    // round-trip cannot represent the caller's `now_unix` exactly.
    payload
        .set_claim("iat", Some(json!(now_unix)))
        .expect("set iat claim");
    payload
        .set_claim("exp", Some(json!(now_unix + ACCESS_TOKEN_TTL_SECS)))
        .expect("set exp claim");
    keys.sign_jwt(&payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{verify_access_token, AuthError, Jwks, StaticJwksResolver};
    use crate::op::keys::remove_test_key_file;

    /// A fresh key-file path per test. Cleaned up through
    /// [`crate::op::keys::remove_test_key_file`], the only file removal
    /// available here: `src/op/` may touch the filesystem in `keys.rs` alone.
    fn temp_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("op-mint-{}.json", uuid::Uuid::new_v4()))
    }

    /// The published public half, in the shape a `JwksResolver` hands back.
    fn resolver_for(keys: &KeySet) -> StaticJwksResolver {
        let jwks_value = keys.public_jwks();
        let parsed: Vec<josekit::jwk::Jwk> = jwks_value["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| josekit::jwk::Jwk::from_map(v.as_object().unwrap().clone()).unwrap())
            .collect();
        StaticJwksResolver::new("https://pod.toph.so/", Jwks { keys: parsed })
    }

    #[tokio::test]
    async fn a_minted_token_passes_the_pods_own_verifier() {
        let p = temp_path();
        let keys = KeySet::load_or_generate(&p).unwrap();
        let space = crate::space::StorageSpace::new("https://pod.toph.so/").unwrap();
        let webid = NamedNode::new("https://pod.toph.so/profile#it").unwrap();
        let now = 1_700_000_000_i64;

        let token = mint_access_token(&keys, &space, &webid, "some-jkt-thumbprint", now);

        let resolver = resolver_for(&keys);
        let claims = verify_access_token(&token, &resolver, now + 10)
            .await
            .expect("verifies");
        assert_eq!(claims.webid, webid.as_str());
        assert_eq!(claims.jkt, "some-jkt-thumbprint");
        assert_eq!(claims.issuer, "https://pod.toph.so/");
        assert_eq!(claims.audience, vec!["solid".to_string()]);

        // On the wire `aud` must be the array, not the bare string josekit's
        // `set_audience` writes for a single value: the verifier's
        // `parse_audience` accepts both, so the shape can only be pinned on
        // the token itself.
        use base64::Engine as _;
        let payload_segment = token.split('.').nth(1).expect("compact JWS has a payload");
        let raw: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(payload_segment)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["aud"], serde_json::json!(["solid"]));

        remove_test_key_file(&p);
    }

    #[tokio::test]
    async fn a_minted_token_expires_after_the_ttl() {
        let p = temp_path();
        let keys = KeySet::load_or_generate(&p).unwrap();
        let space = crate::space::StorageSpace::new("https://pod.toph.so/").unwrap();
        let webid = NamedNode::new("https://pod.toph.so/profile#it").unwrap();
        let now = 1_700_000_000_i64;

        let token = mint_access_token(&keys, &space, &webid, "jkt", now);

        let resolver = resolver_for(&keys);
        assert!(
            matches!(
                verify_access_token(&token, &resolver, now + ACCESS_TOKEN_TTL_SECS + 1).await,
                Err(AuthError::Expired)
            ),
            "past exp must refuse as expired"
        );
        remove_test_key_file(&p);
    }
}
