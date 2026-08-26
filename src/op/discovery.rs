//! The OIDC discovery document, what `/.well-known/openid-configuration`
//! serves. `authorization_endpoint` and `token_endpoint` are deliberately
//! absent until they exist (#58); `scopes_supported` carries `webid`, the
//! Solid-OIDC §10 conformance declaration.

use crate::space::{GraphName, StorageSpace};

use super::KeySet;

/// The discovery document for the OP at `space`'s root: `issuer`,
/// `jwks_uri` (`{issuer}.well-known/jwks.json`), `scopes_supported:
/// ["openid", "webid"]`, and `id_token_signing_alg_values_supported` from
/// the key set.
pub fn document(space: &StorageSpace, keys: &KeySet) -> serde_json::Value {
    let issuer = space.root().graph_iri().to_string();
    serde_json::json!({
        "issuer": issuer,
        "jwks_uri": format!("{issuer}.well-known/jwks.json"),
        "scopes_supported": ["openid", "webid"],
        "id_token_signing_alg_values_supported": keys.signing_algs(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::op::keys::remove_test_key_file;

    #[test]
    fn the_document_names_issuer_jwks_and_the_webid_scope() {
        let p = std::env::temp_dir().join(format!("op-disc-{}.json", uuid::Uuid::new_v4()));
        let keys = KeySet::load_or_generate(&p).unwrap();
        let space = crate::space::StorageSpace::new("https://pod.toph.so/").unwrap();
        let doc = document(&space, &keys);
        assert_eq!(doc["issuer"], "https://pod.toph.so/");
        assert_eq!(doc["jwks_uri"], "https://pod.toph.so/.well-known/jwks.json");
        assert_eq!(doc["scopes_supported"], serde_json::json!(["openid", "webid"]));
        assert_eq!(doc["id_token_signing_alg_values_supported"], serde_json::json!(["ES256"]));
        remove_test_key_file(&p);
    }

    // Deliberate until #58: naming an endpoint nothing answers would send
    // clients into a 404 they can blame on themselves.
    #[test]
    fn no_endpoint_is_advertised_before_it_exists() {
        let p = std::env::temp_dir().join(format!("op-disc-{}.json", uuid::Uuid::new_v4()));
        let keys = KeySet::load_or_generate(&p).unwrap();
        let space = crate::space::StorageSpace::new("https://pod.toph.so/").unwrap();
        let doc = document(&space, &keys);
        assert!(doc.get("authorization_endpoint").is_none());
        assert!(doc.get("token_endpoint").is_none());
        remove_test_key_file(&p);
    }
}
