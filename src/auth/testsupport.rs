//! Hermetic (no-network) token minting for auth tests.
//!
//! `TestIdp` mints Solid-OIDC-shaped access tokens as an external IdP would;
//! `TestClient` holds a DPoP keypair and mints proofs. Later auth tasks'
//! tests build their fixtures on top of these.

use josekit::jwk::alg::ec::EcCurve;
use josekit::jwk::Jwk;
use josekit::jws::{JwsHeader, ES256};
use josekit::jwt::{self, JwtPayload};
use serde_json::json;

use super::jwks::Jwks;

/// A stand-in external Solid-OIDC IdP: an EC P-256 signing keypair, and a
/// method to mint access tokens as it would issue them.
pub struct TestIdp {
    private_jwk: Jwk,
    public_jwk: Jwk,
}

impl TestIdp {
    pub fn new() -> Self {
        let private_jwk = Jwk::generate_ec_key(EcCurve::P256).expect("generate IdP EC key");
        let public_jwk = private_jwk.to_public_key().expect("derive IdP public key");
        Self {
            private_jwk,
            public_jwk,
        }
    }

    /// The IdP's published (public) keys, as a `JwksResolver` would resolve them.
    pub fn jwks(&self) -> Jwks {
        Jwks {
            keys: vec![self.public_jwk.clone()],
        }
    }

    /// Mint a DPoP-bound Solid-OIDC access token (compact JWS), signed by
    /// this IdP's key, with `iss`/`sub`/`webid`/`exp`/`cnf.jkt` claims (no
    /// `aud` claim).
    pub fn mint_access_token(&self, webid: &str, dpop_jkt: &str, exp_unix: i64) -> String {
        self.mint_access_token_aud(webid, dpop_jkt, exp_unix, &[])
    }

    /// Mint a DPoP-bound Solid-OIDC access token as [`Self::mint_access_token`]
    /// does, plus an `aud` claim set to the JSON array `aud` (omitted
    /// entirely when `aud` is empty, matching `mint_access_token`).
    pub fn mint_access_token_aud(
        &self,
        webid: &str,
        dpop_jkt: &str,
        exp_unix: i64,
        aud: &[&str],
    ) -> String {
        let signer = ES256
            .signer_from_jwk(&self.private_jwk)
            .expect("build IdP signer");

        let mut header = JwsHeader::new();
        header.set_token_type("JWT");

        let mut payload = JwtPayload::new();
        payload.set_issuer("https://idp.example/");
        payload.set_subject(webid);
        payload
            .set_claim("iat", Some(json!(0)))
            .expect("set iat claim");
        payload
            .set_claim("exp", Some(json!(exp_unix)))
            .expect("set exp claim");
        payload
            .set_claim("webid", Some(json!(webid)))
            .expect("set webid claim");
        payload
            .set_claim("cnf", Some(json!({ "jkt": dpop_jkt })))
            .expect("set cnf claim");
        if !aud.is_empty() {
            payload
                .set_claim("aud", Some(json!(aud)))
                .expect("set aud claim");
        }

        jwt::encode_with_signer(&payload, &header, &signer).expect("sign access token")
    }
}

impl Default for TestIdp {
    fn default() -> Self {
        Self::new()
    }
}

/// A stand-in Solid-OIDC client: an EC P-256 DPoP keypair, and a method to
/// mint DPoP proofs as it would present them alongside an access token.
pub struct TestClient {
    private_jwk: Jwk,
    public_jwk: Jwk,
}

impl TestClient {
    pub fn new() -> Self {
        let private_jwk = Jwk::generate_ec_key(EcCurve::P256).expect("generate client EC key");
        let public_jwk = private_jwk
            .to_public_key()
            .expect("derive client public key");
        Self {
            private_jwk,
            public_jwk,
        }
    }

    /// The RFC 7638 thumbprint of this client's DPoP public key.
    pub fn jkt(&self) -> String {
        let x = self
            .public_jwk
            .parameter("x")
            .and_then(|v| v.as_str())
            .expect("EC public key has an x coordinate")
            .to_string();
        let y = self
            .public_jwk
            .parameter("y")
            .and_then(|v| v.as_str())
            .expect("EC public key has a y coordinate")
            .to_string();
        dpop_verifier::thumbprint_ec_p256(&x, &y).expect("compute RFC 7638 thumbprint")
    }

    /// Mint a DPoP proof (compact JWS) signed by this client's key, with an
    /// embedded public `jwk` header and `htu`/`htm`/`iat`/`jti` claims.
    pub fn mint_dpop(&self, htu: &str, htm: &str, iat_unix: i64, jti: &str) -> String {
        let signer = ES256
            .signer_from_jwk(&self.private_jwk)
            .expect("build client signer");

        let mut header = JwsHeader::new();
        header.set_token_type("dpop+jwt");
        header.set_jwk(self.public_jwk.clone());

        let mut payload = JwtPayload::new();
        payload
            .set_claim("htu", Some(json!(htu)))
            .expect("set htu claim");
        payload
            .set_claim("htm", Some(json!(htm)))
            .expect("set htm claim");
        payload
            .set_claim("iat", Some(json!(iat_unix)))
            .expect("set iat claim");
        payload
            .set_claim("jti", Some(json!(jti)))
            .expect("set jti claim");

        jwt::encode_with_signer(&payload, &header, &signer).expect("sign DPoP proof")
    }
}

impl Default for TestClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::jwks::JwksResolver;

    #[tokio::test]
    async fn idp_jwks_resolves_and_client_jkt_is_stable() {
        let idp = TestIdp::new();
        let resolver =
            crate::auth::jwks::StaticJwksResolver::new("https://idp.example/", idp.jwks());
        assert!(resolver.resolve("https://idp.example/").await.is_ok());
        assert!(resolver.resolve("https://other/").await.is_err());

        let client = TestClient::new();
        let jkt1 = client.jkt();
        assert_eq!(jkt1, client.jkt()); // deterministic thumbprint
        assert!(!jkt1.is_empty());

        // tokens are non-empty compact JWS strings (three dot-separated parts)
        let at = idp.mint_access_token("https://alice.example/card#me", &jkt1, 9_999_999_999);
        assert_eq!(at.matches('.').count(), 2);
        let proof = client.mint_dpop("https://pod.toph.so/foo", "GET", 1_000, "jti-1");
        assert_eq!(proof.matches('.').count(), 2);
    }
}
