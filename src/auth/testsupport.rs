//! Hermetic (no-network) token minting for auth tests.
//!
//! `TestIdp` mints Solid-OIDC-shaped access tokens as an external IdP would;
//! `TestClient` holds a DPoP keypair and mints proofs. Later auth tasks'
//! tests build their fixtures on top of these.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use josekit::jwk::alg::ec::EcCurve;
use josekit::jwk::Jwk;
use josekit::jws::{JwsHeader, JwsSigner, ES256, RS256};
use josekit::jwt::{self, JwtPayload};
use serde_json::json;
use sha2::{Digest, Sha256};

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

/// A stand-in Solid-OIDC client: a DPoP keypair — EC P-256 signing ES256
/// ([`TestClient::new`]) or RSA signing RS256 ([`TestClient::new_rsa`]) — and
/// methods to mint DPoP proofs as it would present them alongside an access
/// token.
pub struct TestClient {
    private_jwk: Jwk,
    public_jwk: Jwk,
}

impl TestClient {
    pub fn new() -> Self {
        let private_jwk = Jwk::generate_ec_key(EcCurve::P256).expect("generate client EC key");
        Self::from_private(private_jwk)
    }

    /// A client whose DPoP key is RSA, so its proofs are signed `RS256` —
    /// the shape the official Solid conformance harness presents, and the one
    /// this pod refused before `verify_rs256_proof` existed.
    ///
    /// 2048 bits because that is the floor `josekit` enforces on the
    /// verifying side; a smaller key could not be used to test acceptance.
    /// See [`Self::new_rsa_with_bits`] for exercising the *rejection* of a
    /// smaller key.
    pub fn new_rsa() -> Self {
        let private_jwk = Jwk::generate_rsa_key(2048).expect("generate client RSA key");
        Self::from_private(private_jwk)
    }

    /// A client whose DPoP key is RSA at an arbitrary bit size, including
    /// below the 2048-bit floor `josekit` enforces.
    ///
    /// Key *generation* has no such floor (`Jwk::generate_rsa_key` delegates
    /// to `RsaKeyPair::generate`, which does not check key size), but
    /// `josekit`'s `RS256.signer_from_jwk` enforces the floor on the
    /// *signing* side too — so a client built with a sub-2048-bit key here
    /// cannot mint a genuinely-signed proof via [`Self::mint_dpop`] (its
    /// `signer()` would panic). Use
    /// [`Self::mint_dpop_with_dummy_signature`] instead: the rejection this
    /// exists to test happens while building the verifier, before any
    /// signature is ever inspected, so a genuine one is not needed.
    pub fn new_rsa_with_bits(bits: u32) -> Self {
        let private_jwk = Jwk::generate_rsa_key(bits).expect("generate client RSA key");
        Self::from_private(private_jwk)
    }

    fn from_private(private_jwk: Jwk) -> Self {
        let public_jwk = private_jwk
            .to_public_key()
            .expect("derive client public key");
        Self {
            private_jwk,
            public_jwk,
        }
    }

    /// The RFC 7638 thumbprint of this client's DPoP public key — what an IdP
    /// would put in the access token's `cnf.jkt`.
    ///
    /// The EC arm delegates to `dpop-verifier`, which is also what the pod's
    /// ES256 path uses, so that half is a round-trip rather than a check. The
    /// RSA arm is deliberately **not** a call into
    /// `auth::dpop::thumbprint_rsa`: it spells RFC 7638 §3.2's required
    /// members for an RSA key (`e`, `kty`, `n`, lexicographically ordered, no
    /// whitespace) out literally, so a mistake in the pod's own computation
    /// shows up as a failing binding test instead of cancelling itself out on
    /// both sides of the comparison.
    pub fn jkt(&self) -> String {
        match self.public_jwk.key_type() {
            "EC" => {
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
            "RSA" => {
                let n = self
                    .public_jwk
                    .parameter("n")
                    .and_then(|v| v.as_str())
                    .expect("RSA public key has a modulus");
                let e = self
                    .public_jwk
                    .parameter("e")
                    .and_then(|v| v.as_str())
                    .expect("RSA public key has an exponent");
                let canonical = format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#);
                URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
            }
            other => panic!("TestClient has no thumbprint rule for kty {other}"),
        }
    }

    fn signer(&self) -> Box<dyn JwsSigner> {
        match self.public_jwk.key_type() {
            "EC" => Box::new(
                ES256
                    .signer_from_jwk(&self.private_jwk)
                    .expect("build client ES256 signer"),
            ),
            "RSA" => Box::new(
                RS256
                    .signer_from_jwk(&self.private_jwk)
                    .expect("build client RS256 signer"),
            ),
            other => panic!("TestClient has no signer for kty {other}"),
        }
    }

    /// Mint a DPoP proof (compact JWS) signed by this client's key, with an
    /// embedded public `jwk` header and `htu`/`htm`/`iat`/`jti` claims.
    pub fn mint_dpop(&self, htu: &str, htm: &str, iat_unix: i64, jti: &str) -> String {
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

        jwt::encode_with_signer(&payload, &header, &*self.signer()).expect("sign DPoP proof")
    }

    /// Mint a DPoP proof whose JOSE header claims `claimed_alg`, while the
    /// signature is still a genuine one produced by this client's real key
    /// under its real algorithm ([`Self::alg`]).
    ///
    /// This is the algorithm-confusion shape, and the reason it is minted
    /// this way rather than with a junk signature: a rejection has to come
    /// from the alg↔key-type rule, not from the signature failing to verify
    /// anyway. Both directions come out of this one helper — an EC client
    /// claiming `RS256` is an RS256 header over an EC JWK (with a genuine
    /// ES256 signature), and an RSA client claiming `ES256` is an ES256
    /// header over an RSA JWK (with a genuine RS256 signature). It also mints
    /// the `none` and `HS256` cases, where an honest key and an honest
    /// signature are relabelled with an algorithm no DPoP verifier may ever
    /// accept.
    ///
    /// Built by hand rather than through `jwt::encode_with_signer`, which
    /// always writes the signer's own `alg` into the header — the header and
    /// the signature are exactly what `mint_dpop` would produce, except for
    /// that one field.
    pub fn mint_dpop_claiming_alg(
        &self,
        claimed_alg: &str,
        htu: &str,
        htm: &str,
        iat_unix: i64,
        jti: &str,
    ) -> String {
        let header = json!({
            "typ": "dpop+jwt",
            "alg": claimed_alg,
            "jwk": serde_json::Value::Object(self.public_jwk.as_ref().clone()),
        });
        let payload = json!({ "htu": htu, "htm": htm, "iat": iat_unix, "jti": jti });

        let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = self
            .signer()
            .sign(signing_input.as_bytes())
            .expect("sign DPoP proof");

        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
    }

    /// Mint a proof shaped exactly like [`Self::mint_dpop`], but with an
    /// arbitrary signature segment instead of a genuine one.
    ///
    /// Exists only for [`Self::new_rsa_with_bits`] keys below 2048 bits:
    /// `josekit`'s own `RS256.signer_from_jwk` refuses to sign with such a
    /// key at all (see that method's doc comment), so a genuine signature
    /// cannot be produced. `verify_rs256_proof` rejects a too-small key while
    /// building its own verifier, strictly before it ever reads the
    /// signature bytes, so an arbitrary placeholder here still exercises
    /// exactly the rejection under test.
    pub fn mint_dpop_with_dummy_signature(
        &self,
        htu: &str,
        htm: &str,
        iat_unix: i64,
        jti: &str,
    ) -> String {
        let header = json!({
            "typ": "dpop+jwt",
            "alg": "RS256",
            "jwk": serde_json::Value::Object(self.public_jwk.as_ref().clone()),
        });
        let payload = json!({ "htu": htu, "htm": htm, "iat": iat_unix, "jti": jti });

        let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
        format!(
            "{header_b64}.{payload_b64}.{}",
            URL_SAFE_NO_PAD.encode([0u8; 32])
        )
    }

    /// Mint a genuinely-signed RS256 proof whose embedded `jwk` header
    /// carries this client's PRIVATE key material (`d`, plus the RSA CRT
    /// parameters) — the shape RFC 9449 §4.2 forbids a DPoP proof from ever
    /// containing. Used to test `verify_rs256_proof`'s explicit `d` check.
    pub fn mint_dpop_with_private_jwk_in_header(
        &self,
        htu: &str,
        htm: &str,
        iat_unix: i64,
        jti: &str,
    ) -> String {
        let mut header = JwsHeader::new();
        header.set_token_type("dpop+jwt");
        header.set_jwk(self.private_jwk.clone());

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

        jwt::encode_with_signer(&payload, &header, &*self.signer()).expect("sign DPoP proof")
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
