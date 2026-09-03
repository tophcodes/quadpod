//! Verifying a Solid-OIDC access-token's JWS signature and claims.
//!
//! The token's header/payload are peeked at (unverified) only to pick the
//! issuer and the verifying key; every claim returned to the caller comes
//! from a payload whose signature has already been checked against a key
//! from the issuer's published JWKS (never a key embedded in the token).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use josekit::jwk::Jwk;
use josekit::jws::{JwsVerifier, ES256, RS256};
use josekit::jwt;
use serde_json::Value;

use super::jwks::JwksResolver;
use super::AuthError;

/// The verified claims of a Solid-OIDC access token.
pub struct AccessClaims {
    pub webid: String,
    pub jkt: String,
    pub issuer: String,
    pub audience: Vec<String>,
}

/// Verify `token`'s JWS signature against the issuer's published keys (via
/// `resolver`) and extract its claims. Fails closed: every decode, lookup,
/// or verification error returns the matching [`AuthError`] rather than a
/// silent pass.
///
/// The verification algorithm comes from the RESOLVED KEY, never from the
/// token's own header, which is what forecloses `alg: none` and
/// algorithm-confusion attacks: a header claiming `none` or `HS256` cannot
/// nominate the verifier it would like to be checked under, and josekit's
/// `decode_with_verifier` separately refuses a token whose header algorithm
/// disagrees with the verifier it was handed.
///
/// [`verifier_for`] is what maps the key to that algorithm, RS256 for RSA
/// and ES256 for EC P-256, the same two `op::keys::signer_for` signs with.
/// Before that pairing existed this function pinned ES256 outright, which
/// made an RS256 issuer indistinguishable from a forgery and, worse, made
/// this pod reject the tokens its own OP mints from an RSA key: the key set
/// signs RS256 for a key that declares it, publishes `RS256` in the JWKS,
/// and advertises it in `id_token_signing_alg_values_supported`, so the
/// verify side pinning ES256 was a pod that could not read its own
/// signature. ADR-3 settled the identical question one layer down for DPoP
/// proofs ("accepting only ES256 was stricter than the specification
/// without a reason"); this is that decision applied to the access token.
pub async fn verify_access_token(
    token: &str,
    resolver: &dyn JwksResolver,
    now_unix: i64,
) -> Result<AccessClaims, AuthError> {
    // Peek at the header's `kid` and the payload's `iss` WITHOUT trusting
    // the signature yet: these are used only to pick the issuer's JWKS and
    // a verifying key, never accepted as authenticated claims.
    let parts: Vec<&str> = token.split('.').collect();
    let [header_part, payload_part, _signature_part] = parts[..] else {
        return Err(AuthError::Malformed("not a compact JWS".to_string()));
    };
    let header = decode_segment(header_part)?;
    let payload = decode_segment(payload_part)?;

    let kid = header.get("kid").and_then(Value::as_str);
    let iss = payload
        .get("iss")
        .and_then(Value::as_str)
        .ok_or_else(|| AuthError::Malformed("missing iss claim".to_string()))?;

    let jwks = resolver.resolve(iss).await?;
    let jwk = select_key(&jwks.keys, kid)?;

    // Verify the JWS signature against the resolved PUBLIC key, with the
    // verifier the KEY selects, not whatever `alg` the header claims.
    let verifier = verifier_for(jwk)?;
    let (verified_payload, _verified_header) =
        jwt::decode_with_verifier(token, &*verifier).map_err(|_| AuthError::BadSignature)?;

    // From here on, every claim comes from `verified_payload`, its
    // signature has been checked against the issuer's key.
    let exp = verified_payload
        .claim("exp")
        .and_then(Value::as_i64)
        .ok_or_else(|| AuthError::Malformed("missing exp claim".to_string()))?;
    if exp <= now_unix {
        return Err(AuthError::Expired);
    }

    let webid = verified_payload
        .claim("webid")
        .and_then(Value::as_str)
        .ok_or_else(|| AuthError::Malformed("missing webid claim".to_string()))?
        .to_string();

    let jkt = verified_payload
        .claim("cnf")
        .and_then(|cnf| cnf.get("jkt"))
        .and_then(Value::as_str)
        .ok_or(AuthError::Binding)?
        .to_string();

    let issuer = verified_payload
        .issuer()
        .ok_or_else(|| AuthError::Malformed("missing iss claim".to_string()))?
        .to_string();

    let audience = parse_audience(verified_payload.claim("aud"));

    Ok(AccessClaims {
        webid,
        jkt,
        issuer,
        audience,
    })
}

/// Parse an `aud` claim value from a VERIFIED payload into a `Vec<String>`.
/// Solid-OIDC access tokens carry `aud` as either a single JSON string or a
/// JSON array of strings; a missing claim (or one of any other shape)
/// yields an empty `Vec` rather than an error, since `aud` enforcement is
/// optional (gated on `AuthConfig::expected_audience` in `authenticate`).
fn parse_audience(claim: Option<&Value>) -> Vec<String> {
    match claim {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

/// Peek at a compact JWS's payload `iss` claim WITHOUT verifying the
/// signature. This is the same untrusted peek `verify_access_token` performs
/// internally to pick a JWKS/key; it is exposed here for callers (the
/// trusted-issuer allowlist pre-check in `authenticate`) that need the raw
/// `iss` BEFORE any fetch happens. The returned value must NEVER be used to
/// accept a token, only ever to reject one early, since it is not yet backed
/// by a verified signature.
pub fn peek_untrusted_issuer(token: &str) -> Result<String, AuthError> {
    let parts: Vec<&str> = token.split('.').collect();
    let [_header_part, payload_part, _signature_part] = parts[..] else {
        return Err(AuthError::Malformed("not a compact JWS".to_string()));
    };
    let payload = decode_segment(payload_part)?;
    payload
        .get("iss")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| AuthError::Malformed("missing iss claim".to_string()))
}

/// Base64url(no-pad)-decode and JSON-parse one JWS segment.
fn decode_segment(segment: &str) -> Result<Value, AuthError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| AuthError::Malformed("invalid base64url segment".to_string()))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| AuthError::Malformed("invalid JSON segment".to_string()))
}

/// The verifier for `jwk`, chosen by the key's own type: RS256 for an RSA
/// key, ES256 for an EC P-256 one. The mirror of `op::keys::signer_for`, and
/// the two have to stay in step: a key this pod signs with and cannot verify
/// is a pod that rejects its own tokens.
///
/// Chosen from the KEY, never from the token header. That is the whole
/// safety argument for widening past one algorithm: the algorithm is a
/// property of the key the issuer published under its own `jwks_uri`, so a
/// token can no more choose it than it can choose the key. A header claiming
/// `none`, `HS256`, or anything else the resolved key does not support is
/// refused by `decode_with_verifier` before a signature is inspected.
///
/// A key of any other type is [`AuthError::UnsupportedKeyType`] rather than
/// [`AuthError::BadSignature`]: an issuer whose keys this pod cannot handle
/// is a configuration fact an operator can act on, and reporting it as a
/// forgery is exactly what makes it undiagnosable from the log.
fn verifier_for(jwk: &Jwk) -> Result<Box<dyn JwsVerifier>, AuthError> {
    let built: Result<Box<dyn JwsVerifier>, _> = match (jwk.key_type(), jwk.curve()) {
        ("RSA", _) => RS256
            .verifier_from_jwk(jwk)
            .map(|v| Box::new(v) as Box<dyn JwsVerifier>),
        ("EC", Some("P-256")) => ES256
            .verifier_from_jwk(jwk)
            .map(|v| Box::new(v) as Box<dyn JwsVerifier>),
        _ => return Err(AuthError::UnsupportedKeyType),
    };
    // A key of a type this pod handles that still will not build a verifier
    // (an RSA modulus under josekit's 2048-bit floor, a malformed member) is
    // a key nothing can be verified against, which is a refusal, not a
    // capability gap.
    built.map_err(|_| AuthError::BadSignature)
}

/// Select the JWK to verify against: by `kid` if the header names one,
/// else the first signing-capable key (no `use`/`key_ops` restriction, or
/// one that explicitly allows verification).
///
/// Whichever key this returns is also what picks the algorithm
/// ([`verifier_for`]), so a JWKS mixing key types stays coherent: the token
/// is checked under the algorithm of the key it selected, never under one it
/// asked for. The `kid`-less arm is best-effort by nature, and it is the
/// issuer's own JWKS that decides whether it can be: a set holding more than
/// one usable key and a token that names none of them is an issuer not
/// saying which key signed. Every issuer in practice sends `kid`.
fn select_key<'a>(keys: &'a [Jwk], kid: Option<&str>) -> Result<&'a Jwk, AuthError> {
    if let Some(kid) = kid {
        return keys
            .iter()
            .find(|k| k.key_id() == Some(kid))
            .ok_or(AuthError::MissingKey);
    }
    keys.iter()
        .find(|k| matches!(k.key_use(), None | Some("sig")) && k.is_for_key_operation("verify"))
        .ok_or(AuthError::MissingKey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{
        jwks::StaticJwksResolver,
        testsupport::{TestClient, TestIdp},
        AuthError,
    };

    fn setup() -> (StaticJwksResolver, TestClient, TestIdp) {
        let idp = TestIdp::new();
        let resolver = StaticJwksResolver::new("https://idp.example/", idp.jwks());
        (resolver, TestClient::new(), idp)
    }

    #[tokio::test]
    async fn valid_token_yields_webid_and_jkt() {
        let (resolver, client, idp) = setup();
        let jkt = client.jkt();
        let at = idp.mint_access_token("https://alice.example/card#me", &jkt, 9_999_999_999);
        let claims = verify_access_token(&at, &resolver, 1_000).await.unwrap();
        assert_eq!(claims.webid, "https://alice.example/card#me");
        assert_eq!(claims.jkt, jkt);
        assert_eq!(claims.issuer, "https://idp.example/");
        assert!(claims.audience.is_empty());
    }

    #[tokio::test]
    async fn token_with_aud_array_yields_audience() {
        let (resolver, client, idp) = setup();
        let jkt = client.jkt();
        let at = idp.mint_access_token_aud(
            "https://alice.example/card#me",
            &jkt,
            9_999_999_999,
            &["solid", "https://pod.toph.so/"],
        );
        let claims = verify_access_token(&at, &resolver, 1_000).await.unwrap();
        assert_eq!(
            claims.audience,
            vec!["solid".to_string(), "https://pod.toph.so/".to_string()]
        );
    }

    #[tokio::test]
    async fn expired_token_is_rejected() {
        let (resolver, client, idp) = setup();
        let at = idp.mint_access_token("https://alice.example/card#me", &client.jkt(), 500);
        assert!(matches!(
            verify_access_token(&at, &resolver, 1_000).await,
            Err(AuthError::Expired)
        ));
    }

    #[tokio::test]
    async fn unknown_issuer_is_rejected() {
        let (_r, client, idp) = setup();
        let empty = StaticJwksResolver::new("https://someone-else/", idp.jwks());
        let at = idp.mint_access_token("https://alice.example/card#me", &client.jkt(), 9_999_999_999);
        assert!(matches!(
            verify_access_token(&at, &empty, 1_000).await,
            Err(AuthError::UnknownIssuer)
        ));
    }

    #[tokio::test]
    async fn token_signed_by_wrong_key_is_rejected() {
        let (resolver, client, _idp) = setup();
        // a DIFFERENT idp signs, but resolver holds the ORIGINAL idp's jwks
        let attacker = TestIdp::new();
        let at = attacker.mint_access_token("https://alice.example/card#me", &client.jkt(), 9_999_999_999);
        assert!(matches!(
            verify_access_token(&at, &resolver, 1_000).await,
            Err(AuthError::BadSignature)
        ));
    }

    /// Hand-build a compact JWS from a header/payload/signature segment,
    /// bypassing josekit's signer entirely: this is how a forged,
    /// non-ES256 token is constructed for the algorithm-confusion tests
    /// below.
    fn build_jws(header: &Value, payload: &Value, signature_segment: &str) -> String {
        let encode = |v: &Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap());
        format!(
            "{}.{}.{}",
            encode(header),
            encode(payload),
            signature_segment
        )
    }

    fn forged_payload(webid: &str, jkt: &str) -> Value {
        serde_json::json!({
            "iss": "https://idp.example/",
            "webid": webid,
            "exp": 9_999_999_999i64,
            "cnf": { "jkt": jkt },
        })
    }

    /// `alg: none` with an empty signature segment is the classic
    /// algorithm-confusion forgery: if the verifier trusted the header's
    /// own `alg` claim, this would "verify" trivially since there's no
    /// signature to check at all. `verify_access_token` pins ES256
    /// regardless of what the header claims, so this must be rejected.
    #[tokio::test]
    async fn alg_none_forged_token_is_rejected() {
        let (resolver, client, _idp) = setup();
        let header = serde_json::json!({ "alg": "none", "typ": "JWT" });
        let payload = forged_payload("https://alice.example/card#me", &client.jkt());
        let forged = build_jws(&header, &payload, "");

        assert!(verify_access_token(&forged, &resolver, 1_000).await.is_err());
    }

    /// An HS256-"signed" token (arbitrary signature bytes, the pinned
    /// ES256 verifier must reject on the mismatched `alg` header before
    /// ever attempting to check the signature) must also be rejected. This
    /// is the other half of the algorithm-confusion boundary: a symmetric
    /// alg can't be substituted for the asymmetric one the resolver's key
    /// is for.
    #[tokio::test]
    async fn hs256_forged_token_is_rejected() {
        let (resolver, client, _idp) = setup();
        let header = serde_json::json!({ "alg": "HS256", "typ": "JWT" });
        let payload = forged_payload("https://alice.example/card#me", &client.jkt());
        let bogus_signature = URL_SAFE_NO_PAD.encode(b"not-a-real-hmac-signature");
        let forged = build_jws(&header, &payload, &bogus_signature);

        assert!(verify_access_token(&forged, &resolver, 1_000).await.is_err());
    }

    /// The regression this pairing exists for. RS256 is the algorithm OIDC
    /// Core requires every provider to support, and pinning ES256 rejected
    /// every issuer that uses it, as a forged signature.
    #[tokio::test]
    async fn an_rs256_token_from_an_rsa_issuer_verifies() {
        let idp = TestIdp::new_rsa();
        let client = TestClient::new();
        let resolver = StaticJwksResolver::new("https://idp.example/", idp.jwks());
        let jkt = client.jkt();
        let at = idp.mint_access_token("https://alice.example/card#me", &jkt, 9_999_999_999);

        let claims = verify_access_token(&at, &resolver, 1_000).await.unwrap();
        assert_eq!(claims.webid, "https://alice.example/card#me");
        assert_eq!(claims.jkt, jkt);
        assert_eq!(claims.issuer, "https://idp.example/");
    }

    /// Widening to a second algorithm must not let a token pick which one it
    /// is checked under. The key the resolver hands back decides, so a token
    /// signed by the wrong key type is refused rather than routed to a
    /// verifier that happens to match its header.
    #[tokio::test]
    async fn an_es256_token_does_not_verify_against_an_rsa_jwks() {
        let ec_idp = TestIdp::new();
        let rsa_idp = TestIdp::new_rsa();
        let client = TestClient::new();
        // The resolver publishes the RSA issuer's key; the token is ES256.
        let resolver = StaticJwksResolver::new("https://idp.example/", rsa_idp.jwks());
        let at = ec_idp.mint_access_token("https://alice.example/card#me", &client.jkt(), 9_999_999_999);

        assert!(matches!(
            verify_access_token(&at, &resolver, 1_000).await,
            Err(AuthError::BadSignature)
        ));
    }

    /// And the reverse direction, so neither arm is the one carrying the
    /// test on its own.
    #[tokio::test]
    async fn an_rs256_token_does_not_verify_against_an_ec_jwks() {
        let ec_idp = TestIdp::new();
        let rsa_idp = TestIdp::new_rsa();
        let client = TestClient::new();
        let resolver = StaticJwksResolver::new("https://idp.example/", ec_idp.jwks());
        let at = rsa_idp.mint_access_token("https://alice.example/card#me", &client.jkt(), 9_999_999_999);

        assert!(matches!(
            verify_access_token(&at, &resolver, 1_000).await,
            Err(AuthError::BadSignature)
        ));
    }

    /// A key type this pod cannot verify is a fact about the issuer's
    /// configuration, and it must not be reported as a forged signature:
    /// that is what makes an operator chase an attack that is not happening.
    #[test]
    fn an_unsupported_key_type_is_distinguished_from_a_bad_signature() {
        // OKP/Ed25519 is a real JWKS key type, and one `verifier_for` has no
        // arm for.
        let okp = Jwk::generate_ed_key(josekit::jwk::alg::ed::EdCurve::Ed25519).unwrap();
        assert!(matches!(
            verifier_for(&okp),
            Err(AuthError::UnsupportedKeyType)
        ));

        // An EC key on a curve other than P-256 is the same class of answer,
        // not an ES256 verification that fails later.
        let p384 = Jwk::generate_ec_key(josekit::jwk::alg::ec::EcCurve::P384).unwrap();
        assert!(matches!(
            verifier_for(&p384),
            Err(AuthError::UnsupportedKeyType)
        ));
    }

    /// An RSA key below josekit's 2048-bit floor is a key nothing can be
    /// verified against, which is a refusal rather than a capability gap:
    /// the pod handles RSA, this particular key is unusable.
    #[test]
    fn an_undersized_rsa_key_is_a_refusal_not_an_unsupported_type() {
        let weak = Jwk::generate_rsa_key(1024).unwrap();
        assert!(matches!(verifier_for(&weak), Err(AuthError::BadSignature)));
    }

    #[test]
    fn parse_audience_accepts_string_array_or_missing() {
        assert_eq!(
            parse_audience(Some(&serde_json::json!("solid"))),
            vec!["solid".to_string()]
        );
        assert_eq!(
            parse_audience(Some(&serde_json::json!(["solid", "https://rs.example/"]))),
            vec!["solid".to_string(), "https://rs.example/".to_string()]
        );
        assert_eq!(parse_audience(None), Vec::<String>::new());
    }
}
