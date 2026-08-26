//! Verifying a Solid-OIDC access-token's JWS signature and claims.
//!
//! The token's header/payload are peeked at (unverified) only to pick the
//! issuer and the verifying key; every claim returned to the caller comes
//! from a payload whose signature has already been checked against a key
//! from the issuer's published JWKS (never a key embedded in the token).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use josekit::jwk::Jwk;
use josekit::jws::ES256;
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
/// The verification algorithm is pinned to ES256 regardless of what the
/// token's own header claims (its `alg` is never read for this purpose),
/// which forecloses `alg: none` and algorithm-confusion attacks.
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
    // verifier built for the pinned ES256 algorithm, not whatever `alg`
    // the header claims.
    let verifier = ES256
        .verifier_from_jwk(jwk)
        .map_err(|_| AuthError::BadSignature)?;
    let (verified_payload, _verified_header) =
        jwt::decode_with_verifier(token, &verifier).map_err(|_| AuthError::BadSignature)?;

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

/// Select the JWK to verify against: by `kid` if the header names one,
/// else the first signing-capable key (no `use`/`key_ops` restriction, or
/// one that explicitly allows verification).
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
