//! Orchestrating credential verification into an [`Agent`] for a request.

use super::access_token::verify_access_token;
use super::dpop::verify_dpop;
use super::jwks::JwksResolver;
use super::webid_issuer::WebIdIssuerVerifier;
use super::{Agent, AuthError};

/// Authenticate a request from its `Authorization` and `DPoP` headers.
///
/// If both headers are absent, the request is unauthenticated (`Agent::Public`).
/// Otherwise, valid Solid-OIDC credentials are required: `Authorization` MUST
/// use the `DPoP` scheme (a `Bearer` token, or any other scheme, is rejected —
/// Solid-OIDC access tokens are DPoP-bound, never usable as bearer tokens),
/// and a `DPoP` proof header MUST be present. The access token is verified,
/// then its `webid` claim must be authorized by the token's issuer: a
/// signature-verified token only proves the token is self-consistent with
/// SOME issuer's key — it does NOT prove that issuer is entitled to speak
/// for the claimed webid. Without this check an attacker running their own
/// IdP could mint a token naming any victim's webid and it would verify
/// fine. `webid_verifier` closes that hole by dereferencing the webid's
/// profile and confirming it declares the token's issuer via
/// `solid:oidcIssuer`. Only then is the DPoP proof verified and bound to
/// the token's `cnf.jkt`. Any failure along the way is an error — this
/// never falls back to `Public` once credentials were presented. Fails
/// closed.
pub async fn authenticate(
    auth_header: Option<&str>,
    dpop_header: Option<&str>,
    htm: &str,
    htu: &str,
    resolver: &dyn JwksResolver,
    webid_verifier: &dyn WebIdIssuerVerifier,
    now_unix: i64,
) -> Result<Agent, AuthError> {
    if auth_header.is_none() && dpop_header.is_none() {
        return Ok(Agent::Public);
    }

    let token = parse_dpop_scheme(auth_header)?;
    let proof = dpop_header
        .ok_or_else(|| AuthError::DpopInvalid("missing DPoP proof header".to_string()))?;

    let claims = verify_access_token(token, resolver, now_unix).await?;

    if !webid_verifier
        .authorizes(&claims.webid, &claims.issuer)
        .await?
    {
        return Err(AuthError::IssuerNotAuthorized);
    }

    verify_dpop(proof, htu, htm, &claims.jkt, now_unix).await?;

    Ok(Agent::WebId(claims.webid))
}

/// Parse an `Authorization` header of the form `DPoP <token>`, requiring the
/// `DPoP` scheme exactly (a `Bearer` scheme, or any other, is rejected).
fn parse_dpop_scheme(auth_header: Option<&str>) -> Result<&str, AuthError> {
    let header = auth_header
        .ok_or_else(|| AuthError::DpopInvalid("missing Authorization header".to_string()))?;
    let (scheme, token) = header
        .split_once(' ')
        .ok_or_else(|| AuthError::Malformed("malformed Authorization header".to_string()))?;
    if scheme != "DPoP" {
        return Err(AuthError::DpopInvalid(format!(
            "unsupported Authorization scheme: {scheme}"
        )));
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{
        jwks::StaticJwksResolver,
        testsupport::{TestClient, TestIdp},
        webid_issuer::StaticWebIdIssuers,
        Agent,
    };

    #[tokio::test]
    async fn no_credentials_is_public() {
        let idp = TestIdp::new();
        let resolver = StaticJwksResolver::new("https://idp.example/", idp.jwks());
        let webids = StaticWebIdIssuers::new();
        let agent = authenticate(
            None,
            None,
            "GET",
            "https://pod.toph.so/foo",
            &resolver,
            &webids,
            1_000,
        )
        .await
        .unwrap();
        assert_eq!(agent, Agent::Public);
    }

    #[tokio::test]
    async fn valid_credentials_yield_webid() {
        let idp = TestIdp::new();
        let client = TestClient::new();
        let resolver = StaticJwksResolver::new("https://idp.example/", idp.jwks());
        let mut webids = StaticWebIdIssuers::new();
        webids.allow("https://alice.example/card#me", "https://idp.example/");
        let at = idp.mint_access_token(
            "https://alice.example/card#me",
            &client.jkt(),
            9_999_999_999,
        );
        let proof = client.mint_dpop("https://pod.toph.so/foo", "GET", 1_000, "jti-x");
        let agent = authenticate(
            Some(&format!("DPoP {at}")),
            Some(&proof),
            "GET",
            "https://pod.toph.so/foo",
            &resolver,
            &webids,
            1_010,
        )
        .await
        .unwrap();
        assert_eq!(agent, Agent::WebId("https://alice.example/card#me".into()));
    }

    #[tokio::test]
    async fn token_without_dpop_proof_is_error() {
        let idp = TestIdp::new();
        let client = TestClient::new();
        let resolver = StaticJwksResolver::new("https://idp.example/", idp.jwks());
        let webids = StaticWebIdIssuers::new();
        let at = idp.mint_access_token(
            "https://alice.example/card#me",
            &client.jkt(),
            9_999_999_999,
        );
        assert!(authenticate(
            Some(&format!("DPoP {at}")),
            None,
            "GET",
            "https://pod.toph.so/foo",
            &resolver,
            &webids,
            1_010,
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn issuer_not_authorized_by_webid_is_rejected() {
        let idp = crate::auth::testsupport::TestIdp::new();
        let client = crate::auth::testsupport::TestClient::new();
        // `idp` here plays the role of the attacker's IdP: it mints a
        // validly self-signed token naming alice's webid. `TestIdp` always
        // sets `iss` to "https://idp.example/", so the resolver must be
        // keyed there for JWKS resolution (and thus signature
        // verification) to succeed — the point of this test is that the
        // signature check passing is NOT enough: alice's profile does NOT
        // list this issuer, so the webid-issuer trust binding must still
        // reject it.
        let resolver = crate::auth::jwks::StaticJwksResolver::new("https://idp.example/", idp.jwks());
        let webids = crate::auth::webid_issuer::StaticWebIdIssuers::new(); // empty → authorizes() = false
        let at = idp.mint_access_token("https://alice.example/card#me", &client.jkt(), 9_999_999_999);
        let proof = client.mint_dpop("https://pod.toph.so/foo", "GET", 1_000, "jti-imp");
        let r = authenticate(Some(&format!("DPoP {at}")), Some(&proof), "GET",
            "https://pod.toph.so/foo", &resolver, &webids, 1_010).await;
        assert!(matches!(r, Err(crate::auth::AuthError::IssuerNotAuthorized)));
    }

    #[tokio::test]
    async fn issuer_authorized_by_webid_succeeds() {
        let idp = crate::auth::testsupport::TestIdp::new();
        let client = crate::auth::testsupport::TestClient::new();
        let resolver = crate::auth::jwks::StaticJwksResolver::new("https://idp.example/", idp.jwks());
        let mut webids = crate::auth::webid_issuer::StaticWebIdIssuers::new();
        webids.allow("https://alice.example/card#me", "https://idp.example/");
        let at = idp.mint_access_token("https://alice.example/card#me", &client.jkt(), 9_999_999_999);
        let proof = client.mint_dpop("https://pod.toph.so/foo", "GET", 1_000, "jti-ok2");
        let agent = authenticate(Some(&format!("DPoP {at}")), Some(&proof), "GET",
            "https://pod.toph.so/foo", &resolver, &webids, 1_010).await.unwrap();
        assert_eq!(agent, crate::auth::Agent::WebId("https://alice.example/card#me".into()));
    }
}
