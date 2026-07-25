//! Orchestrating credential verification into an [`Agent`] for a request.

use super::access_token::{peek_untrusted_issuer, verify_access_token};
use super::config::AuthConfig;
use super::dpop::verify_dpop;
use super::jwks::JwksResolver;
use super::webid_issuer::{issuer_matches, WebIdIssuerVerifier};
use super::{Agent, AuthError};

/// The trust-configuration collaborators [`authenticate`] verifies a
/// request's credentials against: the issuer's published keys, the
/// WebID-issuer trust binding, and the (optional) issuer allowlist / audience
/// config. Bundled into one struct (rather than three separate parameters)
/// to keep `authenticate`'s argument count sane — these three are always
/// supplied together by the caller (`AppState` in `http.rs`), unlike the
/// per-request data (`auth_header`, `dpop_header`, `htm`, `htu`, `now_unix`).
pub struct AuthDeps<'a> {
    pub resolver: &'a dyn JwksResolver,
    pub webid_verifier: &'a dyn WebIdIssuerVerifier,
    pub config: &'a AuthConfig,
}

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
///
/// Before any JWKS fetch, if `config.trusted_issuers` is `Some(set)` the
/// token's `iss` (peeked WITHOUT signature verification, via
/// [`peek_untrusted_issuer`]) must match a member of `set` — compared via
/// [`issuer_matches`] (trailing-slash-insensitive, the same normalization
/// used for the WebID-issuer binding) — or the request is rejected as
/// [`AuthError::UntrustedIssuer`]. This untrusted peek is used ONLY to
/// reject early, never to accept. This shrinks the SSRF surface (an
/// untrusted issuer never triggers an outbound fetch) as defense-in-depth
/// over the WebID-issuer binding, which remains the primary control. If
/// `trusted_issuers` is `None`, every issuer proceeds to that binding check
/// (open federation).
///
/// After the access token's signature is verified, if `config.expected_audience`
/// is `Some(value)`, `value` must appear in the token's (verified) `aud`
/// claim or the request is rejected as [`AuthError::WrongAudience`] —
/// defense-in-depth so a token minted for a different resource server isn't
/// accepted here. If `expected_audience` is `None`, this check is skipped
/// (backward-compatible).
pub async fn authenticate(
    auth_header: Option<&str>,
    dpop_header: Option<&str>,
    htm: &str,
    htu: &str,
    deps: AuthDeps<'_>,
    now_unix: i64,
) -> Result<Agent, AuthError> {
    if auth_header.is_none() && dpop_header.is_none() {
        return Ok(Agent::Public);
    }

    let token = parse_dpop_scheme(auth_header)?;
    let proof = dpop_header
        .ok_or_else(|| AuthError::DpopInvalid("missing DPoP proof header".to_string()))?;

    if let Some(trusted) = &deps.config.trusted_issuers {
        let untrusted_iss = peek_untrusted_issuer(token)?;
        if !trusted.iter().any(|t| issuer_matches(t, &untrusted_iss)) {
            return Err(AuthError::UntrustedIssuer);
        }
    }

    let claims = verify_access_token(token, deps.resolver, now_unix).await?;

    if let Some(expected) = &deps.config.expected_audience {
        if !claims.audience.iter().any(|a| a == expected) {
            return Err(AuthError::WrongAudience);
        }
    }

    if !deps
        .webid_verifier
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
        config::AuthConfig,
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
        let cfg = AuthConfig::default();
        let deps = AuthDeps { resolver: &resolver, webid_verifier: &webids, config: &cfg };
        let agent = authenticate(None, None, "GET", "https://pod.toph.so/foo", deps, 1_000)
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
        let cfg = AuthConfig::default();
        let at = idp.mint_access_token(
            "https://alice.example/card#me",
            &client.jkt(),
            9_999_999_999,
        );
        let proof = client.mint_dpop("https://pod.toph.so/foo", "GET", 1_000, "jti-x");
        let deps = AuthDeps { resolver: &resolver, webid_verifier: &webids, config: &cfg };
        let agent = authenticate(
            Some(&format!("DPoP {at}")),
            Some(&proof),
            "GET",
            "https://pod.toph.so/foo",
            deps,
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
        let cfg = AuthConfig::default();
        let at = idp.mint_access_token(
            "https://alice.example/card#me",
            &client.jkt(),
            9_999_999_999,
        );
        let deps = AuthDeps { resolver: &resolver, webid_verifier: &webids, config: &cfg };
        assert!(authenticate(
            Some(&format!("DPoP {at}")),
            None,
            "GET",
            "https://pod.toph.so/foo",
            deps,
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
        let cfg = AuthConfig::default();
        let at = idp.mint_access_token("https://alice.example/card#me", &client.jkt(), 9_999_999_999);
        let proof = client.mint_dpop("https://pod.toph.so/foo", "GET", 1_000, "jti-imp");
        let deps = AuthDeps { resolver: &resolver, webid_verifier: &webids, config: &cfg };
        let r = authenticate(Some(&format!("DPoP {at}")), Some(&proof), "GET",
            "https://pod.toph.so/foo", deps, 1_010).await;
        assert!(matches!(r, Err(crate::auth::AuthError::IssuerNotAuthorized)));
    }

    #[tokio::test]
    async fn issuer_authorized_by_webid_succeeds() {
        let idp = crate::auth::testsupport::TestIdp::new();
        let client = crate::auth::testsupport::TestClient::new();
        let resolver = crate::auth::jwks::StaticJwksResolver::new("https://idp.example/", idp.jwks());
        let mut webids = crate::auth::webid_issuer::StaticWebIdIssuers::new();
        webids.allow("https://alice.example/card#me", "https://idp.example/");
        let cfg = AuthConfig::default();
        let at = idp.mint_access_token("https://alice.example/card#me", &client.jkt(), 9_999_999_999);
        let proof = client.mint_dpop("https://pod.toph.so/foo", "GET", 1_000, "jti-ok2");
        let deps = AuthDeps { resolver: &resolver, webid_verifier: &webids, config: &cfg };
        let agent = authenticate(Some(&format!("DPoP {at}")), Some(&proof), "GET",
            "https://pod.toph.so/foo", deps, 1_010).await.unwrap();
        assert_eq!(agent, crate::auth::Agent::WebId("https://alice.example/card#me".into()));
    }

    #[tokio::test]
    async fn issuer_not_in_allowlist_is_rejected_before_fetch() {
        let idp = crate::auth::testsupport::TestIdp::new();
        let client = crate::auth::testsupport::TestClient::new();
        let resolver = crate::auth::jwks::StaticJwksResolver::new("https://idp.example/", idp.jwks());
        let mut webids = crate::auth::webid_issuer::StaticWebIdIssuers::new();
        webids.allow("https://alice.example/card#me", "https://idp.example/");
        let cfg = crate::auth::config::AuthConfig {
            trusted_issuers: Some(["https://ONLY-this.example/".to_string()].into_iter().collect()),
            ..Default::default()
        };
        let at = idp.mint_access_token("https://alice.example/card#me", &client.jkt(), 9_999_999_999);
        let proof = client.mint_dpop("https://pod.toph.so/foo", "GET", 1_000, "jti-allow");
        let deps = AuthDeps { resolver: &resolver, webid_verifier: &webids, config: &cfg };
        let r = authenticate(Some(&format!("DPoP {at}")), Some(&proof), "GET",
            "https://pod.toph.so/foo", deps, 1_010).await;
        assert!(matches!(r, Err(crate::auth::AuthError::UntrustedIssuer)));
    }

    #[tokio::test]
    async fn allowlisted_issuer_without_trailing_slash_accepts_token_with_one() {
        // `TestIdp` always sets `iss` to "https://idp.example/" (with a
        // trailing slash). Configuring the allowlist WITHOUT one must still
        // accept it — the allowlist match must use the same
        // trailing-slash-insensitive normalization as the WebID-issuer
        // binding, or a perfectly valid config locks everyone out.
        let idp = TestIdp::new();
        let client = TestClient::new();
        let resolver = StaticJwksResolver::new("https://idp.example/", idp.jwks());
        let mut webids = StaticWebIdIssuers::new();
        webids.allow("https://alice.example/card#me", "https://idp.example/");
        let cfg = AuthConfig {
            trusted_issuers: Some(["https://idp.example".to_string()].into_iter().collect()),
            ..Default::default()
        };
        let at = idp.mint_access_token(
            "https://alice.example/card#me",
            &client.jkt(),
            9_999_999_999,
        );
        let proof = client.mint_dpop("https://pod.toph.so/foo", "GET", 1_000, "jti-slash");
        let deps = AuthDeps { resolver: &resolver, webid_verifier: &webids, config: &cfg };
        let r = authenticate(Some(&format!("DPoP {at}")), Some(&proof), "GET",
            "https://pod.toph.so/foo", deps, 1_010).await;
        assert!(
            !matches!(r, Err(AuthError::UntrustedIssuer)),
            "trailing-slash mismatch must not be treated as an untrusted issuer"
        );
    }

    #[tokio::test]
    async fn matching_audience_is_accepted_when_expected_set() {
        let idp = TestIdp::new();
        let client = TestClient::new();
        let resolver = StaticJwksResolver::new("https://idp.example/", idp.jwks());
        let mut webids = StaticWebIdIssuers::new();
        webids.allow("https://alice.example/card#me", "https://idp.example/");
        let cfg = AuthConfig {
            expected_audience: Some("https://pod.toph.so/".to_string()),
            ..Default::default()
        };
        let at = idp.mint_access_token_aud(
            "https://alice.example/card#me",
            &client.jkt(),
            9_999_999_999,
            &["solid", "https://pod.toph.so/"],
        );
        let proof = client.mint_dpop("https://pod.toph.so/foo", "GET", 1_000, "jti-aud-ok");
        let deps = AuthDeps { resolver: &resolver, webid_verifier: &webids, config: &cfg };
        let agent = authenticate(Some(&format!("DPoP {at}")), Some(&proof), "GET",
            "https://pod.toph.so/foo", deps, 1_010).await.unwrap();
        assert_eq!(agent, Agent::WebId("https://alice.example/card#me".into()));
    }

    #[tokio::test]
    async fn wrong_audience_is_rejected_when_expected_set() {
        let idp = TestIdp::new();
        let client = TestClient::new();
        let resolver = StaticJwksResolver::new("https://idp.example/", idp.jwks());
        let mut webids = StaticWebIdIssuers::new();
        webids.allow("https://alice.example/card#me", "https://idp.example/");
        let cfg = AuthConfig {
            expected_audience: Some("https://pod.toph.so/".to_string()),
            ..Default::default()
        };
        let at = idp.mint_access_token_aud(
            "https://alice.example/card#me",
            &client.jkt(),
            9_999_999_999,
            &["https://other-rs.example/"],
        );
        let proof = client.mint_dpop("https://pod.toph.so/foo", "GET", 1_000, "jti-aud-bad");
        let deps = AuthDeps { resolver: &resolver, webid_verifier: &webids, config: &cfg };
        let r = authenticate(Some(&format!("DPoP {at}")), Some(&proof), "GET",
            "https://pod.toph.so/foo", deps, 1_010).await;
        assert!(matches!(r, Err(AuthError::WrongAudience)));
    }

    #[tokio::test]
    async fn no_expected_audience_succeeds_regardless_of_token_aud() {
        let idp = TestIdp::new();
        let client = TestClient::new();
        let resolver = StaticJwksResolver::new("https://idp.example/", idp.jwks());
        let mut webids = StaticWebIdIssuers::new();
        webids.allow("https://alice.example/card#me", "https://idp.example/");
        let cfg = AuthConfig::default(); // expected_audience: None
        let at = idp.mint_access_token_aud(
            "https://alice.example/card#me",
            &client.jkt(),
            9_999_999_999,
            &["https://some-other-rs.example/"],
        );
        let proof = client.mint_dpop("https://pod.toph.so/foo", "GET", 1_000, "jti-aud-none");
        let deps = AuthDeps { resolver: &resolver, webid_verifier: &webids, config: &cfg };
        let agent = authenticate(Some(&format!("DPoP {at}")), Some(&proof), "GET",
            "https://pod.toph.so/foo", deps, 1_010).await.unwrap();
        assert_eq!(agent, Agent::WebId("https://alice.example/card#me".into()));
    }
}
