//! WebID↔issuer trust binding — closing the full-impersonation hole.
//!
//! [`verify_access_token`](super::verify_access_token) only proves that a
//! token was signed by the key of whatever issuer the token itself names.
//! That is not enough: an attacker who runs their own IdP can mint a token
//! naming ANY webid at all (`{iss: https://attacker.example/, webid:
//! https://alice.example/card#me}`), sign it with their own key, and it
//! verifies fine — the token is internally self-consistent. Nothing so far
//! confirms that Alice's IdP actually IS `attacker.example`.
//!
//! Solid-OIDC closes this by requiring the WebID's own profile document to
//! declare its authorized issuer(s) via the `solid:oidcIssuer` predicate. A
//! [`WebIdIssuerVerifier`] dereferences that profile and confirms the
//! token's issuer is among them; [`authenticate`](super::authenticate)
//! calls it after the token's signature has been verified but before the
//! `webid` claim is trusted, and fails closed on any doubt.

use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use oxigraph::io::RdfFormat;
use oxigraph::model::{NamedOrBlankNode, Term};

use super::safe_fetch::{guarded_get, FetchPolicy};
use super::AuthError;
use crate::rdf;

/// The Solid-OIDC predicate a WebID profile document uses to declare which
/// issuer(s) are authorized to mint tokens on its behalf.
pub const SOLID_OIDC_ISSUER: &str = "http://www.w3.org/ns/solid/terms#oidcIssuer";

/// Confirms that a WebID's profile document authorizes a given token
/// issuer, i.e. that the profile contains the triple
/// `<webid> solid:oidcIssuer <issuer>`. This is the trust binding that
/// stops a token's `webid` claim from being accepted on the strength of its
/// signature alone.
#[async_trait]
pub trait WebIdIssuerVerifier: Send + Sync {
    async fn authorizes(&self, webid: &str, issuer: &str) -> Result<bool, AuthError>;
}

/// An in-memory `WebIdIssuerVerifier` over a fixed webid -> allowed-issuers
/// map. Used in hermetic tests (no network).
#[derive(Default)]
pub struct StaticWebIdIssuers {
    map: HashMap<String, Vec<String>>,
}

impl StaticWebIdIssuers {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    /// Declare that `webid`'s profile authorizes `issuer`.
    pub fn allow(&mut self, webid: &str, issuer: &str) {
        self.map
            .entry(webid.to_string())
            .or_default()
            .push(issuer.to_string());
    }
}

#[async_trait]
impl WebIdIssuerVerifier for StaticWebIdIssuers {
    async fn authorizes(&self, webid: &str, issuer: &str) -> Result<bool, AuthError> {
        Ok(self
            .map
            .get(webid)
            .is_some_and(|issuers| issuers.iter().any(|i| issuer_matches(i, issuer))))
    }
}

/// Production `WebIdIssuerVerifier`: dereferences the WebID's profile
/// document over HTTP and checks it for the `solid:oidcIssuer` triple.
pub struct HttpWebIdIssuers {
    client: reqwest::Client,
    policy: FetchPolicy,
}

impl HttpWebIdIssuers {
    /// Production constructor: fetches are SSRF-guarded with the policy the
    /// operator configured — [`FetchPolicy::default`] (https-only, private
    /// IPs blocked) unless they named hosts via `--allow-insecure-host`. The
    /// webid is attacker-influenced input just like the token's `iss`.
    pub fn new(policy: FetchPolicy) -> Self {
        Self::build(policy)
    }

    /// Construct with an explicit [`FetchPolicy`] — used by hermetic tests
    /// that fetch from a local (`127.0.0.1`) test server and so must allow
    /// http and private IPs. Test-only: a permissive policy must be
    /// unconstructable in a production build, so production code must go
    /// through [`Self::new`].
    #[cfg(test)]
    pub fn with_policy(policy: FetchPolicy) -> Self {
        Self::build(policy)
    }

    fn build(policy: FetchPolicy) -> Self {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .build()
            .expect("reqwest client with timeouts should always build");
        Self { client, policy }
    }
}

#[async_trait]
impl WebIdIssuerVerifier for HttpWebIdIssuers {
    async fn authorizes(&self, webid: &str, issuer: &str) -> Result<bool, AuthError> {
        // The profile DOCUMENT is the webid with any fragment stripped
        // (`https://alice.example/card#me` -> `https://alice.example/card`).
        let doc_url = webid.split('#').next().unwrap_or(webid);

        let (body, content_type) = guarded_get(
            &self.client,
            doc_url,
            "text/turtle, application/ld+json;q=0.9",
            &self.policy,
        )
        .await?;
        let fmt = content_type
            .as_deref()
            .and_then(rdf::format_for_content_type)
            .unwrap_or(RdfFormat::Turtle);
        let triples = rdf::parse(body.as_bytes(), fmt, doc_url)
            .map_err(|e| AuthError::FetchBlocked(format!("invalid profile document: {e}")))?;

        Ok(triples.iter().any(|t| {
            matches!(&t.subject, NamedOrBlankNode::NamedNode(n) if n.as_str() == webid)
                && t.predicate.as_str() == SOLID_OIDC_ISSUER
                && matches!(&t.object, Term::NamedNode(n) if issuer_matches(n.as_str(), issuer))
        }))
    }
}

/// Compares two issuer strings ignoring a trailing slash: issuers are
/// sometimes written with one and sometimes without, and both forms name
/// the same issuer.
///
/// `pub(crate)` so [`super::authenticate`]'s issuer-allowlist check can
/// reuse the exact same normalization instead of re-implementing it (and
/// risking divergence).
pub(crate) fn issuer_matches(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Router};

    /// Spin up a local (no external network) profile-document server
    /// serving a Turtle profile that declares `solid:oidcIssuer` for one
    /// issuer, and return the webid it describes.
    async fn spawn_profile_server(issuer: &str) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let webid = format!("http://{addr}/profile#me");

        let ttl = format!(
            "@prefix solid: <http://www.w3.org/ns/solid/terms#> .\n\
             <#me> solid:oidcIssuer <{issuer}> .\n"
        );

        let app = Router::new().route(
            "/profile",
            get(move || async move {
                (
                    [(axum::http::header::CONTENT_TYPE, "text/turtle")],
                    ttl.clone(),
                )
            }),
        );

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        webid
    }

    fn permissive_verifier() -> HttpWebIdIssuers {
        HttpWebIdIssuers::with_policy(FetchPolicy::permissive())
    }

    /// Spin up a local profile-document server serving the SAME
    /// `solid:oidcIssuer` declaration as [`spawn_profile_server`], but as
    /// **JSON-LD** (expanded form) with `Content-Type: application/ld+json`
    /// instead of Turtle — proving `authorizes` content-negotiates the
    /// parse format rather than always assuming Turtle.
    async fn spawn_jsonld_profile_server(issuer: &str) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let webid = format!("http://{addr}/profile#me");

        let jsonld = format!(
            r#"[{{"@id": "{webid}", "http://www.w3.org/ns/solid/terms#oidcIssuer": [{{"@id": "{issuer}"}}]}}]"#
        );

        let app = Router::new().route(
            "/profile",
            get(move || async move {
                (
                    [(axum::http::header::CONTENT_TYPE, "application/ld+json")],
                    jsonld.clone(),
                )
            }),
        );

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        webid
    }

    #[tokio::test]
    async fn jsonld_profile_with_listed_issuer_is_authorized() {
        let webid = spawn_jsonld_profile_server("https://idp.example/").await;
        let verifier = permissive_verifier();
        assert!(verifier
            .authorizes(&webid, "https://idp.example/")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn listed_issuer_is_authorized() {
        let webid = spawn_profile_server("https://idp.example/").await;
        let verifier = permissive_verifier();
        assert!(verifier
            .authorizes(&webid, "https://idp.example/")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn unlisted_issuer_is_not_authorized() {
        let webid = spawn_profile_server("https://idp.example/").await;
        let verifier = permissive_verifier();
        assert!(!verifier
            .authorizes(&webid, "https://attacker.example/")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn trailing_slash_is_ignored_when_matching_issuer() {
        let webid = spawn_profile_server("https://idp.example").await; // no trailing slash
        let verifier = permissive_verifier();
        assert!(verifier
            .authorizes(&webid, "https://idp.example/") // queried with trailing slash
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn static_verifier_rejects_unlisted_webid() {
        let webids = StaticWebIdIssuers::new();
        assert!(!webids
            .authorizes("https://alice.example/card#me", "https://idp.example/")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn static_verifier_authorizes_allowed_pair() {
        let mut webids = StaticWebIdIssuers::new();
        webids.allow("https://alice.example/card#me", "https://idp.example/");
        assert!(webids
            .authorizes("https://alice.example/card#me", "https://idp.example/")
            .await
            .unwrap());
    }

    /// A profile document that declares `solid:oidcIssuer` on the RIGHT
    /// predicate/object but the WRONG subject (someone else's WebID, not
    /// the one being queried) must not authorize the requested webid. This
    /// proves the match enforces the subject binding too — not just that
    /// the predicate and object happen to appear somewhere in the graph.
    #[tokio::test]
    async fn subject_mismatch_is_not_authorized() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let webid = format!("http://{addr}/profile#me");

        // Declares oidcIssuer for a DIFFERENT subject than the requested webid.
        let ttl = "@prefix solid: <http://www.w3.org/ns/solid/terms#> .\n\
                   <https://other.example/card#someoneelse> solid:oidcIssuer <https://idp.example/> .\n"
            .to_string();

        let app = Router::new().route(
            "/profile",
            get(move || async move {
                (
                    [(axum::http::header::CONTENT_TYPE, "text/turtle")],
                    ttl.clone(),
                )
            }),
        );

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let verifier = permissive_verifier();
        assert!(
            !verifier
                .authorizes(&webid, "https://idp.example/")
                .await
                .unwrap(),
            "oidcIssuer triple on the WRONG subject must not authorize the requested webid"
        );
    }
}
