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
use std::time::{Duration, Instant};

use async_trait::async_trait;
use oxigraph::model::{NamedOrBlankNode, Term};
use tokio::sync::RwLock;

use super::safe_fetch::{guarded_get, FetchPolicy, GuardedClient};
use super::AuthError;
use crate::rdf::Format;

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

/// How long a WebID's declared issuer list is trusted before the profile
/// document is fetched again.
///
/// Shorter than [`super::http_jwks::CACHE_TTL`] on purpose: a JWKS rotates on
/// the IdP's schedule, but `solid:oidcIssuer` is edited by the WebID's owner,
/// who then immediately expects a token from the new issuer to work. Two
/// minutes matches `@solid/access-token-verifier`, whose fixed-TTL cache is
/// the behaviour every Solid client is already calibrated against.
const CACHE_TTL: Duration = Duration::from_secs(120);

/// How long a failed profile fetch is remembered before the same WebID is
/// dereferenced again.
///
/// This is not only a politeness to a flapping host. `authorizes` runs on a
/// signature-verified token, but with no `trusted_issuers` allowlist
/// configured that proves nothing about the `webid` claim — anyone running
/// their own IdP can sign one naming any URL. Without this, each such request
/// is one fresh outbound fetch to an attacker-chosen address.
const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(30);

/// Cap on entries in either cache. Both are keyed by the token's `webid`
/// claim, which is attacker-influenced under the conditions described at
/// [`NEGATIVE_CACHE_TTL`], so neither may grow without bound.
const MAX_CACHE_ENTRIES: usize = 1024;

/// Production `WebIdIssuerVerifier`: dereferences the WebID's profile
/// document over HTTP and checks it for the `solid:oidcIssuer` triple,
/// caching each profile's declared issuer list for [`CACHE_TTL`].
///
/// The cache holds the issuer *list*, not the yes/no answer for one issuer:
/// a profile declaring two issuers is one entry answering both questions,
/// and the second question costs no fetch.
pub struct HttpWebIdIssuers {
    client: GuardedClient,
    policy: FetchPolicy,
    cache: RwLock<HashMap<String, (Vec<String>, Instant)>>,
    negative_cache: RwLock<HashMap<String, Instant>>,
}

impl HttpWebIdIssuers {
    /// Production constructor: fetches are SSRF-guarded with the policy the
    /// operator configured — [`FetchPolicy::default`] (https-only, private
    /// IPs blocked) unless they named hosts via `--allow-insecure-host`. The
    /// webid is attacker-influenced input just like the token's `iss`.
    ///
    /// `client` is shared with every other guarded fetcher in the process, so
    /// profile lookups reuse connections and TLS sessions with OIDC discovery
    /// and JWKS fetches to the same origin.
    pub fn new(client: GuardedClient, policy: FetchPolicy) -> Self {
        Self::build(client, policy)
    }

    /// Construct with an explicit [`FetchPolicy`] — used by hermetic tests
    /// that fetch from a local (`127.0.0.1`) test server and so must allow
    /// http and private IPs. Test-only: a permissive policy must be
    /// unconstructable in a production build, so production code must go
    /// through [`Self::new`].
    #[cfg(test)]
    pub fn with_policy(policy: FetchPolicy) -> Self {
        Self::build(GuardedClient::new(&policy), policy)
    }

    fn build(client: GuardedClient, policy: FetchPolicy) -> Self {
        Self {
            client,
            policy,
            cache: RwLock::new(HashMap::new()),
            negative_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Fetch and parse `webid`'s profile document, returning every issuer it
    /// declares for that exact subject. Uncached.
    async fn fetch_issuers(&self, webid: &str) -> Result<Vec<String>, AuthError> {
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
            .and_then(Format::from_content_type)
            .unwrap_or_else(|| {
                Format::from_content_type("text/turtle").expect("text/turtle is always supported")
            });
        let dataset = fmt
            // No version constraint: this document belongs to someone else,
            // is never stored here, and is read only for `solid:oidcIssuer`
            // triples. Refusing a 1.2 profile would break authentication over
            // a term nothing in this path looks at.
            .parse(body.as_bytes(), doc_url, crate::rdf::RdfVersion::Rdf12)
            .map_err(|e| AuthError::FetchBlocked(format!("invalid profile document: {e}")))?;

        Ok(dataset
            .quads()
            .iter()
            .filter(|t| {
                matches!(&t.subject, NamedOrBlankNode::NamedNode(n) if n.as_str() == webid)
                    && t.predicate.as_str() == SOLID_OIDC_ISSUER
            })
            .filter_map(|t| match &t.object {
                Term::NamedNode(n) => Some(n.as_str().to_string()),
                _ => None,
            })
            .collect())
    }
}

/// Insert into a bounded cache, making room first if the map is at
/// [`MAX_CACHE_ENTRIES`]: expired entries go first, and if that frees nothing
/// the least recently fetched entry is evicted.
///
/// Eviction rather than refusal because the entry being inserted is the one
/// just proven live; the worst case is a cache miss, never unbounded memory.
fn insert_bounded<V>(
    map: &mut HashMap<String, V>,
    key: String,
    value: V,
    ttl: Duration,
    stamp: fn(&V) -> Instant,
) {
    if map.len() >= MAX_CACHE_ENTRIES && !map.contains_key(&key) {
        map.retain(|_, v| stamp(v).elapsed() < ttl);

        if map.len() >= MAX_CACHE_ENTRIES {
            if let Some(oldest) = map
                .iter()
                .min_by_key(|(_, v)| stamp(v))
                .map(|(k, _)| k.clone())
            {
                map.remove(&oldest);
            }
        }
    }

    map.insert(key, value);
}

#[async_trait]
impl WebIdIssuerVerifier for HttpWebIdIssuers {
    /// A profile that parsed but does not declare `issuer` is `Ok(false)`; a
    /// profile that could not be fetched or parsed is `Err`. The cache
    /// preserves that distinction — the first outcome is a fact about the
    /// WebID and is cached as the issuer list, the second is a failure and
    /// goes to the negative cache.
    async fn authorizes(&self, webid: &str, issuer: &str) -> Result<bool, AuthError> {
        if let Some((issuers, fetched_at)) = self.cache.read().await.get(webid) {
            if fetched_at.elapsed() < CACHE_TTL {
                return Ok(issuers.iter().any(|i| issuer_matches(i, issuer)));
            }
        }

        if let Some(failed_at) = self.negative_cache.read().await.get(webid) {
            if failed_at.elapsed() < NEGATIVE_CACHE_TTL {
                return Err(AuthError::FetchBlocked(
                    "webid profile document recently failed to resolve".to_string(),
                ));
            }
        }

        match self.fetch_issuers(webid).await {
            Ok(issuers) => {
                let authorized = issuers.iter().any(|i| issuer_matches(i, issuer));
                insert_bounded(
                    &mut *self.cache.write().await,
                    webid.to_string(),
                    (issuers, Instant::now()),
                    CACHE_TTL,
                    |(_, at)| *at,
                );
                self.negative_cache.write().await.remove(webid);
                Ok(authorized)
            }
            Err(e) => {
                insert_bounded(
                    &mut *self.negative_cache.write().await,
                    webid.to_string(),
                    Instant::now(),
                    NEGATIVE_CACHE_TTL,
                    |at| *at,
                );
                Err(e)
            }
        }
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
    use std::sync::atomic::{AtomicUsize, Ordering};

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

    /// Like [`spawn_profile_server`] but declares `issuers` (possibly several)
    /// and counts how many times the profile was actually fetched — the only
    /// way to tell a cache hit from a silent refetch.
    async fn spawn_counting_profile_server(
        issuers: &[&str],
    ) -> (String, std::sync::Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let webid = format!("http://{addr}/profile#me");
        let hits = std::sync::Arc::new(AtomicUsize::new(0));

        let mut ttl = "@prefix solid: <http://www.w3.org/ns/solid/terms#> .\n".to_string();
        for issuer in issuers {
            ttl.push_str(&format!("<#me> solid:oidcIssuer <{issuer}> .\n"));
        }

        let counter = hits.clone();
        let app = Router::new().route(
            "/profile",
            get(move || {
                let ttl = ttl.clone();
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    ([(axum::http::header::CONTENT_TYPE, "text/turtle")], ttl)
                }
            }),
        );

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        (webid, hits)
    }

    /// The headline: a second authorization of the same WebID inside the TTL
    /// is answered from cache. Before this, every authenticated request
    /// dereferenced the profile document again.
    #[tokio::test]
    async fn profile_is_fetched_once_and_then_served_from_cache() {
        let (webid, hits) = spawn_counting_profile_server(&["https://idp.example/"]).await;
        let verifier = permissive_verifier();

        assert!(verifier
            .authorizes(&webid, "https://idp.example/")
            .await
            .unwrap());
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        assert!(verifier
            .authorizes(&webid, "https://idp.example/")
            .await
            .unwrap());
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    /// Why the cache holds the issuer *list* rather than one issuer's yes/no:
    /// a profile declaring two issuers answers both questions from the one
    /// entry. Keying on `(webid, issuer)` would refetch for the second.
    #[tokio::test]
    async fn a_second_issuer_of_the_same_profile_costs_no_fetch() {
        let (webid, hits) =
            spawn_counting_profile_server(&["https://a.example/", "https://b.example/"]).await;
        let verifier = permissive_verifier();

        assert!(verifier
            .authorizes(&webid, "https://a.example/")
            .await
            .unwrap());
        assert!(verifier
            .authorizes(&webid, "https://b.example/")
            .await
            .unwrap());
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    /// A cached profile still answers `false` for an issuer it does not
    /// declare — the cache must not turn "fetched once" into "authorized".
    #[tokio::test]
    async fn a_cached_profile_still_refuses_an_undeclared_issuer() {
        let (webid, hits) = spawn_counting_profile_server(&["https://idp.example/"]).await;
        let verifier = permissive_verifier();

        assert!(verifier
            .authorizes(&webid, "https://idp.example/")
            .await
            .unwrap());
        assert!(!verifier
            .authorizes(&webid, "https://attacker.example/")
            .await
            .unwrap());
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    /// A failed profile fetch is remembered, so a request stream carrying
    /// made-up WebIDs cannot turn into one outbound fetch per request.
    #[tokio::test]
    async fn a_failed_profile_fetch_is_negatively_cached() {
        let hits = std::sync::Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let webid = format!("http://{addr}/profile#me");

        let counter = hits.clone();
        let app = Router::new().route(
            "/profile",
            get(move || {
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR
                }
            }),
        );
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let verifier = permissive_verifier();
        assert!(verifier.authorizes(&webid, "https://idp.example/").await.is_err());
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        assert!(verifier.authorizes(&webid, "https://idp.example/").await.is_err());
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    /// Both caches are keyed by the token's `webid` claim, which an attacker
    /// running their own IdP can set freely when no `trusted_issuers`
    /// allowlist is configured. Neither may grow without bound.
    #[test]
    fn a_bounded_cache_does_not_grow_past_its_cap() {
        let mut map: HashMap<String, (Vec<String>, Instant)> = HashMap::new();

        for i in 0..MAX_CACHE_ENTRIES + 50 {
            insert_bounded(
                &mut map,
                format!("https://example.test/{i}#me"),
                (vec!["https://idp.example/".to_string()], Instant::now()),
                CACHE_TTL,
                |(_, at)| *at,
            );
        }

        assert_eq!(map.len(), MAX_CACHE_ENTRIES);
    }

    /// Eviction must not fire on a key already present: re-fetching the same
    /// WebID replaces its entry rather than displacing someone else's.
    #[test]
    fn refreshing_an_existing_entry_evicts_nothing() {
        let mut map: HashMap<String, (Vec<String>, Instant)> = HashMap::new();

        for i in 0..MAX_CACHE_ENTRIES {
            insert_bounded(
                &mut map,
                format!("https://example.test/{i}#me"),
                (vec![], Instant::now()),
                CACHE_TTL,
                |(_, at)| *at,
            );
        }

        insert_bounded(
            &mut map,
            "https://example.test/0#me".to_string(),
            (vec!["https://idp.example/".to_string()], Instant::now()),
            CACHE_TTL,
            |(_, at)| *at,
        );

        assert_eq!(map.len(), MAX_CACHE_ENTRIES);
        assert_eq!(
            map["https://example.test/0#me"].0,
            vec!["https://idp.example/".to_string()]
        );
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
