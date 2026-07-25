//! Production `JwksResolver`: OIDC discovery over HTTP, with a TTL cache.
//!
//! Unlike `StaticJwksResolver` (used in every hermetic test in this crate),
//! this performs real network calls: `GET <issuer>/.well-known/openid-configuration`
//! to find the issuer's `jwks_uri`, then `GET <jwks_uri>` for the keys
//! themselves. Both requests happen at most once per issuer per
//! [`CACHE_TTL`]; the cache is a process-lifetime, in-memory map (no
//! cross-replica sharing, no persistence across restarts) — the same kind
//! of v1 limitation already noted for `auth::dpop`'s replay store.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use josekit::jwk::Jwk;
use serde_json::Value;
use tokio::sync::RwLock;

use super::jwks::{Jwks, JwksResolver};
use super::safe_fetch::{guarded_get, FetchPolicy};
use super::AuthError;

/// How long a resolved `Jwks` is trusted before this resolver re-fetches it
/// from the issuer.
const CACHE_TTL: Duration = Duration::from_secs(300);

/// How long a discovery/JWKS FAILURE is remembered before this resolver
/// will attempt to fetch the same issuer again. Short by design (unlike
/// `CACHE_TTL`): this only exists to stop a flapping or hostile issuer from
/// being re-probed on every single request, not to durably remember an
/// issuer as bad.
const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(30);

/// An HTTP `JwksResolver` for production use: resolves an issuer's signing
/// keys via OIDC discovery, caching the result per issuer for `CACHE_TTL`.
pub struct HttpJwksResolver {
    client: reqwest::Client,
    cache: RwLock<HashMap<String, (Jwks, Instant)>>,
    negative_cache: RwLock<HashMap<String, Instant>>,
    policy: FetchPolicy,
}

impl HttpJwksResolver {
    /// Production constructor: fetches are SSRF-guarded with
    /// [`FetchPolicy::default`] (https-only, private IPs blocked).
    pub fn new() -> Self {
        Self::build(FetchPolicy::default())
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
        Self {
            client,
            cache: RwLock::new(HashMap::new()),
            negative_cache: RwLock::new(HashMap::new()),
            policy,
        }
    }

    /// Perform the OIDC-discovery + JWKS fetch, uncached. Any SSRF-guard
    /// rejection, network failure, non-2xx status, or unexpected JSON
    /// shape fails closed as `AuthError::UnknownIssuer` — from the
    /// caller's point of view, an issuer whose keys can't be resolved is
    /// exactly as unusable as one that was never configured at all.
    async fn fetch(&self, issuer: &str) -> Result<Jwks, AuthError> {
        let discovery_url = if issuer.ends_with('/') {
            format!("{issuer}.well-known/openid-configuration")
        } else {
            format!("{issuer}/.well-known/openid-configuration")
        };

        let discovery_body =
            guarded_get(&self.client, &discovery_url, "application/json", &self.policy)
                .await
                .map_err(|_| AuthError::UnknownIssuer)?;
        let discovery: Value =
            serde_json::from_str(&discovery_body).map_err(|_| AuthError::UnknownIssuer)?;
        let jwks_uri = discovery
            .get("jwks_uri")
            .and_then(Value::as_str)
            .ok_or(AuthError::UnknownIssuer)?;

        let jwks_body = guarded_get(&self.client, jwks_uri, "application/json", &self.policy)
            .await
            .map_err(|_| AuthError::UnknownIssuer)?;
        let jwks_doc: Value =
            serde_json::from_str(&jwks_body).map_err(|_| AuthError::UnknownIssuer)?;
        let keys_value = jwks_doc.get("keys").ok_or(AuthError::UnknownIssuer)?;
        let keys: Vec<Jwk> =
            serde_json::from_value(keys_value.clone()).map_err(|_| AuthError::UnknownIssuer)?;

        Ok(Jwks { keys })
    }
}

impl Default for HttpJwksResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl JwksResolver for HttpJwksResolver {
    async fn resolve(&self, issuer: &str) -> Result<Jwks, AuthError> {
        if let Some((jwks, fetched_at)) = self.cache.read().await.get(issuer) {
            if fetched_at.elapsed() < CACHE_TTL {
                return Ok(Jwks {
                    keys: jwks.keys.clone(),
                });
            }
        }

        if let Some(failed_at) = self.negative_cache.read().await.get(issuer) {
            if failed_at.elapsed() < NEGATIVE_CACHE_TTL {
                return Err(AuthError::UnknownIssuer);
            }
        }

        match self.fetch(issuer).await {
            Ok(jwks) => {
                self.cache.write().await.insert(
                    issuer.to_string(),
                    (
                        Jwks {
                            keys: jwks.keys.clone(),
                        },
                        Instant::now(),
                    ),
                );
                self.negative_cache.write().await.remove(issuer);
                Ok(jwks)
            }
            Err(e) => {
                self.negative_cache
                    .write()
                    .await
                    .insert(issuer.to_string(), Instant::now());
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::routing::get;
    use axum::{Json, Router};
    use serde_json::json;

    use super::*;
    use crate::auth::testsupport::TestIdp;

    #[derive(Clone)]
    struct JwksCtx {
        keys: serde_json::Value,
        hits: Arc<AtomicUsize>,
    }

    async fn jwks_handler(State(ctx): State<JwksCtx>) -> Json<serde_json::Value> {
        ctx.hits.fetch_add(1, Ordering::SeqCst);
        Json(json!({ "keys": ctx.keys }))
    }

    async fn discovery_handler(State(jwks_uri): State<String>) -> Json<serde_json::Value> {
        Json(json!({ "jwks_uri": jwks_uri }))
    }

    /// Spin up a local OIDC-discovery + JWKS server (no external network)
    /// serving `idp`'s real public key, and return its base issuer URL plus
    /// a shared counter of how many times `/jwks` was hit (to prove the TTL
    /// cache avoids refetching).
    async fn spawn_test_idp_server(idp: &TestIdp) -> (String, Arc<AtomicUsize>) {
        let jwks_hits = Arc::new(AtomicUsize::new(0));
        let keys = serde_json::to_value(idp.jwks().keys).expect("serialize public jwks");

        // The discovery response needs the server's own address (for
        // `jwks_uri`), so bind first and build routes referencing it,
        // mirroring how a real IdP publishes its own base URL.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let issuer = format!("http://{addr}/");
        let jwks_uri = format!("http://{addr}/jwks");

        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(discovery_handler).with_state(jwks_uri),
            )
            .route(
                "/jwks",
                get(jwks_handler).with_state(JwksCtx {
                    keys,
                    hits: jwks_hits.clone(),
                }),
            );

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        (issuer, jwks_hits)
    }

    #[tokio::test]
    async fn resolves_jwks_via_oidc_discovery_and_caches() {
        let idp = TestIdp::new();
        let (issuer, jwks_hits) = spawn_test_idp_server(&idp).await;
        let resolver = HttpJwksResolver::with_policy(FetchPolicy::permissive());

        let jwks = resolver.resolve(&issuer).await.expect("resolve via HTTP");
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks_hits.load(Ordering::SeqCst), 1);

        // second resolve within the TTL must be served from cache, not refetched
        resolver.resolve(&issuer).await.expect("resolve from cache");
        assert_eq!(jwks_hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn unknown_host_is_unknown_issuer() {
        let resolver = HttpJwksResolver::with_policy(FetchPolicy::permissive());
        // port 0 is never a listening server; this is a local-only failure,
        // not a real network call to an external host.
        assert!(matches!(
            resolver.resolve("http://127.0.0.1:0/").await,
            Err(AuthError::UnknownIssuer)
        ));
    }

    async fn failing_discovery_handler(
        State(hits): State<Arc<AtomicUsize>>,
    ) -> StatusCode {
        hits.fetch_add(1, Ordering::SeqCst);
        StatusCode::INTERNAL_SERVER_ERROR
    }

    /// Spin up a discovery endpoint that always fails (500), counting how
    /// many times it's hit.
    async fn spawn_failing_discovery_server() -> (String, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let issuer = format!("http://{addr}/");

        let app = Router::new().route(
            "/.well-known/openid-configuration",
            get(failing_discovery_handler).with_state(hits.clone()),
        );

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        (issuer, hits)
    }

    #[tokio::test]
    async fn resolution_failure_is_negatively_cached() {
        let (issuer, hits) = spawn_failing_discovery_server().await;
        let resolver = HttpJwksResolver::with_policy(FetchPolicy::permissive());

        assert!(matches!(
            resolver.resolve(&issuer).await,
            Err(AuthError::UnknownIssuer)
        ));
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        // A second resolve within the negative-cache TTL must be served
        // from the negative cache, not re-probe the (still failing) server.
        assert!(matches!(
            resolver.resolve(&issuer).await,
            Err(AuthError::UnknownIssuer)
        ));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }
}
