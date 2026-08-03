//! Axum middleware that authenticates each request and attaches its
//! resulting [`Agent`](super::Agent) to the request extensions.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::http::AppState;
use crate::space::{GraphName, StorageSpace};

use super::authenticate;

/// Derive the DPoP-bound `htu` for a request: the configured public base plus
/// the **raw** request path, exactly as it came in on the wire.
///
/// `htu` is a wire-level concept, not a storage one. RFC 9449 §4.2 defines it
/// as "the HTTP target URI … of the request to which the JWT is attached", and
/// a client signs the URL it is about to put on the wire — `/caf%C3%A9`, never
/// `/café`. This function must therefore hand `verify_dpop` that same wire
/// form, and nothing else: the percent-DECODED path is a *storage* question,
/// answered downstream by [`StorageSpace::resolve`] and the handlers' own
/// `Path<String>` extraction, and it must not leak into the credential check.
///
/// It used to. `derive_htu` percent-decoded the path and returned the target's
/// **graph IRI**, and `verify_dpop` compensated by percent-decoding both sides
/// of its own comparison. That made two distinct wire URLs interchangeable:
/// a proof minted for `/a%41` (which the handlers see as `/aA`) also verified
/// against a request to `/a%2541` (which the handlers see as `/a%41`) — a
/// *different* resource. Both comparisons decoded their way to `/aA` and
/// accepted, so a signed body could be re-targeted at a resource its client
/// never addressed. Empirically it was also broken for the honest case: a
/// client signing the wire `https://pod.toph.so/a%41` was answered `401`,
/// because `dpop-verifier`'s own `normalize_htu` leaves `%41` encoded while
/// this function had already decoded it to `/aA`. Only percent-escapes the
/// `url` crate re-creates on parse (non-ASCII UTF-8, e.g. `/caf%C3%A9`)
/// happened to line up.
///
/// Returning base + raw path makes both comparisons — `dpop-verifier`'s and
/// [`crate::auth::dpop`]'s own exact one — operate on the wire form, so they
/// agree, the aliasing disappears, and the honest case works. There is no
/// fallible step left: every request path is a `htu` a client can sign,
/// including one in the reserved namespace, one that breaks the IRI, and one
/// whose percent-decoding is not valid UTF-8. Each is answered by the handler
/// (`404`/`400`) rather than mis-answered as a `401`, and none of them can
/// reach data, because what a request is *allowed* to touch is the WAC gate's
/// decision on the true target, not this string's.
fn derive_htu(space: &StorageSpace, raw_path: &str) -> String {
    // The root container's IRI is the configured base, by definition.
    let root = space.root();
    let base = root.graph_iri().trim_end_matches('/');
    format!("{base}{raw_path}")
}

/// Authenticate a request from its `Authorization`/`DPoP` headers and
/// attach the resulting `Agent` to `req.extensions()` for downstream
/// handlers to read (attach-not-enforce: access decisions are Plan 5).
///
/// `htu` (the DPoP-bound target URL) is derived from the CONFIGURED public
/// base URI plus the RAW request path (see [`derive_htu`]), never from the
/// request's socket scheme/host — the pod may sit behind a reverse proxy that
/// rewrites those, so trusting them would let an attacker mint proofs against
/// a URL the pod never actually serves under. `now_unix` uses the real wall
/// clock; see `auth::dpop::InMemoryJtiReplayStore` for the matching
/// single-instance replay-store limitation, and `auth::http_jwks` for the
/// JWKS-TTL one.
///
/// Fails closed: any error from `authenticate` (malformed, expired, bad
/// signature, wrong `htu`/`htm`, `cnf.jkt` mismatch, replay, ...) is a
/// `401`. Only the total absence of both credential headers proceeds as
/// `Agent::Public`.
pub async fn auth_layer(State(st): State<AppState>, mut req: Request, next: Next) -> Response {
    let htu = derive_htu(&st.space, req.uri().path());
    let htm = req.method().as_str().to_string();
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let dpop_header = req
        .headers()
        .get("dpop")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_secs() as i64;

    let deps = super::AuthDeps {
        resolver: st.resolver.as_ref(),
        webid_verifier: st.webid_verifier.as_ref(),
        config: st.auth_config.as_ref(),
        replay: st.replay.as_ref(),
    };
    match authenticate(
        auth_header.as_deref(),
        dpop_header.as_deref(),
        &htm,
        &htu,
        deps,
        now_unix,
    )
    .await
    {
        Ok(agent) => {
            req.extensions_mut().insert(agent);
            next.run(req).await
        }
        Err(_) => StatusCode::UNAUTHORIZED.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, routing::get, body::Body, extract::Extension,
        http::{Request, StatusCode, header}, response::IntoResponse};
    use tower::ServiceExt;
    use std::sync::Arc;
    use crate::{space::StorageSpace, store::OxigraphStore,
        auth::{Agent, jwks::StaticJwksResolver, testsupport::{TestIdp, TestClient}}};

    // The property the whole DPoP check now rests on: `htu` is the URL as the
    // client put it on the wire, character for character. A percent-escape is
    // preserved, never decoded — decoding it is what once let a proof for
    // `/a%41` verify against a request to `/a%2541`, two different resources.
    #[test]
    fn derive_htu_is_the_wire_form_of_the_request_path() {
        let space = StorageSpace::new("https://pod.toph.so/").unwrap();
        assert_eq!(derive_htu(&space, "/a%2Fb"), "https://pod.toph.so/a%2Fb");
        assert_eq!(derive_htu(&space, "/caf%C3%A9"), "https://pod.toph.so/caf%C3%A9");
        assert_eq!(derive_htu(&space, "/a%41"), "https://pod.toph.so/a%41");
        assert_eq!(derive_htu(&space, "/a%2541"), "https://pod.toph.so/a%2541");
        assert_ne!(derive_htu(&space, "/a%41"), derive_htu(&space, "/a%2541"));
    }

    // For every path that needs no escaping, the wire form and the target's
    // graph IRI coincide — which is why the change is invisible to ordinary
    // requests. Auxiliaries are included deliberately: their IRI is
    // reassembled from the reserved segment and the subject's path, so if that
    // reassembly ever stopped being "base + request path", every authenticated
    // request to an auxiliary would fail with a 401.
    #[test]
    fn derive_htu_agrees_with_the_graph_iri_for_unescaped_paths() {
        let space = StorageSpace::new("https://pod.toph.so/").unwrap();
        for path in ["/", "/foo", "/box/", "/a/b/c", "/.aux/.acl", "/.aux/foo.acl",
                     "/.aux/box/.acl", "/.auxiliary"] {
            let target = space.resolve(path).expect("resolvable");
            assert_eq!(derive_htu(&space, path), target.graph_iri(), "htu for {path}");
            assert_eq!(derive_htu(&space, path), format!("https://pod.toph.so{path}"));
        }
    }

    // A path in the reserved namespace that names no auxiliary is answered by
    // the handler (404), which it can only do if the credential check passed
    // — so the `htu` must be the one a client signs for that URL, not a
    // fail-closed sentinel that would turn the 404 into a misleading 401.
    #[test]
    fn derive_htu_still_matches_a_signed_url_that_resolves_to_nothing() {
        let space = StorageSpace::new("https://pod.toph.so/").unwrap();
        for path in ["/.aux", "/.aux/", "/.aux/bogus/x", "/foo> bar"] {
            assert!(space.resolve(path).is_err(), "{path} should not resolve");
            assert_eq!(derive_htu(&space, path), format!("https://pod.toph.so{path}"));
        }
    }

    // A raw path whose percent-decoding is not valid UTF-8 is, on the wire,
    // an ordinary signable URL — so it gets an ordinary `htu` rather than the
    // unmatchable sentinel the decoding version needed. Nothing is loosened:
    // the handlers extract their path with axum's `Path<String>`, which
    // refuses the same invalid UTF-8 with a `400`, so such a request is
    // answered for what it is instead of being mis-answered as a `401`.
    #[test]
    fn derive_htu_of_an_invalid_utf8_path_is_still_the_wire_form() {
        let space = StorageSpace::new("https://pod.toph.so/").unwrap();
        assert_eq!(derive_htu(&space, "/%ff%fe"), "https://pod.toph.so/%ff%fe");
    }

    async fn whoami(Extension(agent): Extension<Agent>) -> impl IntoResponse {
        match agent { Agent::Public => "public".to_string(), Agent::WebId(w) => w }
    }

    fn app_with(resolver: Arc<dyn crate::auth::jwks::JwksResolver>) -> Router {
        let state = crate::http::AppState {
            store: Arc::new(OxigraphStore::in_memory().unwrap()),
            events: Arc::new(crate::notify::Bus::new()),
            blobs: Arc::new(crate::blob::ObjectStoreBlobs::in_memory()),
            space: StorageSpace::new("https://pod.toph.so/").unwrap(),
            resolver,
            webid_verifier: Arc::new(crate::auth::webid_issuer::StaticWebIdIssuers::new()),
            auth_config: Arc::new(crate::auth::AuthConfig::default()),
            replay: Arc::new(crate::auth::InMemoryJtiReplayStore::new()),
            max_body_bytes: 64 * 1024 * 1024,
        };
        Router::new().route("/{*path}", get(whoami))
            .layer(axum::middleware::from_fn_with_state(state.clone(), auth_layer))
            .with_state(state)
    }

    #[tokio::test]
    async fn no_credentials_passes_as_public() {
        let idp = TestIdp::new();
        let app = app_with(Arc::new(StaticJwksResolver::new("https://idp.example/", idp.jwks())));
        let res = app.oneshot(Request::builder().uri("/foo").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn tampered_token_is_401() {
        let idp = TestIdp::new();
        let client = TestClient::new();
        let app = app_with(Arc::new(StaticJwksResolver::new("https://idp.example/", idp.jwks())));
        let mut at = idp.mint_access_token("https://alice.example/card#me", &client.jkt(), 9_999_999_999);
        at.push('x'); // corrupt the signature
        let proof = client.mint_dpop("https://pod.toph.so/foo", "GET", 1_000, "jti-http");
        let req = Request::builder().uri("/foo")
            .header(header::AUTHORIZATION, format!("DPoP {at}"))
            .header("dpop", proof).body(Body::empty()).unwrap();
        assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);
    }
}
