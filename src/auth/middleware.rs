//! Axum middleware that authenticates each request and attaches its
//! resulting [`Agent`](super::Agent) to the request extensions.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use percent_encoding::percent_decode_str;

use crate::http::AppState;
use crate::space::StorageSpace;

use super::authenticate;

/// A `htu` no legitimate DPoP proof can ever carry (real `htu`s are always
/// `<configured base><path>`, always a `http`/`https` IRI). Used as
/// [`derive_htu`]'s fallback when the raw path's percent-decoding is not
/// valid UTF-8, so that fallback fails closed without an early return: an
/// unauthenticated request is unaffected (this value is never read), while
/// an authenticated one fails `verify_dpop`'s `htu` comparison and is
/// rejected as a `401`.
const HTU_DECODE_FAILURE_SENTINEL: &str = "urn:sparql-pod:invalid-percent-decoded-path";

/// Derive the DPoP-bound `htu` for a raw (possibly percent-encoded) request
/// path, percent-decoding it first so it lines up with the path the LDP
/// handlers in `http.rs` actually operate on — they read it via axum's
/// `Path<String>` extractor, which percent-decodes it. Without this
/// decoding, a DPoP proof's `htu` would be checked against a *different* IRI
/// than the one the handler reads/writes, which Plan 5's WAC gate would
/// then authorize incorrectly.
///
/// A `graph_iri` failure on the successfully-decoded path (e.g. it contains
/// IRI-breaking characters) is returned as `Err(())`, matching the request
/// being unroutable to any resource — the caller should reject it outright.
/// A percent-decode failure (invalid UTF-8) is NOT treated as an error here:
/// see [`HTU_DECODE_FAILURE_SENTINEL`].
fn derive_htu(space: &StorageSpace, raw_path: &str) -> Result<String, ()> {
    match percent_decode_str(raw_path).decode_utf8() {
        Ok(decoded) => space.graph_iri(&decoded).map_err(|_| ()),
        Err(_) => Ok(HTU_DECODE_FAILURE_SENTINEL.to_string()),
    }
}

/// Authenticate a request from its `Authorization`/`DPoP` headers and
/// attach the resulting `Agent` to `req.extensions()` for downstream
/// handlers to read (attach-not-enforce: access decisions are Plan 5).
///
/// `htu` (the DPoP-bound target URL) is derived from the CONFIGURED public
/// base URI plus the percent-DECODED request path (see [`derive_htu`]),
/// never from the request's socket scheme/host — the pod may sit behind a
/// reverse proxy that rewrites those, so trusting them would let an
/// attacker mint proofs against a URL the pod never actually serves under.
/// `now_unix` uses the real wall
/// clock; see `auth::dpop`'s doc comment for the matching process-lifetime
/// replay-store limitation, and `auth::http_jwks` for the JWKS-TTL one.
///
/// Fails closed: any error from `authenticate` (malformed, expired, bad
/// signature, wrong `htu`/`htm`, `cnf.jkt` mismatch, replay, ...) is a
/// `401`. Only the total absence of both credential headers proceeds as
/// `Agent::Public`.
pub async fn auth_layer(State(st): State<AppState>, mut req: Request, next: Next) -> Response {
    let htu = match derive_htu(&st.space, req.uri().path()) {
        Ok(iri) => iri,
        Err(()) => return StatusCode::BAD_REQUEST.into_response(),
    };
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

    match authenticate(
        auth_header.as_deref(),
        dpop_header.as_deref(),
        &htm,
        &htu,
        st.resolver.as_ref(),
        st.webid_verifier.as_ref(),
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

    // Handlers in `http.rs` read their path via axum's `Path<String>`
    // extractor, which percent-decodes it. `derive_htu` must decode the raw
    // request path the same way before computing the graph IRI, so the IRI a
    // DPoP proof's `htu` is checked against is the same IRI the handler
    // actually operates on (Important #3, Task 7).
    #[test]
    fn derive_htu_matches_handlers_decoded_path() {
        let space = StorageSpace::new("https://pod.toph.so/").unwrap();
        assert_eq!(
            derive_htu(&space, "/a%2Fb").unwrap(),
            "https://pod.toph.so/a/b"
        );
        assert_eq!(
            derive_htu(&space, "/caf%C3%A9").unwrap(),
            "https://pod.toph.so/café"
        );
    }

    // A raw path whose percent-decoding is not valid UTF-8 must not abort
    // the request outright (that would 400 even a credential-less request,
    // which should still be allowed through as `Public`). Instead it must
    // yield some `htu` that can never match a legitimate DPoP proof, so an
    // authenticated request still fails closed (401 via the normal
    // `verify_dpop` htu mismatch) while an unauthenticated one is unaffected.
    #[test]
    fn derive_htu_on_invalid_utf8_yields_unmatchable_htu_not_an_error() {
        let space = StorageSpace::new("https://pod.toph.so/").unwrap();
        let htu = derive_htu(&space, "/%ff%fe").expect("decode failure must not be Err(())");
        assert_ne!(htu, "https://pod.toph.so/%ff%fe");
        assert!(!htu.is_empty());
    }

    async fn whoami(Extension(agent): Extension<Agent>) -> impl IntoResponse {
        match agent { Agent::Public => "public".to_string(), Agent::WebId(w) => w }
    }

    fn app_with(resolver: Arc<dyn crate::auth::jwks::JwksResolver>) -> Router {
        let state = crate::http::AppState {
            store: Arc::new(OxigraphStore::in_memory().unwrap()),
            space: StorageSpace::new("https://pod.toph.so/").unwrap(),
            resolver,
            webid_verifier: Arc::new(crate::auth::webid_issuer::StaticWebIdIssuers::new()),
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
