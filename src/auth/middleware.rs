//! Axum middleware that authenticates each request and attaches its
//! resulting [`Agent`](super::Agent) to the request extensions.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::http::AppState;

use super::authenticate;

/// Authenticate a request from its `Authorization`/`DPoP` headers and
/// attach the resulting `Agent` to `req.extensions()` for downstream
/// handlers to read (attach-not-enforce: access decisions are Plan 5).
///
/// `htu` (the DPoP-bound target URL) is derived from the CONFIGURED public
/// base URI via `st.space.graph_iri`, never from the request's socket
/// scheme/host — the pod may sit behind a reverse proxy that rewrites
/// those, so trusting them would let an attacker mint proofs against a
/// URL the pod never actually serves under. `now_unix` uses the real wall
/// clock; see `auth::dpop`'s doc comment for the matching process-lifetime
/// replay-store limitation, and `auth::http_jwks` for the JWKS-TTL one.
///
/// Fails closed: any error from `authenticate` (malformed, expired, bad
/// signature, wrong `htu`/`htm`, `cnf.jkt` mismatch, replay, ...) is a
/// `401`. Only the total absence of both credential headers proceeds as
/// `Agent::Public`.
pub async fn auth_layer(State(st): State<AppState>, mut req: Request, next: Next) -> Response {
    let htu = match st.space.graph_iri(req.uri().path()) {
        Ok(iri) => iri,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
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

    async fn whoami(Extension(agent): Extension<Agent>) -> impl IntoResponse {
        match agent { Agent::Public => "public".to_string(), Agent::WebId(w) => w }
    }

    fn app_with(resolver: Arc<dyn crate::auth::jwks::JwksResolver>) -> Router {
        let state = crate::http::AppState {
            store: Arc::new(OxigraphStore::in_memory().unwrap()),
            space: StorageSpace::new("https://pod.toph.so/").unwrap(),
            resolver,
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
