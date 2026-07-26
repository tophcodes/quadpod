//! Every route, every verb, no credentials: the answer must always be a
//! refusal. This is the structural safeguard for Plan 6's per-handler guard
//! design — a handler added later without an `authorize` call fails here
//! rather than silently exposing the store.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use sparql_pod::{
    auth::AuthConfig,
    auth::{StaticJwksResolver, StaticWebIdIssuers, Jwks},
    container,
    http::{router, AppState},
    space::StorageSpace,
    store::OxigraphStore,
    wac,
};
use tower::ServiceExt;

const OWNER: &str = "https://alice.example/card#me";

async fn app() -> axum::Router {
    let store = Arc::new(OxigraphStore::in_memory().unwrap());
    let space = StorageSpace::new("https://pod.toph.so/").unwrap();
    container::provision_root(store.as_ref(), &space).await.unwrap();
    wac::provision::provision_root_acl(store.as_ref(), &space, OWNER).await.unwrap();
    // Seed content so that "not found" can never be the reason for a refusal.
    let t = sparql_pod::rdf::parse(
        b"<#it> <http://schema.org/name> \"seed\" .",
        oxigraph::io::RdfFormat::Turtle,
        "https://pod.toph.so/seeded",
    ).unwrap();
    sparql_pod::resource::put_rdf(store.as_ref(), &space, "/seeded", &t).await.unwrap();

    router(AppState {
        store,
        space,
        resolver: Arc::new(StaticJwksResolver::new("https://idp.example/", Jwks { keys: vec![] })),
        webid_verifier: Arc::new(StaticWebIdIssuers::new()),
        auth_config: Arc::new(AuthConfig::default()),
    })
}

#[tokio::test]
async fn no_route_serves_an_unauthenticated_request() {
    let paths = [
        "/", "/seeded", "/seeded.acl", "/.acl", "/box/", "/box/child",
        "/does-not-exist", "/a/b/c",
    ];
    let methods = ["GET", "PUT", "POST", "DELETE"];

    for path in paths {
        for method in methods {
            let app = app().await;
            let req = Request::builder()
                .method(method)
                .uri(path)
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from("<#it> <http://schema.org/name> \"x\" ."))
                .unwrap();
            let status = app.oneshot(req).await.unwrap().status();
            assert!(
                status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
                "{method} {path} returned {status}, expected 401/403 — is a guard missing?"
            );
        }
    }
}
