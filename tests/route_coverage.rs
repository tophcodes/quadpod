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
    space::{GraphName, StorageSpace, Target},
    store::OxigraphStore,
    wac,
};
use tower::ServiceExt;

const OWNER: &str = "https://alice.example/card#me";

async fn app() -> axum::Router {
    let store = Arc::new(OxigraphStore::in_memory().unwrap());
    let space = StorageSpace::new("https://pod.toph.so/").unwrap();
    container::provision_root(store.as_ref(), &space.root()).await.unwrap();
    wac::provision::provision_root_acl(store.as_ref(), &space, OWNER, false).await.unwrap();
    // Seed content so that "not found" can never be the reason for a refusal,
    // and seed its ACL too so the reserved namespace is populated as well.
    let Target::Resource(seeded) = space.resolve("/seeded").unwrap() else {
        unreachable!("/seeded is a resource path")
    };
    let turtle = sparql_pod::rdf::Format::from_content_type("text/turtle").unwrap();
    let t: Vec<oxigraph::model::Triple> = turtle
        .parse(b"<#it> <http://schema.org/name> \"seed\" .", seeded.graph_iri())
        .unwrap()
        .quads().iter().cloned().map(oxigraph::model::Triple::from).collect();
    sparql_pod::resource::put_rdf(store.as_ref(), &seeded, &t).await.unwrap();
    let acl = seeded.aux(sparql_pod::space::AuxKind::Acl);
    let acl_triples: Vec<oxigraph::model::Triple> = turtle
        .parse(
            format!(
                "<#o> <http://www.w3.org/ns/auth/acl#agent> <{OWNER}> ; \
                 <http://www.w3.org/ns/auth/acl#accessTo> <{}> ; \
                 <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Control> .",
                seeded.graph_iri(),
            ).as_bytes(),
            acl.graph_iri(),
        )
        .unwrap()
        .quads().iter().cloned().map(oxigraph::model::Triple::from).collect();
    sparql_pod::aux::put(store.as_ref(), &acl, &acl_triples).await.unwrap();

    router(AppState {
        store,
        blobs: Arc::new(sparql_pod::blob::ObjectStoreBlobs::in_memory()),
        space,
        resolver: Arc::new(StaticJwksResolver::new("https://idp.example/", Jwks { keys: vec![] })),
        webid_verifier: Arc::new(StaticWebIdIssuers::new()),
        auth_config: Arc::new(AuthConfig::default()),
        max_body_bytes: 64 * 1024 * 1024,
    })
}

#[tokio::test]
async fn no_route_serves_an_unauthenticated_request() {
    let paths = [
        "/", "/seeded", "/.aux/seeded.acl", "/.aux/.acl", "/box/", "/box/child",
        "/does-not-exist", "/a/b/c",
    ];
    // HEAD is served by the same handler axum's `get()` route installs, so it
    // is guarded like GET — but this test exists to be structural, and a verb
    // that reaches a handler belongs in the list whether or not it currently
    // shares one. Only the status is asserted: a HEAD response has no body.
    let methods = ["GET", "HEAD", "PUT", "POST", "DELETE"];

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

/// The reserved namespace is not storage, so a path in it that names no
/// auxiliary resource is refused before authorization can even apply — there
/// is no resource to hold an ACL. Nothing is served either way, which is what
/// the test above is really about; the status differs because the reason
/// does.
#[tokio::test]
async fn the_unallocated_reserved_namespace_serves_nothing_either() {
    let paths = ["/.aux", "/.aux/", "/.aux/bogus/x", "/.aux/.aux/seeded.acl.acl"];
    let methods = ["GET", "HEAD", "PUT", "POST", "DELETE"];

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
            assert_eq!(
                status, StatusCode::NOT_FOUND,
                "{method} {path} returned {status}, expected 404 — is it addressable?"
            );
        }
    }
}
