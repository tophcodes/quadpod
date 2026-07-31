//! What one request costs the store.
//!
//! The budgets are upper bounds, not equalities: a budget that fails when the
//! count drops punishes the improvement it exists to protect. They are
//! committed against the counts as they were before
//! `2026-07-31-request-scoped-guard-design.md` was implemented, and tightened
//! in the commit that makes the lower numbers true.
//!
//! The store decorator lives here rather than in `src/` because
//! `docs/constraints.md` pins `SparqlStore` to one implementor under `src/`,
//! and that rule is about a backend carrying ADR-2's atomicity obligation. A
//! decorator that forwards every call is not a second backend — but the check
//! cannot tell, and weakening it would weaken it against a real one too.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use oxigraph::model::Triple;
use oxigraph::sparql::QuerySolution;
use sparql_pod::{
    auth::{AuthConfig, StaticJwksResolver, StaticWebIdIssuers, Jwks},
    aux, container,
    http::{router, AppState},
    rdf::{Format, RdfVersion},
    space::{AuxKind, GraphName, StorageSpace, Target},
    store::{OxigraphStore, SparqlStore, StoreError},
};
use tower::ServiceExt;

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
struct Counts {
    update: usize,
    query_triples: usize,
    ask: usize,
    query_solutions: usize,
}

impl Counts {
    fn total(self) -> usize {
        self.update + self.query_triples + self.ask + self.query_solutions
    }
}

/// Forwards every call to `inner` and tallies it. Holds no state of its own,
/// so it inherits `OxigraphStore`'s `;`-sequence atomicity rather than
/// claiming its own.
struct CountingStore {
    inner: OxigraphStore,
    counts: Mutex<Counts>,
}

impl CountingStore {
    fn new(inner: OxigraphStore) -> Self {
        Self { inner, counts: Mutex::new(Counts::default()) }
    }

    /// Read the tally and reset it, so each test measures one request.
    fn take(&self) -> Counts {
        std::mem::take(&mut self.counts.lock().unwrap())
    }
}

#[async_trait::async_trait]
impl SparqlStore for CountingStore {
    async fn update(&self, sparql: &str) -> Result<(), StoreError> {
        self.counts.lock().unwrap().update += 1;
        self.inner.update(sparql).await
    }

    async fn query_triples(&self, sparql: &str) -> Result<Vec<Triple>, StoreError> {
        self.counts.lock().unwrap().query_triples += 1;
        self.inner.query_triples(sparql).await
    }

    async fn ask(&self, sparql: &str) -> Result<bool, StoreError> {
        self.counts.lock().unwrap().ask += 1;
        self.inner.ask(sparql).await
    }

    async fn query_solutions(&self, sparql: &str) -> Result<Vec<QuerySolution>, StoreError> {
        self.counts.lock().unwrap().query_solutions += 1;
        self.inner.query_solutions(sparql).await
    }

    fn rdf_version(&self) -> RdfVersion {
        self.inner.rdf_version()
    }
}

const PUBLIC_AGENT_CLASS: &str = "http://www.w3.org/ns/auth/acl#agentClass";
const FOAF_AGENT: &str = "http://xmlns.com/foaf/0.1/Agent";

/// An app whose root ACL grants **everyone** read, write and control.
///
/// Public access is what makes this file credential-free: `auth::testsupport`
/// is `#[cfg(test)]` and so invisible to an integration test, and minting DPoP
/// proofs by hand here would measure the auth layer rather than the store. The
/// store-call counts are identical either way — `pdp::decide` is pure, and the
/// one branch that differs for an anonymous agent (reusing the user decision
/// as the public one) touches nothing stored.
async fn app() -> (axum::Router, Arc<CountingStore>) {
    let counting = Arc::new(CountingStore::new(OxigraphStore::in_memory().unwrap()));
    let store: Arc<dyn SparqlStore> = counting.clone();
    let space = StorageSpace::new("https://pod.toph.so/").unwrap();

    container::provision_root(store.as_ref(), &space.root()).await.unwrap();

    let root = space.root();
    let root_acl = root.as_resource().aux(AuxKind::Acl);
    let root_iri = root.graph_iri().to_owned();
    let turtle = Format::from_content_type("text/turtle").unwrap();
    let triples: Vec<Triple> = turtle
        .parse(
            format!(
                "<#public> <{PUBLIC_AGENT_CLASS}> <{FOAF_AGENT}> ; \
                 <http://www.w3.org/ns/auth/acl#accessTo> <{root_iri}> ; \
                 <http://www.w3.org/ns/auth/acl#default> <{root_iri}> ; \
                 <http://www.w3.org/ns/auth/acl#mode> \
                   <http://www.w3.org/ns/auth/acl#Read>, \
                   <http://www.w3.org/ns/auth/acl#Write>, \
                   <http://www.w3.org/ns/auth/acl#Control> ."
            )
            .as_bytes(),
            root_acl.graph_iri(),
            RdfVersion::Rdf11,
        )
        .unwrap()
        .quads().iter().cloned().map(Triple::from).collect();
    aux::put(store.as_ref(), &root_acl, &triples).await.unwrap();

    let Target::Resource(seeded) = space.resolve("/seeded").unwrap() else {
        unreachable!("/seeded is a resource path")
    };
    let content: Vec<Triple> = turtle
        .parse(
            b"<#it> <http://schema.org/name> \"seed\" .",
            seeded.graph_iri(),
            RdfVersion::Rdf11,
        )
        .unwrap()
        .quads().iter().cloned().map(Triple::from).collect();
    sparql_pod::resource::put_rdf(store.as_ref(), &seeded, &content).await.unwrap();

    let app = router(AppState {
        store,
        blobs: Arc::new(sparql_pod::blob::ObjectStoreBlobs::in_memory()),
        space,
        resolver: Arc::new(StaticJwksResolver::new("https://idp.example/", Jwks { keys: vec![] })),
        webid_verifier: Arc::new(StaticWebIdIssuers::new()),
        auth_config: Arc::new(AuthConfig::default()),
        max_body_bytes: 64 * 1024 * 1024,
    });
    (app, counting)
}

const GET_BUDGET: usize = 8;

#[tokio::test]
async fn a_get_stays_within_budget() {
    let (app, counts) = app().await;
    counts.take(); // discard the fixture's own writes

    let res = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/seeded")
                .header(header::ACCEPT, "text/turtle")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let c = counts.take();
    println!("GET /seeded: {c:?} total={}", c.total());
    assert!(c.total() <= GET_BUDGET, "GET /seeded cost {c:?}, budget {GET_BUDGET}");
}

const PUT_EXISTING_BUDGET: usize = 11;

#[tokio::test]
async fn a_put_on_an_existing_resource_stays_within_budget() {
    let (app, counts) = app().await;
    counts.take();

    let res = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/seeded")
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from("<#it> <http://schema.org/name> \"two\" ."))
                .unwrap(),
        )
        .await
        .unwrap();
    // Every successful PUT to a resource answers `201 Created` regardless of
    // whether the resource previously existed (`src/http.rs`'s `put_impl`
    // returns `created(&target)` unconditionally) — matched here rather than
    // the `204` the brief assumed.
    assert_eq!(res.status(), StatusCode::CREATED);

    let c = counts.take();
    println!("PUT /seeded (existing): {c:?} total={}", c.total());
    assert!(
        c.total() <= PUT_EXISTING_BUDGET,
        "PUT /seeded (existing) cost {c:?}, budget {PUT_EXISTING_BUDGET}"
    );
}

const PUT_DEEP_BUDGET: usize = 13;

#[tokio::test]
async fn a_put_creating_a_deep_resource_stays_within_budget() {
    let (app, counts) = app().await;
    counts.take();

    let res = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/a/b/c")
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from("<#it> <http://schema.org/name> \"two\" ."))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    let c = counts.take();
    println!("PUT /a/b/c (deep): {c:?} total={}", c.total());
    assert!(
        c.total() <= PUT_DEEP_BUDGET,
        "PUT /a/b/c (deep) cost {c:?}, budget {PUT_DEEP_BUDGET}"
    );
}

const POST_BUDGET: usize = 9;

#[tokio::test]
async fn a_post_stays_within_budget() {
    let (app, counts) = app().await;
    counts.take();

    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/")
                .header(header::CONTENT_TYPE, "text/turtle")
                .header("Slug", "child")
                .body(Body::from("<#it> <http://schema.org/name> \"two\" ."))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    let c = counts.take();
    println!("POST /: {c:?} total={}", c.total());
    assert!(c.total() <= POST_BUDGET, "POST / cost {c:?}, budget {POST_BUDGET}");
}

const DELETE_BUDGET: usize = 6;

#[tokio::test]
async fn a_delete_stays_within_budget() {
    let (app, counts) = app().await;
    counts.take();

    let res = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/seeded")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    let c = counts.take();
    println!("DELETE /seeded: {c:?} total={}", c.total());
    assert!(c.total() <= DELETE_BUDGET, "DELETE /seeded cost {c:?}, budget {DELETE_BUDGET}");
}

const PATCH_BUDGET: usize = 7;

#[tokio::test]
async fn a_patch_stays_within_budget() {
    let (app, counts) = app().await;
    counts.take();

    let body = "@prefix solid: <http://www.w3.org/ns/solid/terms#> .\n\
                _:patch a solid:InsertDeletePatch ;\n\
                  solid:inserts { <https://pod.toph.so/seeded#it> <http://schema.org/name> \"patched\" . } .\n";

    let res = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/seeded")
                .header(header::CONTENT_TYPE, "text/n3")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    let c = counts.take();
    println!("PATCH /seeded: {c:?} total={}", c.total());
    assert!(c.total() <= PATCH_BUDGET, "PATCH /seeded cost {c:?}, budget {PATCH_BUDGET}");
}
