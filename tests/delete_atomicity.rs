//! A delete either applies or it does not.
//!
//! Removing a resource and taking it out of its parent's containment are one
//! operation from the client's side: a parent that lists a member which is
//! gone is a state no request can reach and no client can repair, because
//! containment is server-managed and a retry finds nothing left to delete.
//! `SparqlStore`'s atomicity obligation covers one `;`-separated update, so
//! the property holds only while both halves ride in the same one — which is
//! what a store that refuses the containment half specifically can pin.
//!
//! The store decorator lives here for the reason `tests/call_budget.rs` and
//! `tests/observability.rs` state for theirs: `docs/constraints.md` pins
//! `SparqlStore` to one implementor under `src/`, and that rule is about a
//! backend carrying ADR-2's atomicity obligation. A decorator that forwards
//! every call is not a second backend — but the check cannot tell, and
//! weakening it would weaken it against a real one too.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use oxigraph::model::Triple;
use oxigraph::sparql::QuerySolution;
use sparql_pod::{
    auth::{AuthConfig, InMemoryJtiReplayStore, Jwks, StaticJwksResolver, StaticWebIdIssuers},
    aux, container,
    http::{router, AppState},
    rdf::{Format, RdfVersion},
    space::{AuxKind, GraphName, StorageSpace},
    store::{OxigraphStore, SparqlStore, StoreError},
};
use tower::ServiceExt;

/// The containment predicate, spelled out: what this store recognises is the
/// update that touches a parent's membership triples, whether that update
/// carries anything else along with it or not.
const LDP_CONTAINS: &str = "http://www.w3.org/ns/ldp#contains";

/// Forwards to `inner` until [`ContainmentFailingStore::arm`], then refuses
/// every update that would rewrite containment — and only those.
///
/// A store that failed everything could not tell the two designs apart: it
/// would stop the first update as readily as the second, and a delete that
/// never started is trivially atomic. Failing the containment half alone is
/// what makes a two-update delete land in the state this file exists to
/// forbid, and a one-update delete not.
struct ContainmentFailingStore {
    inner: OxigraphStore,
    armed: AtomicBool,
}

impl ContainmentFailingStore {
    fn new(inner: OxigraphStore) -> Self {
        Self { inner, armed: AtomicBool::new(false) }
    }

    /// Armed after the fixture is seeded, so the containment writes that set
    /// the test up are allowed and only the delete's is refused.
    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }

    fn refuses(&self, sparql: &str) -> bool {
        self.armed.load(Ordering::SeqCst) && sparql.contains(LDP_CONTAINS)
    }
}

#[async_trait::async_trait]
impl SparqlStore for ContainmentFailingStore {
    async fn update(&self, sparql: &str) -> Result<(), StoreError> {
        if self.refuses(sparql) {
            return Err(StoreError::Backend("containment is unwritable".into()));
        }
        self.inner.update(sparql).await
    }

    async fn query_triples(&self, sparql: &str) -> Result<Vec<Triple>, StoreError> {
        self.inner.query_triples(sparql).await
    }

    async fn ask(&self, sparql: &str) -> Result<bool, StoreError> {
        self.inner.ask(sparql).await
    }

    async fn query_solutions(&self, sparql: &str) -> Result<Vec<QuerySolution>, StoreError> {
        self.inner.query_solutions(sparql).await
    }

    fn rdf_version(&self) -> RdfVersion {
        self.inner.rdf_version()
    }
}

const PUBLIC_AGENT_CLASS: &str = "http://www.w3.org/ns/auth/acl#agentClass";
const FOAF_AGENT: &str = "http://xmlns.com/foaf/0.1/Agent";

/// An app whose root ACL grants **everyone** read, write and control, for the
/// reason `tests/call_budget.rs` gives: `auth::testsupport` is `#[cfg(test)]`
/// and therefore invisible here, and hand-minted DPoP proofs would test the
/// auth layer rather than the delete.
async fn app() -> (axum::Router, Arc<ContainmentFailingStore>) {
    let failing = Arc::new(ContainmentFailingStore::new(OxigraphStore::in_memory().unwrap()));
    let store: Arc<dyn SparqlStore> = failing.clone();
    let space = StorageSpace::new("https://pod.toph.so/").unwrap();

    container::provision_root(store.as_ref(), &space.root()).await.unwrap();

    let root = space.root();
    let root_acl = root.as_resource().aux(AuxKind::Acl);
    let root_iri = root.graph_iri().to_owned();
    let triples: Vec<Triple> = Format::from_content_type("text/turtle")
        .unwrap()
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

    let app = router(AppState {
        store,
        events: Arc::new(sparql_pod::notify::Bus::new()),
        blobs: Arc::new(sparql_pod::blob::ObjectStoreBlobs::in_memory()),
        space,
        resolver: Arc::new(StaticJwksResolver::new("https://idp.example/", Jwks { keys: vec![] })),
        webid_verifier: Arc::new(StaticWebIdIssuers::new()),
        auth_config: Arc::new(AuthConfig::default()),
        replay: Arc::new(InMemoryJtiReplayStore::new()),
        max_body_bytes: 64 * 1024 * 1024,
        op_keys: None,
    });
    (app, failing)
}

async fn status(app: &axum::Router, method: &str, uri: &str) -> StatusCode {
    app.clone()
        .oneshot(Request::builder().method(method).uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

/// Whether the root container's own representation still names `iri` — the
/// client-visible form of "the parent lists this member". Read over HTTP
/// rather than out of the store, because the dangling triple's whole harm is
/// that a client sees it and cannot act on it.
async fn root_lists(app: &axum::Router, iri: &str) -> bool {
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/")
                .header(header::ACCEPT, "text/turtle")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "the container must stay readable");
    let body = http_body_util::BodyExt::collect(res.into_body()).await.unwrap().to_bytes();
    String::from_utf8(body.to_vec()).unwrap().contains(iri)
}

/// The property: a delete whose containment half cannot happen leaves the
/// resource alone. Split in two updates, the drops commit and the unlink does
/// not, and the root is left listing a member that answers `404` — permanently,
/// since the retry that would repair it finds nothing to delete.
#[tokio::test]
async fn a_delete_that_cannot_unlink_the_member_leaves_the_member_in_place() {
    let (app, store) = app().await;

    let create = Request::builder()
        .method("PUT")
        .uri("/doc")
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from("<#it> <http://schema.org/name> \"doc\" ."))
        .unwrap();
    assert_eq!(app.clone().oneshot(create).await.unwrap().status(), StatusCode::CREATED);
    assert!(
        root_lists(&app, "https://pod.toph.so/doc").await,
        "premise: the root lists the resource before the delete"
    );

    store.arm();
    assert_eq!(
        status(&app, "DELETE", "/doc").await,
        StatusCode::INTERNAL_SERVER_ERROR,
        "premise: the containment removal really did fail"
    );

    assert!(
        root_lists(&app, "https://pod.toph.so/doc").await,
        "the unlink failed, so the containment triple is still there"
    );
    assert_eq!(
        status(&app, "GET", "/doc").await,
        StatusCode::OK,
        "and therefore the resource it names must still be there too"
    );
}
