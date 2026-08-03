//! What an operator can read about a request after it failed.
//!
//! A `500` says nothing to the client (`src/http.rs`'s
//! `a_500_says_nothing_about_the_backend_that_failed` pins that half), so the
//! cause has to be in the log, attributed to the request it belongs to. Both
//! properties are one: the body is only safe to drop because the log has it.
//!
//! Its own test binary, and therefore its own process, because `tracing`'s
//! callsite-interest cache and max-level filter are global. A subscriber
//! installed by one test while the rest of a binary is making requests sees
//! whichever callsites happened to be registered first — this file installs
//! one before anything runs and is the only thing running.
//!
//! The failing store decorator lives here for the reason `tests/call_budget.rs`
//! states for its counting one: `docs/constraints.md` pins `SparqlStore` to a
//! single implementor under `src/`, and that rule is about a backend carrying
//! ADR-2's atomicity obligation.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use oxigraph::model::Triple;
use oxigraph::sparql::QuerySolution;
use sparql_pod::{
    auth::{AuthConfig, InMemoryJtiReplayStore, Jwks, StaticJwksResolver, StaticWebIdIssuers},
    container,
    http::{router, AppState},
    rdf::RdfVersion,
    space::StorageSpace,
    store::{OxigraphStore, SparqlStore, StoreError},
};
use tower::ServiceExt;

/// The message the armed store fails with — what the log must carry and the
/// response must not.
const BACKEND_MESSAGE: &str = "the disk went away";

/// Forwards to `inner` until [`FailingStore::arm`], then fails every read.
///
/// Armed after provisioning, so the pod starts from a well-formed store and
/// the failure lands where a real outage would: on the request's own reads.
struct FailingStore {
    inner: OxigraphStore,
    armed: AtomicBool,
}

impl FailingStore {
    fn new(inner: OxigraphStore) -> Self {
        Self { inner, armed: AtomicBool::new(false) }
    }

    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }

    fn failure<T>(&self) -> Option<Result<T, StoreError>> {
        self.armed
            .load(Ordering::SeqCst)
            .then(|| Err(StoreError::Backend(BACKEND_MESSAGE.into())))
    }
}

#[async_trait::async_trait]
impl SparqlStore for FailingStore {
    async fn update(&self, sparql: &str) -> Result<(), StoreError> {
        match self.failure() {
            Some(e) => e,
            None => self.inner.update(sparql).await,
        }
    }

    async fn query_triples(&self, sparql: &str) -> Result<Vec<Triple>, StoreError> {
        match self.failure() {
            Some(e) => e,
            None => self.inner.query_triples(sparql).await,
        }
    }

    async fn ask(&self, sparql: &str) -> Result<bool, StoreError> {
        match self.failure() {
            Some(e) => e,
            None => self.inner.ask(sparql).await,
        }
    }

    async fn query_solutions(&self, sparql: &str) -> Result<Vec<QuerySolution>, StoreError> {
        match self.failure() {
            Some(e) => e,
            None => self.inner.query_solutions(sparql).await,
        }
    }

    fn rdf_version(&self) -> RdfVersion {
        self.inner.rdf_version()
    }
}

/// A `tracing` sink this test can read back.
#[derive(Clone, Default)]
struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for CapturedLogs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("nothing panics holding this lock").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLogs {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

impl CapturedLogs {
    fn text(&self) -> String {
        let bytes = self.0.lock().expect("nothing panics holding this lock").clone();
        String::from_utf8(bytes).expect("the formatter writes utf-8")
    }
}

/// The store failure reaches the client as a `500` whatever the request was
/// authorized to do, so this needs no credentials and no ACL: the read that
/// fails is the one every request makes before any decision is taken.
async fn app() -> (axum::Router, Arc<FailingStore>) {
    let failing = Arc::new(FailingStore::new(OxigraphStore::in_memory().unwrap()));
    let store: Arc<dyn SparqlStore> = failing.clone();
    let space = StorageSpace::new("https://pod.toph.so/").unwrap();
    container::provision_root(store.as_ref(), &space.root()).await.unwrap();

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
    });
    (app, failing)
}

#[tokio::test]
async fn a_failed_request_leaves_its_cause_in_the_log_and_not_in_the_response() {
    let logs = CapturedLogs::default();
    // Installed before the app is built, so every callsite the request touches
    // is registered while this subscriber is the one being asked about it.
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt().with_writer(logs.clone()).with_ansi(false).finish(),
    )
    .expect("this binary installs one subscriber");

    let (app, store) = app().await;
    store.arm();
    let res = app
        .oneshot(Request::builder().method("GET").uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = http_body_util::BodyExt::collect(res.into_body()).await.unwrap().to_bytes();
    let body = String::from_utf8(body.to_vec()).unwrap();
    // The literal, not the crate's constant: what a client sees is the
    // contract, and it is spelled out here so a change to it has to be made
    // twice, deliberately.
    assert_eq!(body, "internal server error", "the client is told nothing about the store");

    let logged = logs.text();
    assert!(logged.contains(BACKEND_MESSAGE), "the operator is told everything: {logged}");
    assert!(
        logged.contains("method=GET") && logged.contains("path=/"),
        "and which request it was: {logged}"
    );
    assert!(logged.contains("status=500"), "the access log records the answer too: {logged}");
}
