//! The fixture every test file in this directory builds on, and the
//! imports they all need: a sibling gets both from `use super::fixture::*`.

pub(super) use super::super::*;
pub(super) use axum::body::Body;
pub(super) use axum::http::{Request, StatusCode, header};
pub(super) use tower::ServiceExt;
pub(super) use std::sync::Arc;
pub(super) use std::time::{SystemTime, UNIX_EPOCH};
pub(super) use tokio::time::{timeout, Duration};
pub(super) use crate::{space::{ContainerUrl, StorageSpace}, store::OxigraphStore, auth::StaticJwksResolver};
pub(super) use crate::auth::testsupport::{TestClient, TestIdp};
pub(super) use crate::auth::StaticWebIdIssuers;

pub(super) const OWNER: &str = "https://alice.example/card#me";

pub(super) const ISSUER: &str = "https://idp.example/";

/// An app whose root ACL grants OWNER full control, plus the IdP and
/// client needed to mint credentials for them. The store, space and
/// replay set are kept so a second app can be built over the SAME pod
/// (see [`Fixture::app_also_trusting`]) and so tests can inspect the
/// store directly.
pub(super) struct Fixture {
    pub(super) app: axum::Router,
    pub(super) events: Arc<crate::notify::Bus>,
    pub(super) store: Arc<dyn crate::store::SparqlStore>,
    pub(super) blobs: Arc<dyn crate::blob::BlobStore>,
    pub(super) space: StorageSpace,
    pub(super) replay: Arc<dyn crate::auth::JtiReplayStore>,
    pub(super) max_body_bytes: usize,
    pub(super) idp: TestIdp,
    pub(super) client: TestClient,
}

pub(super) async fn fixture() -> Fixture {
    fixture_with_body_limit(64 * 1024 * 1024).await
}

pub(super) async fn fixture_with_body_limit(max_body_bytes: usize) -> Fixture {
    fixture_with_blobs(Arc::new(crate::blob::ObjectStoreBlobs::in_memory()), max_body_bytes).await
}

/// Like [`fixture`], but with a caller-chosen `BlobStore` — for a fixture
/// whose blob backend is failing (see `a_blob_backend_outage_answers_500_not_400`).
pub(super) async fn fixture_with_blobs(blobs: Arc<dyn crate::blob::BlobStore>, max_body_bytes: usize) -> Fixture {
    fixture_with_store_and_blobs(
        Arc::new(OxigraphStore::in_memory().unwrap()), blobs, max_body_bytes,
    ).await
}

/// Like [`fixture_with_blobs`], but with a caller-chosen `SparqlStore` too
/// — for a fixture whose store backend starts failing partway through a
/// test (see `a_failed_write_after_a_warning_carries_no_report_link`).
pub(super) async fn fixture_with_store_and_blobs(
    store: Arc<dyn crate::store::SparqlStore>,
    blobs: Arc<dyn crate::blob::BlobStore>,
    max_body_bytes: usize,
) -> Fixture {
    let space = StorageSpace::new("https://pod.toph.so/").unwrap();
    crate::container::provision_root(store.as_ref(), &space.root()).await.unwrap();
    crate::wac::provision::provision_root_acl(
        store.as_ref(), &space, &NamedNode::new(OWNER).unwrap(), false,
    ).await.unwrap();

    let idp = TestIdp::new();
    let client = TestClient::new();
    let mut issuers = StaticWebIdIssuers::new();
    issuers.allow(OWNER, ISSUER);

    let events = Arc::new(crate::notify::Bus::new());
    let replay: Arc<dyn crate::auth::JtiReplayStore> =
        Arc::new(crate::auth::InMemoryJtiReplayStore::new());
    let state = AppState {
        store: store.clone(),
        events: events.clone(),
        blobs: blobs.clone(),
        space: space.clone(),
        resolver: Arc::new(StaticJwksResolver::new(ISSUER, idp.jwks())),
        webid_verifier: Arc::new(issuers),
        auth_config: Arc::new(crate::auth::AuthConfig::default()),
        replay: replay.clone(),
        max_body_bytes,
        op_keys: None,
    };
    Fixture {
        app: router(state), events, store, blobs, space, replay, max_body_bytes, idp, client,
    }
}

/// Like [`fixture`], but the pod is its own OP: `op_keys` is set, the
/// resolver maps the pod's own issuer to the key set's public JWKS, and
/// OWNER's WebID authorizes the pod as issuer — so a token minted by
/// `op::mint_access_token` authenticates a request end to end.
///
/// The returned path is the key file the loader wrote; the caller removes it.
pub(super) async fn fixture_with_op() -> (Fixture, Arc<crate::op::KeySet>, std::path::PathBuf) {
    let path = std::env::temp_dir().join(format!("op-fixture-{}.json", uuid::Uuid::new_v4()));
    let op = Arc::new(crate::op::KeySet::load_or_generate(&path).unwrap());
    let mut f = fixture().await;

    let parsed: Vec<josekit::jwk::Jwk> = op.public_jwks()["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| josekit::jwk::Jwk::from_map(v.as_object().unwrap().clone()).unwrap())
        .collect();
    let issuer = "https://pod.toph.so/";
    let mut issuers = StaticWebIdIssuers::new();
    issuers.allow(OWNER, issuer);

    f.app = router(AppState {
        store: f.store.clone(),
        events: f.events.clone(),
        blobs: f.blobs.clone(),
        space: f.space.clone(),
        resolver: Arc::new(StaticJwksResolver::new(
            issuer,
            crate::auth::Jwks { keys: parsed },
        )),
        webid_verifier: Arc::new(issuers),
        auth_config: Arc::new(crate::auth::AuthConfig::default()),
        replay: f.replay.clone(),
        max_body_bytes: f.max_body_bytes,
        op_keys: Some(op.clone()),
    });
    (f, op, path)
}

pub(super) fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

impl Fixture {
    /// Add credentials for `webid` to a request builder. The DPoP proof's
    /// `htu` must be the CONFIGURED base plus the path (never the socket),
    /// and its `jti` must be unique — the replay store rejects reuse.
    pub(super) fn sign(
        &self,
        builder: axum::http::request::Builder,
        webid: &str,
        method: &str,
        path: &str,
    ) -> axum::http::request::Builder {
        let at = self.idp.mint_access_token(webid, &self.client.jkt(), now_unix() + 3600);
        let htu = format!("https://pod.toph.so{path}");
        let jti = uuid::Uuid::new_v4().to_string();
        let proof = self.client.mint_dpop(&htu, method, now_unix(), &jti);
        builder
            .header(header::AUTHORIZATION, format!("DPoP {at}"))
            .header("dpop", proof)
    }

    /// A request authenticated as the pod owner.
    pub(super) fn owner_request(&self, method: &str, path: &str) -> axum::http::request::Builder {
        let b = Request::builder().method(method).uri(path);
        self.sign(b, OWNER, method, path)
    }

    /// A request whose URI carries a query string. The DPoP proof is
    /// signed for the bare path, because `htu` excludes the query.
    pub(super) fn owner_request_query(&self, method: &str, path: &str, query: &str)
        -> axum::http::request::Builder
    {
        let b = Request::builder().method(method).uri(format!("{path}?{query}"));
        self.sign(b, OWNER, method, path)
    }

    pub(super) async fn put_turtle(&self, path: &str, ttl: &str) {
        let res = self.app.clone().oneshot(self.owner_request("PUT", path)
            .header(header::CONTENT_TYPE, "text/turtle")
            .body(Body::from(ttl.to_owned())).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED, "PUT {path}");
    }

    pub(super) async fn get_turtle(&self, path: &str) -> String {
        let res = self.app.clone().oneshot(self.owner_request("GET", path)
            .header(header::ACCEPT, "text/turtle")
            .body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK, "GET {path}");
        let b = http_body_util::BodyExt::collect(res.into_body()).await.unwrap().to_bytes();
        String::from_utf8(b.to_vec()).unwrap()
    }

    pub(super) async fn put_blob(&self, path: &str, ct: &str, body: &'static [u8]) {
        let res = self.app.clone().oneshot(self.owner_request("PUT", path)
            .header(header::CONTENT_TYPE, ct)
            .body(Body::from(body)).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED, "PUT {path}");
    }

    pub(super) async fn etag_of(&self, path: &str) -> String {
        let res = self.app.clone().oneshot(self.owner_request("GET", path)
            .body(Body::empty()).unwrap()).await.unwrap();
        res.headers()[header::ETAG].to_str().unwrap().to_owned()
    }

    /// The typed URL a request path names, for tests that inspect the
    /// store directly rather than through HTTP.
    pub(super) fn url(&self, path: &str) -> Target {
        self.space.resolve(path).expect("test path resolves")
    }

    pub(super) fn container(&self, path: &str) -> ContainerUrl {
        match self.url(path) {
            Target::Container(c) => c,
            _ => panic!("{path} is not a container path"),
        }
    }

    /// What is stored at `path`, straight from the store.
    pub(super) async fn stored(&self, path: &str) -> Option<Vec<oxigraph::model::Triple>> {
        crate::resource::get_rdf(self.store.as_ref(), &self.url(path)).await.unwrap()
    }

    /// A second app over the same store, authenticating `webid` as well.
    pub(super) fn app_also_trusting(&self, webid: &str) -> axum::Router {
        let mut issuers = StaticWebIdIssuers::new();
        issuers.allow(OWNER, ISSUER);
        issuers.allow(webid, ISSUER);
        router(AppState {
            store: self.store.clone(),
            // The same bus as `app`: this router serves the same data, so a
            // test subscribed through `Fixture::events` must hear what a
            // write through either router reports.
            events: self.events.clone(),
            blobs: self.blobs.clone(),
            space: self.space.clone(),
            resolver: Arc::new(StaticJwksResolver::new(ISSUER, self.idp.jwks())),
            webid_verifier: Arc::new(issuers),
            auth_config: Arc::new(crate::auth::AuthConfig::default()),
            // The same replay set as `app`: this is the same pod behind
            // a second router, so a proof spent through one must not be
            // spendable again through the other.
            replay: self.replay.clone(),
            max_body_bytes: self.max_body_bytes,
            op_keys: None,
        })
    }
}

pub(super) async fn body_string(res: axum::response::Response) -> String {
    let b = http_body_util::BodyExt::collect(res.into_body()).await.unwrap().to_bytes();
    String::from_utf8_lossy(&b).into_owned()
}

pub(super) const TRIPLE_TERM_TTL: &str =
    "<#it> <http://e/p> <<( <http://e/a> <http://e/b> <http://e/c> )>> .";

pub(super) const DIRECTIONAL_TTL: &str = "<#it> <http://e/p> \"hi\"@en--ltr .";

pub(super) async fn put_versioned(f: &Fixture, path: &str, ct: &str, ttl: &'static str)
    -> axum::response::Response
{
    let req = f.owner_request("PUT", path)
        .header(header::CONTENT_TYPE, ct)
        .body(Body::from(ttl)).unwrap();
    f.app.clone().oneshot(req).await.unwrap()
}

pub(super) async fn get_accepting(f: &Fixture, path: &str, accept: &str) -> axum::response::Response {
    let req = f.owner_request("GET", path)
        .header(header::ACCEPT, accept)
        .body(Body::empty()).unwrap();
    f.app.clone().oneshot(req).await.unwrap()
}

/// Write `body` as the ACL of `subject_path` and return the response.
pub(super) async fn put_acl(f: &Fixture, subject_path: &str, body: &str) -> axum::response::Response {
    let path = format!("/.aux{subject_path}.acl");
    let req = f.owner_request("PUT", &path)
        .header(header::CONTENT_TYPE, "text/turtle")
        .body(Body::from(body.to_owned())).unwrap();
    f.app.clone().oneshot(req).await.unwrap()
}

/// A `BlobStore` whose `put` always fails, standing in for a backend
/// outage — disk full, bucket unreachable. Reached only through the HTTP
/// handlers here, unlike `resource::`'s own `FailingBlobs`: that one
/// pins `put_dataset`'s write order, but nothing at that level ever
/// passes through `put_status`, which is the function this test exists
/// to cover.
pub(super) struct FailingBlobs;

#[async_trait::async_trait]
impl crate::blob::BlobStore for FailingBlobs {
    async fn put(&self, _: &crate::blob::BlobKey, _: bytes::Bytes)
        -> Result<(), crate::blob::BlobError> {
        Err(crate::blob::BlobError::Backend("disk on fire".into()))
    }
    async fn get(&self, _: &crate::blob::BlobKey)
        -> Result<Option<bytes::Bytes>, crate::blob::BlobError> {
        Err(crate::blob::BlobError::Backend("disk on fire".into()))
    }
    async fn delete(&self, _: &crate::blob::BlobKey)
        -> Result<(), crate::blob::BlobError> { Ok(()) }
}

/// A `SparqlStore` that delegates to a real in-memory store until
/// [`FailingStore::arm`] is called, after which every `update` fails —
/// standing in for a backend outage that starts partway through a test.
/// Reads (`query_triples`, `ask`) always delegate, so shape lookup and
/// validation, which never write, are unaffected.
pub(super) struct FailingStore {
    inner: OxigraphStore,
    armed: std::sync::atomic::AtomicBool,
}

impl FailingStore {
    pub(super) fn new(inner: OxigraphStore) -> Self {
        Self { inner, armed: std::sync::atomic::AtomicBool::new(false) }
    }
    pub(super) fn arm(&self) {
        self.armed.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl crate::store::SparqlStore for FailingStore {
    async fn update(&self, sparql: &str) -> Result<(), crate::store::StoreError> {
        if self.armed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(crate::store::StoreError::Backend("store backend outage".into()));
        }
        self.inner.update(sparql).await
    }
    async fn query_triples(&self, sparql: &str) -> Result<Vec<Triple>, crate::store::StoreError> {
        self.inner.query_triples(sparql).await
    }
    async fn ask(&self, sparql: &str) -> Result<bool, crate::store::StoreError> {
        self.inner.ask(sparql).await
    }
    /// Delegated, not pinned: this double exists to fail *writes*, and
    /// answering anything else here would make it quietly also a test of
    /// version refusal.
    fn rdf_version(&self) -> crate::rdf::RdfVersion {
        self.inner.rdf_version()
    }
    async fn query_solutions(&self, sparql: &str)
        -> Result<Vec<oxigraph::sparql::QuerySolution>, crate::store::StoreError>
    {
        self.inner.query_solutions(sparql).await
    }
}

pub(super) fn patch_body(inner: &str) -> String {
    format!(
        "@prefix solid: <http://www.w3.org/ns/solid/terms#> .\n\
         @prefix ex: <http://example.org/> .\n{inner}"
    )
}

pub(super) async fn patch_n3(f: &Fixture, path: &str, inner: &str) -> axum::response::Response {
    f.app.clone().oneshot(f.owner_request("PATCH", path)
        .header(header::CONTENT_TYPE, "text/n3")
        .body(Body::from(patch_body(inner))).unwrap()).await.unwrap()
}
