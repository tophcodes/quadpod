use crate::rdf::RdfVersion;
use oxigraph::model::Triple;
use oxigraph::sparql::{QueryResults, QuerySolution, SparqlEvaluator};
use oxigraph::store::Store;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("store backend error: {0}")]
    Backend(String),
}

/// A SPARQL 1.1 endpoint the pod stores everything through.
///
/// **Obligation on every implementor: a `;`-separated update sequence is
/// atomic.** Either every operation in it takes effect or none does. This is
/// not something SPARQL guarantees — it is a property of the backend, and
/// `OxigraphStore` has it because `BoundPreparedSparqlUpdate::execute`
/// evaluates all operations before it commits.
///
/// Every write path depends on it and none of them can check it. A resource
/// write drops the old content, writes the new, and marks presence in one
/// sequence; an implementor without the property would let an interruption
/// leave content with no presence marker (invisible forever) or a marker with
/// no content, and there is no compile error to say so. See the parent design
/// spec §16, ADR-2.
#[async_trait::async_trait]
pub trait SparqlStore: Send + Sync {
    async fn update(&self, sparql: &str) -> Result<(), StoreError>;
    async fn query_triples(&self, sparql: &str) -> Result<Vec<Triple>, StoreError>;
    async fn ask(&self, sparql: &str) -> Result<bool, StoreError>;


    /// The richest [`RdfVersion`] this backend can hold — the amended §13 of
    /// the root spec, which now names capabilities rather than a product
    /// class. The write path refuses a representation above it with `415`.
    ///
    /// Neither `async` nor fallible: an implementor either knows this from
    /// its own construction (embedded) or from its configuration (a generic
    /// client for a remote endpoint, whose capability is a property of the
    /// endpoint and not of its own code).
    ///
    /// Deliberately **not** a marker subtrait. That would make the capability
    /// a property of the *type*, which the remote case is not — one type, two
    /// capabilities depending on config — and `AppState` holds
    /// `Arc<dyn SparqlStore>` (ADR-2), so a subtrait would be reachable only
    /// by `Any` downcasting: a bool with ceremony.
    fn rdf_version(&self) -> RdfVersion;

    /// A `SELECT`'s solutions, in the order the backend produced them.
    ///
    /// The third read shape, beside a graph and a boolean. It exists because
    /// N3 Patch must distinguish *no* variable mapping from *one* from *several*
    /// (`2026-07-30-n3-patch-design.md` §6), and neither a `CONSTRUCT` nor an
    /// `ASK` answers that question without encoding a `SELECT` into one of them
    /// and decoding it again.
    ///
    /// Carries no atomicity obligation: this trait's guarantee is about
    /// `;`-separated *updates*, and a read cannot come apart the way a write
    /// sequence can.
    async fn query_solutions(&self, sparql: &str) -> Result<Vec<QuerySolution>, StoreError>;
}

pub struct OxigraphStore {
    inner: Store,
}

impl OxigraphStore {
    pub fn in_memory() -> Result<Self, StoreError> {
        Store::new()
            .map(|inner| Self { inner })
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    /// Runs `f` against the store on Tokio's blocking pool.
    ///
    /// Oxigraph is a synchronous library: `Store::update` and a query's
    /// `execute` run to completion on the calling thread. Awaiting them
    /// directly inside an `async fn` occupies a runtime worker for the whole
    /// evaluation, and a runtime has one worker per core — so a handful of
    /// concurrent queries stall *every* request in flight, including those
    /// that never touch the store.
    ///
    /// It is invisible against the in-memory store, where an evaluation is
    /// microseconds; it is not invisible against a durable one, where the
    /// same call also waits on disk. The offload belongs here, not at the
    /// call sites, because the trait is `async` precisely so a backend can
    /// decide how it yields.
    ///
    /// **This is the only place that reaches for the store handle** — pinned
    /// by a rule in `docs/constraints.md`, since a trait method evaluating
    /// against the handle directly compiles and passes every test.
    async fn blocking<T, F>(&self, f: F) -> Result<T, StoreError>
    where
        F: FnOnce(&Store) -> Result<T, StoreError> + Send + 'static,
        T: Send + 'static,
    {
        // Cheap: `Store` is a handle over shared backing state, so the clone
        // is what lets the closure own its reference for the pool's lifetime.
        let store = self.inner.clone();
        tokio::task::spawn_blocking(move || f(&store))
            .await
            .map_err(|e| StoreError::Backend(format!("store task did not complete: {e}")))?
    }
}

#[async_trait::async_trait]
impl SparqlStore for OxigraphStore {
    async fn update(&self, sparql: &str) -> Result<(), StoreError> {
        let sparql = sparql.to_owned();
        self.blocking(move |store| {
            store
                .update(&sparql)
                .map_err(|e| StoreError::Backend(e.to_string()))
        })
        .await
    }

    async fn query_triples(&self, sparql: &str) -> Result<Vec<Triple>, StoreError> {
        let sparql = sparql.to_owned();
        self.blocking(move |store| {
            let results = evaluate(store, &sparql)?;
            let QueryResults::Graph(triples) = results else {
                return Err(StoreError::Backend("expected CONSTRUCT/graph results".into()));
            };
            triples
                .map(|t| t.map_err(|e| StoreError::Backend(e.to_string())))
                .collect()
        })
        .await
    }

    async fn ask(&self, sparql: &str) -> Result<bool, StoreError> {
        let sparql = sparql.to_owned();
        self.blocking(move |store| match evaluate(store, &sparql)? {
            QueryResults::Boolean(b) => Ok(b),
            _ => Err(StoreError::Backend("expected ASK/boolean results".into())),
        })
        .await
    }


    fn rdf_version(&self) -> RdfVersion {
        // A constant, and an honest one: `Cargo.toml` declares
        // `oxigraph/rdf-12`, so the store and this claim ship together, and
        // removing the declaration fails the build rather than quietly
        // making this a lie (`GroundTerm::Triple` converts from
        // `Term::Triple`, which that feature is what provides).
        //
        // `cfg!(feature = "rdf-12")` would answer a different question — it
        // tests *this* crate's features, and oxigraph's are not visible from
        // here.
        RdfVersion::Rdf12
    }

    async fn query_solutions(&self, sparql: &str) -> Result<Vec<QuerySolution>, StoreError> {
        let sparql = sparql.to_owned();
        self.blocking(move |store| {
            let QueryResults::Solutions(solutions) = evaluate(store, &sparql)? else {
                return Err(StoreError::Backend("expected SELECT/solution results".into()));
            };
            solutions
                .map(|s| s.map_err(|e| StoreError::Backend(e.to_string())))
                .collect()
        })
        .await
    }
}

/// Parses and evaluates a read query against `store`, synchronously.
///
/// The three read shapes differ only in which `QueryResults` variant they
/// accept, so the parse and the `execute` live here once. The evaluator is
/// built without a default `SERVICE` handler: a federated query would
/// otherwise make the store issue outbound requests to a URL the query names.
fn evaluate<'a>(store: &'a Store, sparql: &str) -> Result<QueryResults<'a>, StoreError> {
    SparqlEvaluator::new()
        .without_default_http_service_handler()
        .parse_query(sparql)
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .on_store(store)
        .execute()
        .map_err(|e| StoreError::Backend(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §3.2: the capability belongs to the implementor. `OxigraphStore`
    /// answers from a constant because the feature is compiled in — and
    /// `Cargo.toml` declares it rather than inheriting it from `rudof_lib`
    /// (§3.3), so the constant is a fact about this crate.
    #[test]
    fn the_embedded_store_holds_rdf_1_2() {
        let store = OxigraphStore::in_memory().unwrap();
        assert_eq!(store.rdf_version(), RdfVersion::Rdf12);
    }

    #[tokio::test]
    async fn update_then_query_triples_roundtrips() {
        let store = OxigraphStore::in_memory().unwrap();
        store.update(
            "INSERT DATA { GRAPH <https://pod.toph.so/foo> { \
             <https://pod.toph.so/foo#it> <http://schema.org/name> \"Toph\" } }",
        ).await.unwrap();

        let triples = store.query_triples(
            "CONSTRUCT { ?s ?p ?o } WHERE { GRAPH <https://pod.toph.so/foo> { ?s ?p ?o } }",
        ).await.unwrap();

        assert_eq!(triples.len(), 1);
        assert_eq!(triples[0].predicate.as_str(), "http://schema.org/name");
    }

    #[tokio::test]
    async fn query_of_absent_graph_is_empty() {
        let store = OxigraphStore::in_memory().unwrap();
        let triples = store.query_triples(
            "CONSTRUCT { ?s ?p ?o } WHERE { GRAPH <https://pod.toph.so/missing> { ?s ?p ?o } }",
        ).await.unwrap();
        assert!(triples.is_empty());
    }

    #[tokio::test]
    async fn ask_reports_true_and_false() {
        let store = OxigraphStore::in_memory().unwrap();
        store.update(
            "INSERT DATA { GRAPH <https://pod.toph.so/foo> { \
             <https://pod.toph.so/foo#it> <http://schema.org/name> \"Toph\" } }",
        ).await.unwrap();

        assert!(store.ask(
            "ASK { GRAPH <https://pod.toph.so/foo> { \
             <https://pod.toph.so/foo#it> <http://schema.org/name> \"Toph\" } }",
        ).await.unwrap());

        assert!(!store.ask(
            "ASK { GRAPH <https://pod.toph.so/foo> { \
             <https://pod.toph.so/foo#it> <http://schema.org/name> \"Nope\" } }",
        ).await.unwrap());
    }

    #[tokio::test]
    async fn query_solutions_returns_one_row_per_mapping() {
        let store = OxigraphStore::in_memory().unwrap();
        store.update(
            "INSERT DATA { GRAPH <https://pod.toph.so/foo> { \
             <https://pod.toph.so/foo#a> <http://schema.org/name> \"one\" . \
             <https://pod.toph.so/foo#b> <http://schema.org/name> \"two\" } }",
        ).await.unwrap();

        let rows = store.query_solutions(
            "SELECT ?s WHERE { GRAPH <https://pod.toph.so/foo> { ?s <http://schema.org/name> ?n } }",
        ).await.unwrap();
        assert_eq!(rows.len(), 2);

        // LIMIT is honoured, which is what makes counting cheap.
        let capped = store.query_solutions(
            "SELECT ?s WHERE { GRAPH <https://pod.toph.so/foo> { ?s <http://schema.org/name> ?n } } LIMIT 1",
        ).await.unwrap();
        assert_eq!(capped.len(), 1);

        // A query of the wrong shape is an error, not an empty answer — the
        // same line `query_triples` and `ask` already draw.
        assert!(store.query_solutions("ASK { ?s ?p ?o }").await.is_err());
    }
}
