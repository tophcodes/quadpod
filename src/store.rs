use crate::rdf::RdfVersion;
use oxigraph::model::Triple;
use oxigraph::sparql::{QueryResults, SparqlEvaluator};
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
}

#[async_trait::async_trait]
impl SparqlStore for OxigraphStore {
    async fn update(&self, sparql: &str) -> Result<(), StoreError> {
        self.inner
            .update(sparql)
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn query_triples(&self, sparql: &str) -> Result<Vec<Triple>, StoreError> {
        let results = SparqlEvaluator::new()
            .without_default_http_service_handler()
            .parse_query(sparql)
            .map_err(|e| StoreError::Backend(e.to_string()))?
            .on_store(&self.inner)
            .execute()
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let QueryResults::Graph(triples) = results else {
            return Err(StoreError::Backend("expected CONSTRUCT/graph results".into()));
        };
        triples
            .map(|t| t.map_err(|e| StoreError::Backend(e.to_string())))
            .collect()
    }

    async fn ask(&self, sparql: &str) -> Result<bool, StoreError> {
        let results = SparqlEvaluator::new()
            .without_default_http_service_handler()
            .parse_query(sparql)
            .map_err(|e| StoreError::Backend(e.to_string()))?
            .on_store(&self.inner)
            .execute()
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        match results {
            QueryResults::Boolean(b) => Ok(b),
            _ => Err(StoreError::Backend("expected ASK/boolean results".into())),
        }
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
}
