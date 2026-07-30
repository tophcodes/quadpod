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

    async fn query_solutions(&self, sparql: &str) -> Result<Vec<QuerySolution>, StoreError> {
        let results = SparqlEvaluator::new()
            .without_default_http_service_handler()
            .parse_query(sparql)
            .map_err(|e| StoreError::Backend(e.to_string()))?
            .on_store(&self.inner)
            .execute()
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let QueryResults::Solutions(solutions) = results else {
            return Err(StoreError::Backend("expected SELECT/solution results".into()));
        };
        solutions
            .map(|s| s.map_err(|e| StoreError::Backend(e.to_string())))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
