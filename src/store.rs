use oxigraph::model::Triple;
use oxigraph::sparql::{QueryResults, SparqlEvaluator};
use oxigraph::store::Store;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("store backend error: {0}")]
    Backend(String),
}

#[async_trait::async_trait]
pub trait SparqlStore: Send + Sync {
    async fn update(&self, sparql: &str) -> Result<(), StoreError>;
    async fn query_triples(&self, sparql: &str) -> Result<Vec<Triple>, StoreError>;
    async fn ask(&self, sparql: &str) -> Result<bool, StoreError>;
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
}
