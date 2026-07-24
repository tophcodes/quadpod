use oxigraph::io::{RdfFormat, RdfSerializer};
use oxigraph::sparql::{QueryResults, SparqlEvaluator};
use oxigraph::store::Store;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("store backend error: {0}")]
    Backend(String),
}

pub trait SparqlStore: Send + Sync {
    fn update(
        &self,
        sparql: &str,
    ) -> impl std::future::Future<Output = Result<(), StoreError>> + Send;
    fn query_construct(
        &self,
        sparql: &str,
    ) -> impl std::future::Future<Output = Result<String, StoreError>> + Send;
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

impl SparqlStore for OxigraphStore {
    async fn update(&self, sparql: &str) -> Result<(), StoreError> {
        self.inner
            .update(sparql)
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn query_construct(&self, sparql: &str) -> Result<String, StoreError> {
        let results = SparqlEvaluator::new()
            .parse_query(sparql)
            .map_err(|e| StoreError::Backend(e.to_string()))?
            .on_store(&self.inner)
            .execute()
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let QueryResults::Graph(triples) = results else {
            return Err(StoreError::Backend("expected CONSTRUCT/graph results".into()));
        };

        let mut serializer = RdfSerializer::from_format(RdfFormat::Turtle).for_writer(Vec::new());
        for triple in triples {
            let triple = triple.map_err(|e| StoreError::Backend(e.to_string()))?;
            serializer
                .serialize_triple(&triple)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
        }
        let buf = serializer
            .finish()
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        String::from_utf8(buf).map_err(|e| StoreError::Backend(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn update_then_construct_roundtrips_a_triple() {
        let store = OxigraphStore::in_memory().unwrap();
        store
            .update(
                "INSERT DATA { GRAPH <https://pod.toph.so/foo> { \
                 <https://pod.toph.so/foo#it> <http://schema.org/name> \"Toph\" } }",
            )
            .await
            .unwrap();

        let ttl = store
            .query_construct(
                "CONSTRUCT { ?s ?p ?o } WHERE { GRAPH <https://pod.toph.so/foo> { ?s ?p ?o } }",
            )
            .await
            .unwrap();

        assert!(ttl.contains("schema.org/name"));
        assert!(ttl.contains("Toph"));
    }

    #[tokio::test]
    async fn construct_of_absent_graph_is_empty() {
        let store = OxigraphStore::in_memory().unwrap();
        let ttl = store
            .query_construct(
                "CONSTRUCT { ?s ?p ?o } WHERE { GRAPH <https://pod.toph.so/missing> { ?s ?p ?o } }",
            )
            .await
            .unwrap();
        assert!(!ttl.contains("schema.org"));
    }
}
