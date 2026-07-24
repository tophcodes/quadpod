use crate::{
    space::StorageSpace,
    store::{SparqlStore, StoreError},
};
use oxigraph::io::{RdfFormat, RdfParser};
use oxigraph::model::Triple;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ResourceError {
    #[error("turtle parse error: {0}")]
    Parse(String),
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Parse Turtle (resolved against `base_iri`) into a `\n`-separated block of
/// N-Triples-syntax triples, suitable for embedding inside `INSERT DATA { GRAPH <g> { ... } }`.
fn turtle_to_ntriples(turtle: &str, base_iri: &str) -> Result<String, ResourceError> {
    let parser = RdfParser::from_format(RdfFormat::Turtle)
        .with_base_iri(base_iri)
        .map_err(|e| ResourceError::Parse(e.to_string()))?;

    let mut out = String::new();
    for quad in parser.for_slice(turtle) {
        let quad = quad.map_err(|e| ResourceError::Parse(e.to_string()))?;
        let triple = Triple {
            subject: quad.subject,
            predicate: quad.predicate,
            object: quad.object,
        };
        out.push_str(&triple.to_string());
        out.push_str(" .\n");
    }
    Ok(out)
}

pub async fn put_rdf<S: SparqlStore>(
    store: &S,
    space: &StorageSpace,
    request_path: &str,
    turtle: &str,
) -> Result<(), ResourceError> {
    let g = space.graph_iri(request_path);
    let triples = turtle_to_ntriples(turtle, &g)?;
    let update =
        format!("DROP SILENT GRAPH <{g}>; INSERT DATA {{ GRAPH <{g}> {{ {triples} }} }}");
    store.update(&update).await?;
    Ok(())
}

pub async fn get_rdf<S: SparqlStore>(
    store: &S,
    space: &StorageSpace,
    request_path: &str,
) -> Result<Option<String>, ResourceError> {
    let g = space.graph_iri(request_path);
    let q = format!("CONSTRUCT {{ ?s ?p ?o }} WHERE {{ GRAPH <{g}> {{ ?s ?p ?o }} }}");
    let ttl = store.query_construct(&q).await?;
    if ttl.trim().is_empty() {
        Ok(None)
    } else {
        Ok(Some(ttl))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{space::StorageSpace, store::OxigraphStore};

    fn space() -> StorageSpace {
        StorageSpace::new("https://pod.toph.so/").unwrap()
    }

    #[tokio::test]
    async fn put_then_get_preserves_triples() {
        let store = OxigraphStore::in_memory().unwrap();
        let sp = space();
        let ttl = "<#it> <http://schema.org/name> \"Toph\" .";
        put_rdf(&store, &sp, "/foo", ttl).await.unwrap();

        let got = get_rdf(&store, &sp, "/foo").await.unwrap().expect("exists");
        assert!(got.contains("schema.org/name"));
        assert!(got.contains("Toph"));
    }

    #[tokio::test]
    async fn put_replaces_not_appends() {
        let store = OxigraphStore::in_memory().unwrap();
        let sp = space();
        put_rdf(&store, &sp, "/foo", "<#it> <http://schema.org/name> \"A\" .")
            .await
            .unwrap();
        put_rdf(&store, &sp, "/foo", "<#it> <http://schema.org/name> \"B\" .")
            .await
            .unwrap();
        let got = get_rdf(&store, &sp, "/foo").await.unwrap().unwrap();
        assert!(got.contains("\"B\""));
        assert!(!got.contains("\"A\""));
    }

    #[tokio::test]
    async fn get_absent_resource_is_none() {
        let store = OxigraphStore::in_memory().unwrap();
        assert!(get_rdf(&store, &space(), "/nope").await.unwrap().is_none());
    }
}
