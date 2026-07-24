use crate::{
    rdf::RdfError,
    space::{SpaceError, StorageSpace},
    store::{SparqlStore, StoreError},
};
use oxigraph::model::Triple;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ResourceError {
    #[error("invalid resource IRI")]
    InvalidIri,
    #[error(transparent)]
    Rdf(#[from] RdfError),
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<SpaceError> for ResourceError {
    fn from(_: SpaceError) -> Self {
        ResourceError::InvalidIri
    }
}

pub async fn put_rdf(
    store: &dyn SparqlStore,
    space: &StorageSpace,
    request_path: &str,
    triples: &[Triple],
) -> Result<(), ResourceError> {
    let g = space.graph_iri(request_path)?;
    let mut body = String::new();
    for t in triples {
        body.push_str(&format!("{} {} {} .\n", t.subject, t.predicate, t.object));
    }
    let update = format!("DROP SILENT GRAPH <{g}>; INSERT DATA {{ GRAPH <{g}> {{ {body} }} }}");
    store.update(&update).await?;
    Ok(())
}

pub async fn get_rdf(
    store: &dyn SparqlStore,
    space: &StorageSpace,
    request_path: &str,
) -> Result<Option<Vec<Triple>>, ResourceError> {
    let g = space.graph_iri(request_path)?;
    let q = format!("CONSTRUCT {{ ?s ?p ?o }} WHERE {{ GRAPH <{g}> {{ ?s ?p ?o }} }}");
    let triples = store.query_triples(&q).await?;
    if triples.is_empty() {
        Ok(None)
    } else {
        Ok(Some(triples))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{rdf, space::StorageSpace, store::OxigraphStore};
    use oxigraph::io::RdfFormat;

    fn space() -> StorageSpace {
        StorageSpace::new("https://pod.toph.so/").unwrap()
    }

    #[tokio::test]
    async fn put_then_get_roundtrips_triples() {
        let store = OxigraphStore::in_memory().unwrap();
        let t = rdf::parse(
            b"<#it> <http://schema.org/name> \"Toph\" .",
            RdfFormat::Turtle,
            "https://pod.toph.so/foo",
        )
        .unwrap();
        put_rdf(&store, &space(), "/foo", &t).await.unwrap();
        let got = get_rdf(&store, &space(), "/foo").await.unwrap().expect("exists");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].predicate.as_str(), "http://schema.org/name");
    }

    #[tokio::test]
    async fn put_replaces_not_appends() {
        let store = OxigraphStore::in_memory().unwrap();
        let a = rdf::parse(
            b"<#it> <http://schema.org/name> \"A\" .",
            RdfFormat::Turtle,
            "https://pod.toph.so/foo",
        )
        .unwrap();
        let b = rdf::parse(
            b"<#it> <http://schema.org/name> \"B\" .",
            RdfFormat::Turtle,
            "https://pod.toph.so/foo",
        )
        .unwrap();
        put_rdf(&store, &space(), "/foo", &a).await.unwrap();
        put_rdf(&store, &space(), "/foo", &b).await.unwrap();
        let got = get_rdf(&store, &space(), "/foo").await.unwrap().unwrap();
        assert_eq!(got.len(), 1);
        assert!(matches!(&got[0].object, oxigraph::model::Term::Literal(l) if l.value() == "B"));
    }

    #[tokio::test]
    async fn get_absent_is_none() {
        let store = OxigraphStore::in_memory().unwrap();
        assert!(get_rdf(&store, &space(), "/nope").await.unwrap().is_none());
    }
}
