use crate::{resource::ResourceError, space::StorageSpace, store::SparqlStore};
use oxigraph::model::Triple;

pub const LDP_CONTAINER: &str = "http://www.w3.org/ns/ldp#Container";
pub const LDP_BASIC_CONTAINER: &str = "http://www.w3.org/ns/ldp#BasicContainer";
pub const LDP_CONTAINS: &str = "http://www.w3.org/ns/ldp#contains";
pub const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";

pub fn is_container_path(request_path: &str) -> bool {
    request_path.ends_with('/')
}

/// True if the client is attempting to set server-managed containment triples.
pub fn body_sets_containment(triples: &[Triple]) -> bool {
    triples.iter().any(|t| t.predicate.as_str() == LDP_CONTAINS)
}

/// Parent container path (always trailing-slash), or None for the root "/".
pub fn parent_container(request_path: &str) -> Option<String> {
    if request_path == "/" {
        return None;
    }
    let trimmed = request_path.strip_suffix('/').unwrap_or(request_path);
    match trimmed.rfind('/') {
        Some(idx) => Some(trimmed[..=idx].to_string()),
        None => Some("/".to_string()),
    }
}

pub async fn ensure_container(
    store: &dyn SparqlStore, space: &StorageSpace, path: &str,
) -> Result<(), ResourceError> {
    let c = space.graph_iri(path)?;
    let update = format!(
        "INSERT DATA {{ GRAPH <{c}> {{ \
         <{c}> <{RDF_TYPE}> <{LDP_CONTAINER}> . \
         <{c}> <{RDF_TYPE}> <{LDP_BASIC_CONTAINER}> }} }}",
    );
    store.update(&update).await?;
    Ok(())
}

pub async fn add_containment(
    store: &dyn SparqlStore, space: &StorageSpace, parent: &str, child: &str,
) -> Result<(), ResourceError> {
    let p = space.graph_iri(parent)?;
    let c = space.graph_iri(child)?;
    store.update(&format!(
        "INSERT DATA {{ GRAPH <{p}> {{ <{p}> <{LDP_CONTAINS}> <{c}> }} }}",
    )).await?;
    Ok(())
}

pub async fn remove_containment(
    store: &dyn SparqlStore, space: &StorageSpace, parent: &str, child: &str,
) -> Result<(), ResourceError> {
    let p = space.graph_iri(parent)?;
    let c = space.graph_iri(child)?;
    store.update(&format!(
        "DELETE DATA {{ GRAPH <{p}> {{ <{p}> <{LDP_CONTAINS}> <{c}> }} }}",
    )).await?;
    Ok(())
}

pub async fn container_is_empty(
    store: &dyn SparqlStore, space: &StorageSpace, path: &str,
) -> Result<bool, ResourceError> {
    let c = space.graph_iri(path)?;
    let triples = store.query_triples(&format!(
        "CONSTRUCT {{ <{c}> <{LDP_CONTAINS}> ?x }} \
         WHERE {{ GRAPH <{c}> {{ <{c}> <{LDP_CONTAINS}> ?x }} }}",
    )).await?;
    Ok(triples.is_empty())
}

pub async fn ensure_ancestors(
    store: &dyn SparqlStore, space: &StorageSpace, request_path: &str,
) -> Result<(), ResourceError> {
    let mut child = request_path.to_string();
    while let Some(parent) = parent_container(&child) {
        ensure_container(store, space, &parent).await?;
        add_containment(store, space, &parent, &child).await?;
        child = parent;
    }
    Ok(())
}

pub async fn provision_root(
    store: &dyn SparqlStore, space: &StorageSpace,
) -> Result<(), ResourceError> {
    ensure_container(store, space, "/").await
}

/// Sanitize a client-supplied `Slug` header into a safe child segment.
/// Drops anything outside `[A-Za-z0-9._-]`; falls back to a fresh uuid v4
/// if no slug was given or nothing survives sanitization.
pub fn child_name(slug: Option<&str>) -> String {
    let cleaned: String = slug.unwrap_or("").chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .collect();
    if cleaned.is_empty() { uuid::Uuid::new_v4().to_string() } else { cleaned }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{space::StorageSpace, store::OxigraphStore};

    fn sp() -> StorageSpace { StorageSpace::new("https://pod.toph.so/").unwrap() }

    #[tokio::test]
    async fn ensure_ancestors_creates_chain_and_links() {
        let store = OxigraphStore::in_memory().unwrap();
        let space = sp();
        ensure_ancestors(&store, &space, "/a/b/c").await.unwrap();

        // /a/b/ contains /a/b/c
        assert!(!container_is_empty(&store, &space, "/a/b/").await.unwrap());
        // /a/ contains /a/b/
        assert!(!container_is_empty(&store, &space, "/a/").await.unwrap());
        // root contains /a/
        assert!(!container_is_empty(&store, &space, "/").await.unwrap());
        // /a/b/ is typed as a container (its graph is non-empty with type triples)
        let g = crate::resource::get_rdf(&store, &space, "/a/b/").await.unwrap().unwrap();
        assert!(g.iter().any(|t| t.predicate.as_str() == RDF_TYPE
            && matches!(&t.object, oxigraph::model::Term::NamedNode(n) if n.as_str() == LDP_BASIC_CONTAINER)));
    }

    #[tokio::test]
    async fn add_then_remove_containment_toggles_emptiness() {
        let store = OxigraphStore::in_memory().unwrap();
        let space = sp();
        ensure_container(&store, &space, "/c/").await.unwrap();
        assert!(container_is_empty(&store, &space, "/c/").await.unwrap());
        add_containment(&store, &space, "/c/", "/c/x").await.unwrap();
        assert!(!container_is_empty(&store, &space, "/c/").await.unwrap());
        remove_containment(&store, &space, "/c/", "/c/x").await.unwrap();
        assert!(container_is_empty(&store, &space, "/c/").await.unwrap());
    }

    #[test]
    fn container_paths_end_with_slash() {
        assert!(is_container_path("/foo/"));
        assert!(is_container_path("/"));
        assert!(!is_container_path("/foo"));
        assert!(!is_container_path("/a/b"));
    }

    #[test]
    fn parent_of_resource_and_container() {
        assert_eq!(parent_container("/a/b/c").as_deref(), Some("/a/b/"));
        assert_eq!(parent_container("/a/b/").as_deref(), Some("/a/"));
        assert_eq!(parent_container("/foo").as_deref(), Some("/"));
        assert_eq!(parent_container("/foo/").as_deref(), Some("/"));
        assert_eq!(parent_container("/"), None);
    }
}
