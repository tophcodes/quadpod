//! The WAC policy retrieval point: find the ACL that governs a resource.
//!
//! The ACL for `<res>` lives in the named graph `<res>.acl` (design spec §5).
//! If that graph does not exist, WAC inheritance applies: walk up the
//! container hierarchy and use the first `.acl` found there, evaluated
//! through `acl:default`. The first ACL found wins completely — ancestor
//! rules are never merged in.

use oxigraph::model::Triple;

use crate::{
    container::parent_container,
    resource::{get_rdf, ResourceError},
    space::StorageSpace,
    store::SparqlStore,
};

/// The ACL that governs a resource, plus the context needed to evaluate it.
#[derive(Debug)]
pub struct EffectiveAcl {
    /// The ACL graph's triples.
    pub triples: Vec<Triple>,
    /// IRI of the resource this ACL document belongs to — the object that
    /// `acl:accessTo`/`acl:default` must name for an authorization to apply.
    pub governed_iri: String,
    /// True when this ACL was reached by walking up to a container, i.e.
    /// authorizations apply through `acl:default` rather than `acl:accessTo`.
    pub inherited: bool,
}

const ACL_SUFFIX: &str = ".acl";

/// The request path of the ACL governing `request_path`.
pub fn acl_path(request_path: &str) -> String {
    format!("{request_path}{ACL_SUFFIX}")
}

/// True if `request_path` addresses an ACL resource.
pub fn is_acl_path(request_path: &str) -> bool {
    request_path.ends_with(ACL_SUFFIX)
}

/// Inverse of [`acl_path`]: the resource an ACL path governs. Returns the
/// input unchanged if it is not an ACL path.
pub fn acl_subject_path(acl_request_path: &str) -> String {
    acl_request_path
        .strip_suffix(ACL_SUFFIX)
        .unwrap_or(acl_request_path)
        .to_string()
}

/// Resolve the ACL governing `request_path`: the resource's own `.acl` if it
/// exists, else the nearest ancestor container's, else `None` (which the
/// guard turns into a denial — WAC has no implicit grant).
pub async fn effective_acl(
    store: &dyn SparqlStore,
    space: &StorageSpace,
    request_path: &str,
) -> Result<Option<EffectiveAcl>, ResourceError> {
    if let Some(triples) = get_rdf(store, space, &acl_path(request_path)).await? {
        return Ok(Some(EffectiveAcl {
            triples,
            governed_iri: space.graph_iri(request_path)?,
            inherited: false,
        }));
    }
    let mut current = request_path.to_string();
    while let Some(parent) = parent_container(&current) {
        if let Some(triples) = get_rdf(store, space, &acl_path(&parent)).await? {
            return Ok(Some(EffectiveAcl {
                triples,
                governed_iri: space.graph_iri(&parent)?,
                inherited: true,
            }));
        }
        current = parent;
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wac::pdp::{ACL_ACCESS_TO, ACL_AGENT, ACL_DEFAULT, ACL_MODE, ACL_READ};
    use crate::{rdf, resource::put_rdf, store::OxigraphStore};
    use oxigraph::io::RdfFormat;

    const ALICE: &str = "https://alice.example/card#me";

    fn sp() -> StorageSpace { StorageSpace::new("https://pod.toph.so/").unwrap() }

    async fn write_acl(store: &OxigraphStore, path: &str, turtle: &str) {
        let base = sp().graph_iri(path).unwrap();
        let t = rdf::parse(turtle.as_bytes(), RdfFormat::Turtle, &base).unwrap();
        put_rdf(store, &sp(), path, &t).await.unwrap();
    }

    #[test]
    fn acl_path_appends_dot_acl() {
        assert_eq!(acl_path("/foo"), "/foo.acl");
        assert_eq!(acl_path("/box/"), "/box/.acl");
        assert_eq!(acl_path("/"), "/.acl");
    }

    #[test]
    fn acl_subject_path_is_the_inverse() {
        assert_eq!(acl_subject_path("/foo.acl"), "/foo");
        assert_eq!(acl_subject_path("/box/.acl"), "/box/");
        assert_eq!(acl_subject_path("/.acl"), "/");
    }

    #[test]
    fn is_acl_path_only_matches_the_suffix() {
        assert!(is_acl_path("/foo.acl"));
        assert!(is_acl_path("/.acl"));
        assert!(!is_acl_path("/foo"));
        assert!(!is_acl_path("/acl"));
        assert!(!is_acl_path("/x.acl/")); // a container that merely looks like one
    }

    #[tokio::test]
    async fn direct_acl_is_found_and_not_marked_inherited() {
        let store = OxigraphStore::in_memory().unwrap();
        write_acl(&store, "/foo.acl", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/foo> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        let acl = effective_acl(&store, &sp(), "/foo").await.unwrap().expect("found");
        assert!(!acl.inherited);
        assert_eq!(acl.governed_iri, "https://pod.toph.so/foo");
        assert!(!acl.triples.is_empty(), "triples must be populated");
        assert!(acl.triples.iter().any(|t| t.predicate.as_str() == ACL_MODE),
            "triples must contain ACL_MODE");
    }

    #[tokio::test]
    async fn missing_direct_acl_inherits_from_the_nearest_container() {
        let store = OxigraphStore::in_memory().unwrap();
        write_acl(&store, "/box/.acl", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_DEFAULT}> <https://pod.toph.so/box/> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        let acl = effective_acl(&store, &sp(), "/box/item").await.unwrap().expect("found");
        assert!(acl.inherited);
        assert_eq!(acl.governed_iri, "https://pod.toph.so/box/");
    }

    #[tokio::test]
    async fn walk_ascends_all_the_way_to_the_root_acl() {
        let store = OxigraphStore::in_memory().unwrap();
        write_acl(&store, "/.acl", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_DEFAULT}> <https://pod.toph.so/> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        let acl = effective_acl(&store, &sp(), "/a/b/c").await.unwrap().expect("found");
        assert!(acl.inherited);
        assert_eq!(acl.governed_iri, "https://pod.toph.so/");
    }

    // WAC: the nearest ACL wins COMPLETELY. An ancestor's rules must not be
    // merged in — otherwise revoking access on a subtree would be impossible.
    #[tokio::test]
    async fn nearest_acl_wins_entirely_over_ancestors() {
        let store = OxigraphStore::in_memory().unwrap();
        write_acl(&store, "/.acl", &format!(
            "<#root> <{ACL_AGENT}> <{ALICE}> ; <{ACL_DEFAULT}> <https://pod.toph.so/> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        write_acl(&store, "/box/.acl", &format!(
            "<#box> <{ACL_AGENT}> <https://bob.example/card#me> ; \
             <{ACL_DEFAULT}> <https://pod.toph.so/box/> ; <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        let acl = effective_acl(&store, &sp(), "/box/item").await.unwrap().expect("found");
        assert_eq!(acl.governed_iri, "https://pod.toph.so/box/");
        assert!(!acl.triples.iter().any(|t| matches!(&t.object,
            oxigraph::model::Term::NamedNode(n) if n.as_str() == ALICE)),
            "root rules must not be merged into the nearer ACL");
    }

    #[tokio::test]
    async fn no_acl_anywhere_is_none() {
        let store = OxigraphStore::in_memory().unwrap();
        assert!(effective_acl(&store, &sp(), "/foo").await.unwrap().is_none());
    }

    // An ACL for a resource must not be shadowed by that resource's own
    // graph: /foo.acl is looked up as a graph, /foo is never consulted.
    #[tokio::test]
    async fn resource_data_is_not_mistaken_for_its_acl() {
        let store = OxigraphStore::in_memory().unwrap();
        write_acl(&store, "/foo", "<#it> <http://schema.org/name> \"Toph\" .").await;
        assert!(effective_acl(&store, &sp(), "/foo").await.unwrap().is_none());
    }

    // A container's own ACL must be governed by the container IRI WITH its
    // trailing slash — `decide` compares that string exactly, so normalizing
    // it away here would silently deny everything under the container.
    #[tokio::test]
    async fn direct_container_acl_keeps_the_trailing_slash() {
        let store = OxigraphStore::in_memory().unwrap();
        write_acl(&store, "/box/.acl", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/box/> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        let acl = effective_acl(&store, &sp(), "/box/").await.unwrap().expect("found");
        assert!(!acl.inherited);
        assert_eq!(acl.governed_iri, "https://pod.toph.so/box/");
    }
}
