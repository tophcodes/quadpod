use crate::{
    dataset::{GroundGraphName, GroundQuad},
    resource::{insert_marked, ResourceError},
    space::{ContainerUrl, GraphName},
    store::SparqlStore,
};
use oxigraph::model::{NamedNode, Triple};

pub const LDP_CONTAINER: &str = "http://www.w3.org/ns/ldp#Container";
pub const LDP_BASIC_CONTAINER: &str = "http://www.w3.org/ns/ldp#BasicContainer";
pub const LDP_CONTAINS: &str = "http://www.w3.org/ns/ldp#contains";
pub const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";

/// True if the client is attempting to set server-managed containment triples.
pub fn body_sets_containment(triples: &[Triple]) -> bool {
    triples.iter().any(|t| t.predicate.as_str() == LDP_CONTAINS)
}

/// `triples` minus the two things this pod adds to a container's stored
/// graph on write: `ldp:contains` (accumulated by [`add_containment`]) and
/// the `rdf:type` pair [`ensure_container`] asserts about `container_iri`,
/// the container's own IRI. What remains is exactly the graph a `PUT`/`POST`
/// into this container was validated against — shape validation runs on the
/// client's own body, before either is added
/// (2026-07-30-shape-validation-design.md §3.4).
///
/// The `rdf:type` pair is filtered only on `container_iri`: `ensure_container`
/// never asserts it about any other subject, so a client-authored `<other> a
/// ldp:Container` — which the write path validated and accepted — must
/// survive here too. `ldp:contains` stays subject-agnostic: a client body
/// carrying it is rejected by `body_sets_containment` before it is ever
/// stored, so no client-authored occurrence reaches this function.
pub fn without_server_managed(triples: Vec<Triple>, container_iri: &str) -> Vec<Triple> {
    triples
        .into_iter()
        .filter(|t| {
            if t.predicate.as_str() == LDP_CONTAINS {
                return false;
            }
            let subject_is_container = matches!(&t.subject,
                oxigraph::model::NamedOrBlankNode::NamedNode(n) if n.as_str() == container_iri);
            if t.predicate.as_str() == RDF_TYPE && subject_is_container {
                if let oxigraph::model::Term::NamedNode(n) = &t.object {
                    if n.as_str() == LDP_CONTAINER || n.as_str() == LDP_BASIC_CONTAINER {
                        return false;
                    }
                }
            }
            true
        })
        .collect()
}

/// A `NamedNode` for an IRI that already passed through `StorageSpace`, or
/// for one of the vocabulary constants above. Both are known-valid; the
/// checked constructor is used anyway so a future caller that is neither
/// cannot smuggle a broken IRI into a SPARQL body.
fn node(iri: &str) -> Result<NamedNode, ResourceError> {
    NamedNode::new(iri).map_err(|_| ResourceError::InvalidIri)
}

/// Create `c` if it is absent, and mark it present either way.
///
/// The type triples go in through `insert_marked` rather than a bare
/// `INSERT DATA`: existence is a stored marker, so content written without
/// one is invisible — the container would read as absent forever, and every
/// "did this ancestor already exist" probe above it would be wrong. It is
/// additive rather than a `put_rdf`, because an existing container's members
/// must survive.
pub async fn ensure_container(
    store: &dyn SparqlStore, c: &ContainerUrl,
) -> Result<(), ResourceError> {
    let iri = node(c.graph_iri())?;
    let rdf_type = node(RDF_TYPE)?;
    let quads = [
        GroundQuad::new(iri.clone(), rdf_type.clone(), node(LDP_CONTAINER)?, GroundGraphName::DefaultGraph),
        GroundQuad::new(iri, rdf_type, node(LDP_BASIC_CONTAINER)?, GroundGraphName::DefaultGraph),
    ];
    insert_marked(store, c, &quads).await
}

/// Record `child_iri` as a member of `parent`. The IRI is a `GraphName`'s at
/// every call site; it is passed as a string because the walk in
/// `wac::guard` records the target at one level and the containers it
/// creates at the next. It goes in through `insert_marked` for the same
/// reason as [`ensure_container`]: this module must not be able to leave
/// content in a graph the store reads as absent.
pub async fn add_containment(
    store: &dyn SparqlStore, parent: &ContainerUrl, child_iri: &str,
) -> Result<(), ResourceError> {
    let p = node(parent.graph_iri())?;
    let quads = [GroundQuad::new(
        p, node(LDP_CONTAINS)?, node(child_iri)?, GroundGraphName::DefaultGraph)];
    insert_marked(store, parent, &quads).await
}

pub async fn remove_containment(
    store: &dyn SparqlStore, parent: &ContainerUrl, child_iri: &str,
) -> Result<(), ResourceError> {
    let p = parent.graph_iri();
    let c = node(child_iri)?;
    store.update(&format!(
        "DELETE DATA {{ GRAPH <{p}> {{ <{p}> <{LDP_CONTAINS}> {c} }} }}",
    )).await?;
    Ok(())
}

pub async fn container_is_empty(
    store: &dyn SparqlStore, c: &ContainerUrl,
) -> Result<bool, ResourceError> {
    let c = c.graph_iri();
    let triples = store.query_triples(&format!(
        "CONSTRUCT {{ <{c}> <{LDP_CONTAINS}> ?x }} \
         WHERE {{ GRAPH <{c}> {{ <{c}> <{LDP_CONTAINS}> ?x }} }}",
    )).await?;
    Ok(triples.is_empty())
}

pub async fn provision_root(
    store: &dyn SparqlStore, root: &ContainerUrl,
) -> Result<(), ResourceError> {
    ensure_container(store, root).await
}

/// Whether a `Link` header asks, per LDP §5.2.3.4, for the created resource to
/// be a container.
///
/// Only the link *target* counts — a container IRI appearing in a parameter
/// value says nothing — and the `rel` is a space-separated token list, so
/// `type` has to be one of its tokens rather than the whole value. Splitting
/// values on `,` is safe for what this reads: a comma inside a quoted
/// parameter can only break a value into pieces that no longer parse as
/// `<iri>; rel=type`, which is a false negative, never a false positive.
pub fn type_link_requests_container(link: &str) -> bool {
    link.split(',').any(|value| {
        let value = value.trim();
        let Some(rest) = value.strip_prefix('<') else { return false };
        let Some((target, params)) = rest.split_once('>') else { return false };
        if target != LDP_CONTAINER && target != LDP_BASIC_CONTAINER {
            return false;
        }
        params.split(';').any(|p| match p.split_once('=') {
            Some((name, v)) if name.trim().eq_ignore_ascii_case("rel") =>
                v.trim().trim_matches('"').split_whitespace().any(|t| t == "type"),
            _ => false,
        })
    })
}

/// Sanitize a client-supplied `Slug` header into a safe child segment.
/// Drops anything outside `[A-Za-z0-9._-]`; falls back to a fresh uuid v4
/// if no slug was given or nothing survives sanitization.
pub fn child_name(slug: Option<&str>) -> String {
    let cleaned: String = slug.unwrap_or("").chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .collect();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        uuid::Uuid::new_v4().to_string()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        resource::exists,
        space::{StorageSpace, Target},
        store::OxigraphStore,
    };

    fn sp() -> StorageSpace { StorageSpace::new("https://pod.toph.so/").unwrap() }

    fn container(path: &str) -> ContainerUrl {
        match sp().resolve(path).unwrap() {
            Target::Container(c) => c,
            _ => panic!("not a container path"),
        }
    }

    fn iri(path: &str) -> String {
        sp().resolve(path).unwrap().graph_iri().to_string()
    }

    /// The `rdf:type` pair is filtered on the container's own subject only —
    /// `ensure_container` never asserts it about any other subject, so a
    /// client-authored type triple on a different subject in the same graph
    /// (`<#x>` here) must survive, exactly as `body_sets_containment` already
    /// keeps `ldp:contains` out of the client's own writes so it can stay
    /// subject-agnostic.
    #[test]
    fn without_server_managed_strips_the_type_pair_only_on_the_containers_own_subject() {
        let c = iri("/notes/");
        let other = format!("{c}#x");
        let subject = |s: &str| NamedNode::new(s).unwrap();
        let triples = vec![
            Triple::new(subject(&c), subject(RDF_TYPE), subject(LDP_CONTAINER)),
            Triple::new(subject(&c), subject(RDF_TYPE), subject(LDP_BASIC_CONTAINER)),
            Triple::new(subject(&other), subject(RDF_TYPE), subject(LDP_CONTAINER)),
        ];
        let out = without_server_managed(triples, &c);
        assert_eq!(out, vec![Triple::new(subject(&other), subject(RDF_TYPE), subject(LDP_CONTAINER))],
            "only the container's own rdf:type pair is server-managed; <#x>'s survives");
    }

    #[tokio::test]
    async fn add_then_remove_containment_toggles_emptiness() {
        let store = OxigraphStore::in_memory().unwrap();
        let c = container("/c/");
        ensure_container(&store, &c).await.unwrap();
        assert!(container_is_empty(&store, &c).await.unwrap());
        add_containment(&store, &c, &iri("/c/x")).await.unwrap();
        assert!(!container_is_empty(&store, &c).await.unwrap());
        remove_containment(&store, &c, &iri("/c/x")).await.unwrap();
        assert!(container_is_empty(&store, &c).await.unwrap());
    }

    // Existence is a stored marker, so a container written without one reads
    // as absent — and the traversal that asks "did this ancestor already
    // exist" would then rebuild and re-link it on every write. Creating a
    // container must mark it, and re-ensuring an existing one must not
    // discard its members.
    #[tokio::test]
    async fn ensure_container_marks_presence_and_keeps_existing_members() {
        let store = OxigraphStore::in_memory().unwrap();
        let c = container("/c/");
        assert!(!exists(&store, &c).await.unwrap());

        ensure_container(&store, &c).await.unwrap();
        assert!(exists(&store, &c).await.unwrap(), "a created container exists");

        add_containment(&store, &c, &iri("/c/x")).await.unwrap();
        ensure_container(&store, &c).await.unwrap();
        assert!(!container_is_empty(&store, &c).await.unwrap(),
            "re-ensuring must not erase members");
    }

    #[tokio::test]
    async fn a_created_container_is_typed() {
        let store = OxigraphStore::in_memory().unwrap();
        let c = container("/a/b/");
        ensure_container(&store, &c).await.unwrap();
        let g = crate::resource::get_rdf(&store, &c).await.unwrap().unwrap();
        assert!(g.iter().any(|t| t.predicate.as_str() == RDF_TYPE
            && matches!(&t.object, oxigraph::model::Term::NamedNode(n)
                if n.as_str() == LDP_BASIC_CONTAINER)));
    }

    #[test]
    fn type_link_recognizes_the_container_types() {
        assert!(type_link_requests_container(
            "<http://www.w3.org/ns/ldp#BasicContainer>; rel=\"type\""));
        assert!(type_link_requests_container(
            "<http://www.w3.org/ns/ldp#Container>; rel=type"));
        // One value among several, and a multi-token rel.
        assert!(type_link_requests_container(
            "<https://example.org/a>; rel=\"describedby\", \
             <http://www.w3.org/ns/ldp#BasicContainer>; rel=\"foo type\""));
    }

    #[test]
    fn type_link_ignores_everything_that_does_not_ask_for_a_container() {
        assert!(!type_link_requests_container(""));
        // rel other than `type`
        assert!(!type_link_requests_container(
            "<http://www.w3.org/ns/ldp#BasicContainer>; rel=\"describedby\""));
        // a type that is not a container
        assert!(!type_link_requests_container(
            "<http://www.w3.org/ns/ldp#Resource>; rel=\"type\""));
        // the IRI must be the link target, not loose text
        assert!(!type_link_requests_container(
            "<https://example.org/x>; rel=\"type\"; title=\"http://www.w3.org/ns/ldp#Container\""));
    }

    #[test]
    fn child_name_rejects_dot_only_slugs() {
        assert_ne!(child_name(Some("..")), "..");
        assert_ne!(child_name(Some(".")), ".");
        assert_eq!(child_name(Some("photo")), "photo");
    }
}
