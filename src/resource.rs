//! Graph-level storage operations.
//!
//! Existence is a **stored fact**, not an inference from triple count: an RDF
//! store cannot distinguish an empty named graph from an absent one, and
//! treating "no triples" as "absent" made an empty ACL mean the opposite of
//! what its author intended (it fell back to the ancestor's rules instead of
//! denying). A presence marker in `urn:pod:sys:<iri>` removes the ambiguity.

use crate::{
    dataset::Skolemized,
    rdf::RdfError,
    shelf::ShelfKey,
    space::{DirectlyDeletable, DirectlyWritable, GraphName, ResourceUrl, SpaceError},
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

/// Predicate asserting that a resource exists. Server-asserted, and therefore
/// in the reserved system namespace rather than the user's graph.
pub const SYS_PRESENT: &str = "urn:pod:sys#present";

/// The system graph holding server-asserted facts about `g`.
pub fn sys_graph_iri(g: &impl GraphName) -> String {
    format!("urn:pod:sys:{}", g.graph_iri())
}

/// Render triples as N-Triples for interpolation into an `INSERT` body.
///
/// Every write path shares this so their escaping cannot diverge: oxrdf's
/// `Display` is what escapes quotes, newlines, control characters, language
/// tags and datatypes, and a second copy of this loop would be the place a
/// future change forgets.
pub(crate) fn serialize_for_insert(triples: &[Triple]) -> String {
    let mut body = String::new();
    for t in triples {
        body.push_str(&format!("{} {} {} .\n", t.subject, t.predicate, t.object));
    }
    body
}

/// §5: replace a resource's whole dataset, and record what it arrived as.
///
/// Takes [`Skolemized`] because the store may never see a blank node, and
/// takes a [`ResourceUrl`] rather than `impl DirectlyWritable` because §3.4
/// keeps containers and auxiliaries off this path: a container's graph carries
/// server-managed containment, and an auxiliary's rules would be invisible to
/// WAC in a subgraph. Auxiliaries keep `aux::put`, whose `FILTER EXISTS` guard
/// has no equivalent here.
// skeleton: the attribute goes when the body lands
#[allow(unused_variables)]
pub async fn put_dataset(
    store: &dyn SparqlStore,
    r: &ResourceUrl,
    dataset: &Skolemized,
    media_type: &str,
) -> Result<(), ResourceError> {
    todo!("skeleton")
}

/// §6 step 2: the resource graph, the registry, and one `CONSTRUCT` per shelf.
/// `query_triples` has no graph field, so a single query cannot recover which
/// shelf a triple came from — 2+N in-process queries, and no fast path that
/// skips the shelves, because the ETag covers the resource rather than the
/// response body.
// skeleton: the attribute goes when the body lands
#[allow(unused_variables)]
pub async fn get_dataset(
    store: &dyn SparqlStore,
    r: &ResourceUrl,
) -> Result<Option<Skolemized>, ResourceError> {
    todo!("skeleton")
}

/// §7: resource graph, every registered shelf, and the system graph.
// skeleton: the attribute goes when the body lands
#[allow(unused_variables)]
pub async fn delete_dataset(
    store: &dyn SparqlStore,
    r: &ResourceUrl,
) -> Result<bool, ResourceError> {
    todo!("skeleton")
}

/// §6.4: what the representation arrived as, for `*/*` and for the
/// `mediaType` LWS requires per container member.
// skeleton: the attribute goes when the body lands
#[allow(unused_variables)]
pub async fn stored_media_type(
    store: &dyn SparqlStore,
    r: &ResourceUrl,
) -> Result<Option<String>, ResourceError> {
    todo!("skeleton")
}

/// §5 step 5: the shelves the registry currently lists, read *before* the
/// write update because `DROP GRAPH` takes a literal IRI and the
/// variable-bound alternative empties a graph without removing it.
// skeleton: the attribute goes when the body lands
#[allow(unused_variables)]
pub async fn registered_shelves(
    store: &dyn SparqlStore,
    r: &ResourceUrl,
) -> Result<Vec<ShelfKey>, ResourceError> {
    todo!("skeleton")
}

/// Replace a graph's contents and mark it present, in one update.
pub async fn put_rdf(
    store: &dyn SparqlStore,
    g: &impl DirectlyWritable,
    triples: &[Triple],
) -> Result<(), ResourceError> {
    let iri = g.graph_iri();
    let sys = sys_graph_iri(g);
    let body = serialize_for_insert(triples);
    store
        .update(&format!(
            "DROP SILENT GRAPH <{iri}>; \
             INSERT DATA {{ GRAPH <{iri}> {{ {body} }} }}; \
             INSERT DATA {{ GRAPH <{sys}> {{ <{iri}> <{SYS_PRESENT}> true }} }}"
        ))
        .await?;
    Ok(())
}

/// Insert triples into a graph without replacing what is there, marking it
/// present in the same update. This is the additive counterpart to
/// [`put_rdf`]: containment and container type triples accumulate rather
/// than replace, but must not be able to produce content without a
/// presence marker.
pub async fn insert_marked(
    store: &dyn SparqlStore,
    g: &impl DirectlyWritable,
    triples: &[Triple],
) -> Result<(), ResourceError> {
    let iri = g.graph_iri();
    let sys = sys_graph_iri(g);
    let body = serialize_for_insert(triples);
    store
        .update(&format!(
            "INSERT DATA {{ GRAPH <{iri}> {{ {body} }} }}; \
             INSERT DATA {{ GRAPH <{sys}> {{ <{iri}> <{SYS_PRESENT}> true }} }}"
        ))
        .await?;
    Ok(())
}

/// A graph's contents, or `None` if it does not exist. An existing graph with
/// no triples yields `Some(vec![])`.
pub async fn get_rdf(
    store: &dyn SparqlStore,
    g: &impl GraphName,
) -> Result<Option<Vec<Triple>>, ResourceError> {
    if !exists(store, g).await? {
        return Ok(None);
    }
    let iri = g.graph_iri();
    let triples = store
        .query_triples(&format!(
            "CONSTRUCT {{ ?s ?p ?o }} WHERE {{ GRAPH <{iri}> {{ ?s ?p ?o }} }}"
        ))
        .await?;
    Ok(Some(triples))
}

/// Whether `g` is present. Reads the stored marker in the system graph
/// rather than counting triples, so an empty-but-present graph still
/// reports `true` and unmarked content still reports `false`.
pub async fn exists(store: &dyn SparqlStore, g: &impl GraphName) -> Result<bool, ResourceError> {
    let iri = g.graph_iri();
    let sys = sys_graph_iri(g);
    Ok(store
        .ask(&format!(
            "ASK {{ GRAPH <{sys}> {{ <{iri}> <{SYS_PRESENT}> true }} }}"
        ))
        .await?)
}

/// Delete a graph and its presence marker. Returns whether it existed.
///
/// The drops run unconditionally — `DROP SILENT` on an absent graph is a
/// no-op — so content that somehow exists without a marker (which should
/// never happen, but `!exists` must not make it permanent) is still
/// reachable and removable.
///
/// The cost of that choice, stated plainly: the marker is read before the
/// drops, so a `put_rdf` landing in between is destroyed while this call
/// still returns `false` and its caller answers 404. That is the same
/// read-then-write race the rest of this non-transactional layer carries,
/// and it has no authorization consequence — but it is a real trade, not a
/// free win.
pub async fn delete_rdf(
    store: &dyn SparqlStore,
    g: &impl DirectlyDeletable,
) -> Result<bool, ResourceError> {
    let existed = exists(store, g).await?;
    let iri = g.graph_iri();
    let sys = sys_graph_iri(g);
    store
        .update(&format!("DROP SILENT GRAPH <{iri}>; DROP SILENT GRAPH <{sys}>"))
        .await?;
    Ok(existed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{rdf, space::{AuxKind, AuxUrl, ResourceUrl, StorageSpace, Target}, store::OxigraphStore};
    use oxigraph::io::RdfFormat;

    fn sp() -> StorageSpace { StorageSpace::new("https://pod.toph.so/").unwrap() }

    fn res(path: &str) -> crate::space::ResourceUrl {
        match sp().resolve(path).unwrap() {
            Target::Resource(r) => r,
            Target::Container(c) => c.as_resource().clone(),
            Target::Aux(_) => panic!("not a resource path"),
        }
    }

    fn triples(turtle: &str, base: &str) -> Vec<Triple> {
        rdf::parse(turtle.as_bytes(), RdfFormat::Turtle, base).unwrap()
    }

    /// An existing subject with an auxiliary written for it. `delete_rdf` is
    /// bounded to auxiliaries — a subject is deleted by `aux::delete_subject`,
    /// which cascades — so the deletion tests below exercise it on one, built
    /// through the only API that can create one.
    async fn subject_with_acl(store: &OxigraphStore, subject: &ResourceUrl, turtle: &str) -> AuxUrl {
        put_rdf(store, subject, &[]).await.unwrap();
        let acl = subject.aux(AuxKind::Acl);
        let t = triples(turtle, acl.graph_iri());
        crate::aux::put(store, &acl, &t).await.unwrap();
        acl
    }

    #[tokio::test]
    async fn put_then_get_roundtrips_triples() {
        let store = OxigraphStore::in_memory().unwrap();
        let foo = res("/foo");
        let t = triples("<#it> <http://schema.org/name> \"Toph\" .", foo.graph_iri());
        put_rdf(&store, &foo, &t).await.unwrap();
        let got = get_rdf(&store, &foo).await.unwrap().expect("exists");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].predicate.as_str(), "http://schema.org/name");
    }

    #[tokio::test]
    async fn put_replaces_not_appends() {
        let store = OxigraphStore::in_memory().unwrap();
        let foo = res("/foo");
        put_rdf(&store, &foo, &triples("<#it> <http://schema.org/name> \"A\" .", foo.graph_iri())).await.unwrap();
        put_rdf(&store, &foo, &triples("<#it> <http://schema.org/name> \"B\" .", foo.graph_iri())).await.unwrap();
        let got = get_rdf(&store, &foo).await.unwrap().unwrap();
        assert_eq!(got.len(), 1);
        assert!(matches!(&got[0].object, oxigraph::model::Term::Literal(l) if l.value() == "B"));
    }

    // The whole point of the presence marker: an empty resource is a resource.
    // Before this, "no triples" and "does not exist" were the same state, which
    // made an empty ACL silently widen access instead of locking a subtree down.
    #[tokio::test]
    async fn an_empty_resource_exists_and_is_distinguishable_from_an_absent_one() {
        let store = OxigraphStore::in_memory().unwrap();
        let empty = res("/empty");
        let absent = res("/absent");

        put_rdf(&store, &empty, &[]).await.unwrap();

        assert!(exists(&store, &empty).await.unwrap());
        assert_eq!(get_rdf(&store, &empty).await.unwrap(), Some(Vec::new()));

        assert!(!exists(&store, &absent).await.unwrap());
        assert_eq!(get_rdf(&store, &absent).await.unwrap(), None);
    }

    #[tokio::test]
    async fn delete_removes_content_and_presence() {
        let store = OxigraphStore::in_memory().unwrap();
        let acl = subject_with_acl(&store, &res("/foo"), "<#it> <http://schema.org/name> \"x\" .").await;

        assert!(delete_rdf(&store, &acl).await.unwrap());
        assert!(!exists(&store, &acl).await.unwrap());
        assert_eq!(get_rdf(&store, &acl).await.unwrap(), None);
        assert!(!delete_rdf(&store, &acl).await.unwrap(), "already gone");
    }

    // An empty graph must be deletable too — otherwise it would be
    // unreachable state: exists, but no way to remove it.
    #[tokio::test]
    async fn an_empty_graph_can_be_deleted() {
        let store = OxigraphStore::in_memory().unwrap();
        let acl = subject_with_acl(&store, &res("/empty"), "").await;
        assert!(exists(&store, &acl).await.unwrap());
        assert!(delete_rdf(&store, &acl).await.unwrap());
        assert!(!exists(&store, &acl).await.unwrap());
    }

    #[tokio::test]
    async fn presence_lives_in_the_system_graph_not_the_user_graph() {
        let store = OxigraphStore::in_memory().unwrap();
        let foo = res("/foo");
        put_rdf(&store, &foo, &triples("<#it> <http://schema.org/name> \"x\" .", foo.graph_iri())).await.unwrap();
        // the user sees exactly what they wrote
        assert_eq!(get_rdf(&store, &foo).await.unwrap().unwrap().len(), 1);
        // and the marker is elsewhere
        assert!(sys_graph_iri(&foo).starts_with("urn:pod:sys:"));
    }

    #[tokio::test]
    async fn insert_marked_accumulates_not_replaces() {
        let store = OxigraphStore::in_memory().unwrap();
        let foo = res("/foo");
        insert_marked(&store, &foo, &triples("<#a> <http://schema.org/name> \"A\" .", foo.graph_iri())).await.unwrap();
        insert_marked(&store, &foo, &triples("<#b> <http://schema.org/name> \"B\" .", foo.graph_iri())).await.unwrap();
        let got = get_rdf(&store, &foo).await.unwrap().unwrap();
        assert_eq!(got.len(), 2, "second insert_marked should add, not replace");
    }

    #[tokio::test]
    async fn insert_marked_writes_a_presence_marker() {
        let store = OxigraphStore::in_memory().unwrap();
        let foo = res("/foo");
        insert_marked(&store, &foo, &triples("<#it> <http://schema.org/name> \"x\" .", foo.graph_iri())).await.unwrap();
        assert!(exists(&store, &foo).await.unwrap());
        // A resource is removed by the cascade, not by `delete_rdf`.
        assert!(crate::aux::delete_subject(&store, &foo).await.unwrap());
        assert!(!exists(&store, &foo).await.unwrap());
    }

    // This state is not supposed to occur — every writer in this module goes
    // through put_rdf/insert_marked, both of which write the marker in the
    // same update as the content. This test pins the fail-closed answer in
    // case it ever does: content with no marker reads as absent rather than
    // being exposed.
    #[tokio::test]
    async fn triples_without_a_marker_read_as_absent_but_are_still_deletable() {
        let store = OxigraphStore::in_memory().unwrap();
        let acl = res("/foo").aux(AuxKind::Acl);
        let iri = acl.graph_iri();
        store
            .update(&format!(
                "INSERT DATA {{ GRAPH <{iri}> {{ <{iri}> <http://schema.org/name> \"x\" }} }}"
            ))
            .await
            .unwrap();

        assert!(!exists(&store, &acl).await.unwrap(), "unmarked content must read as absent");
        assert_eq!(get_rdf(&store, &acl).await.unwrap(), None);

        // delete_rdf is unconditional, so orphaned content is still removable
        // even though `existed` reports false.
        assert!(!delete_rdf(&store, &acl).await.unwrap());
        let remaining = store
            .query_triples(&format!(
                "CONSTRUCT {{ ?s ?p ?o }} WHERE {{ GRAPH <{iri}> {{ ?s ?p ?o }} }}"
            ))
            .await
            .unwrap();
        assert!(remaining.is_empty(), "delete_rdf should remove unmarked content too");
    }

    // The ASK is scoped to `GRAPH <urn:pod:sys:{iri}>`, which is what stops a
    // user from forging someone else's presence by writing the marker
    // triple into their own graph instead of the system graph.
    #[tokio::test]
    async fn presence_cannot_be_forged_via_the_user_graph() {
        let store = OxigraphStore::in_memory().unwrap();
        let mine = res("/mine");
        let other = res("/other");
        let forged = triples(
            &format!("<{}> <{SYS_PRESENT}> true .", other.graph_iri()),
            mine.graph_iri(),
        );
        put_rdf(&store, &mine, &forged).await.unwrap();
        assert!(!exists(&store, &other).await.unwrap());
    }
}
