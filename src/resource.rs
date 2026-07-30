//! Graph-level storage operations.
//!
//! Existence is a **stored fact**, not an inference from triple count: an RDF
//! store cannot distinguish an empty named graph from an absent one, and
//! treating "no triples" as "absent" made an empty ACL mean the opposite of
//! what its author intended (it fell back to the ancestor's rules instead of
//! denying). A presence marker in `urn:quadpod:sys:<iri>` removes the ambiguity.

use crate::{
    container::RDF_TYPE,
    dataset::{Dataset, GroundGraphName, GroundQuad, Skolemized},
    rdf::{Format, RdfError},
    shelf::{ShelfKey, SYS_GRAPH_NAME, SYS_HAS_SUBGRAPH, SYS_MEDIA_TYPE},
    space::{DirectlyDeletable, DirectlyWritable, GraphName, ResourceUrl, SpaceError},
    sparql,
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
    #[error(transparent)]
    Blob(#[from] crate::blob::BlobError),
    #[error("the storage key for this URL is too long")]
    KeyTooLong,
    #[error("a binary resource has no stored media type")]
    BinaryWithoutMediaType,
}

impl From<SpaceError> for ResourceError {
    fn from(_: SpaceError) -> Self {
        ResourceError::InvalidIri
    }
}

/// Predicate asserting that a resource exists. Server-asserted, and therefore
/// in the reserved system namespace rather than the user's graph.
pub const SYS_PRESENT: &str = "urn:quadpod:sys#present";

/// Marks a resource whose representation is bytes rather than triples.
///
/// Stored rather than inferred from the media type: inferring it would make
/// every blob stored under a type `Format` later learns re-interpret as an
/// empty RDF resource, and `application/rdf+xml` is already on the follow-up
/// list (`2026-07-28-jsonld-datasets-design.md` §11).
pub const SYS_BINARY_RESOURCE: &str = "urn:quadpod:sys#BinaryResource";

/// What a resource's representation is made of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    Rdf,
    Binary(crate::rdf::MediaType),
}

/// The system graph holding server-asserted facts about `g`.
pub fn sys_graph_iri(g: &impl GraphName) -> String {
    format!("urn:quadpod:sys:{}", g.graph_iri())
}

/// Render a ground dataset's triples as N-Triples for interpolation into an
/// `INSERT` body, ignoring graph name.
///
/// Every write path shares this so their escaping cannot diverge: oxrdf's
/// `Display` is what escapes quotes, newlines, control characters, language
/// tags and datatypes, and a second copy of this loop would be the place a
/// future change forgets. Taking [`Skolemized`] rather than `&[Triple]` is
/// what makes "no blank node in the store" (§4) a property of the argument
/// type at every write path, rather than a claim each caller upholds on its
/// own.
pub(crate) fn serialize_for_insert(quads: &Skolemized) -> String {
    let mut body = String::new();
    for q in quads.quads() {
        body.push_str(&format!("{} {} {} .\n", q.subject, q.predicate, q.object));
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
///
/// Like [`delete_rdf`], this reads the registry (`registered_shelves`, below)
/// before it writes. A concurrent write to the same resource landing in that
/// window can leave orphaned or under-dropped shelves — the same
/// read-then-write race, accepted for the same reason: single-user v1, and
/// `DROP GRAPH` takes no variable, so the read cannot be folded into the
/// update (design spec §5.1).
///
/// One of the two teardown sites (§7): a blob this resource held is
/// superseded by this write. The object is deleted **after** the SPARQL
/// update commits, matching [`aux::delete_subject`](crate::aux::delete_subject):
/// an interrupted delete leaves an object no marker points at, which the next
/// write to the same URL overwrites, whereas the reverse order would leave a
/// resource marked `BinaryResource` with no object behind it — `GET` then
/// answers `404` and blames a backend that did nothing wrong.
pub async fn put_dataset(
    store: &dyn SparqlStore,
    blobs: &dyn crate::blob::BlobStore,
    r: &ResourceUrl,
    dataset: &Skolemized,
    media_type: Format,
) -> Result<(), ResourceError> {
    use oxigraph::model::NamedNode;
    let iri = r.graph_iri();
    let sys = sys_graph_iri(r);

    // Split by graph name; the key is minted only here, from the pair. Each
    // bucket is re-wrapped as default-graph quads because serialize_for_insert
    // only reads subject/predicate/object — the GRAPH <...> wrapper below
    // supplies the graph context.
    let mut default_graph: Vec<GroundQuad> = Vec::new();
    let mut shelves: Vec<(ShelfKey, String, Vec<GroundQuad>)> = Vec::new();
    for q in dataset.quads() {
        let t = GroundQuad::new(
            q.subject.clone(), q.predicate.clone(), q.object.clone(),
            GroundGraphName::DefaultGraph,
        );
        match &q.graph_name {
            GroundGraphName::DefaultGraph => default_graph.push(t),
            GroundGraphName::NamedNode(n) => {
                let key = ShelfKey::of(r, n.as_ref());
                match shelves.iter_mut().find(|(k, _, _)| k == &key) {
                    Some((_, _, ts)) => ts.push(t),
                    None => shelves.push((key, n.as_str().to_owned(), vec![t])),
                }
            }
        }
    }

    // Both drops (§3.2 invariant 4): what the registry lists, and what we are
    // about to write. Literal IRIs — DROP takes no variable, and DELETE WHERE
    // empties a graph without removing it.
    let mut update = String::new();
    for key in registered_shelves(store, r).await? {
        update.push_str(&format!("DROP SILENT GRAPH <{}>; ", key.graph_iri()));
    }
    for (key, _, _) in &shelves {
        update.push_str(&format!("DROP SILENT GRAPH <{}>; ", key.graph_iri()));
    }
    update.push_str(&format!("DROP SILENT GRAPH <{iri}>; DROP SILENT GRAPH <{sys}>; "));

    // One INSERT DATA holding every graph: §5's replacement is one operation,
    // not one per shelf.
    update.push_str("INSERT DATA { ");
    let default_ground = Skolemized::new(default_graph);
    update.push_str(&format!("GRAPH <{iri}> {{ {} }} ", serialize_for_insert(&default_ground)));
    for (key, _, ts) in &shelves {
        let ground = Skolemized::new(ts.clone());
        update.push_str(&format!("GRAPH <{}> {{ {} }} ", key.graph_iri(), serialize_for_insert(&ground)));
    }
    update.push_str("}; ");

    let mt = sparql::Literal::new(&oxigraph::model::Literal::new_simple_literal(
        media_type.media_type(),
    ));
    let mut registry = format!(
        "<{iri}> <{SYS_PRESENT}> true . <{iri}> <{SYS_MEDIA_TYPE}> {mt} . "
    );
    for (key, name, _) in &shelves {
        // §3.6: `space::GraphName` is sealed so only server-minted types may
        // normally reach an interpolation site; a client-supplied graph name
        // is the one exception, and it has been safe so far only because
        // oxigraph's own parsers reject anything that could break out of an
        // IRIREF before it gets here — safe by accident, not by rule. Restore
        // the property explicitly rather than inherit it by luck.
        NamedNode::new(name).map_err(|_| ResourceError::InvalidIri)?;
        registry.push_str(&format!(
            "<{iri}> <{SYS_HAS_SUBGRAPH}> <{k}> . <{k}> <{SYS_GRAPH_NAME}> <{name}> . ",
            k = key.graph_iri()
        ));
    }
    update.push_str(&format!("INSERT DATA {{ GRAPH <{sys}> {{ {registry} }} }}"));

    store.update(&update).await?;

    // §5.2: this write replaces the representation including its kind, so a
    // blob that was here is superseded. Runs after the update commits — see
    // the doc comment above. Unconditional — deleting an absent object
    // succeeds, and a check plus a delete is two round-trips with a window
    // between them. Over-long keys have no object to remove.
    if let Some(key) = crate::blob::BlobKey::of(r) {
        blobs.delete(&key).await?;
    }
    Ok(())
}

/// §5: replace a resource with bytes, and record what they arrived as.
///
/// The object is written **before** the marker, and that order is the design
/// (§5.1): an interrupted marker write leaves an object no read path can see
/// and the next write to the same URL overwrites, whereas the reverse order
/// would leave a resource that exists and cannot be served. The registry read
/// happens before the drops for the same reason it does in [`put_dataset`] —
/// it lives in the graph being dropped.
pub async fn put_blob(
    store: &dyn SparqlStore,
    blobs: &dyn crate::blob::BlobStore,
    r: &ResourceUrl,
    bytes: bytes::Bytes,
    media_type: &crate::rdf::MediaType,
) -> Result<(), ResourceError> {
    let key = crate::blob::BlobKey::of(r).ok_or(ResourceError::KeyTooLong)?;
    let shelves = registered_shelves(store, r).await?;
    blobs.put(&key, bytes).await?;

    let iri = r.graph_iri();
    let sys = sys_graph_iri(r);
    let mt = sparql::Literal::new(&oxigraph::model::Literal::new_simple_literal(
        media_type.as_str(),
    ));
    let mut update = String::new();
    for shelf in shelves {
        update.push_str(&format!("DROP SILENT GRAPH <{}>; ", shelf.graph_iri()));
    }
    update.push_str(&format!(
        "DROP SILENT GRAPH <{iri}>; DROP SILENT GRAPH <{sys}>; \
         INSERT DATA {{ GRAPH <{sys}> {{ \
           <{iri}> <{SYS_PRESENT}> true . \
           <{iri}> <{RDF_TYPE}> <{SYS_BINARY_RESOURCE}> . \
           <{iri}> <{SYS_MEDIA_TYPE}> {mt} \
         }} }}"
    ));
    store.update(&update).await?;
    Ok(())
}

/// Which kind of representation `r` holds, or `None` if it is absent.
pub async fn kind_of(
    store: &dyn SparqlStore,
    r: &ResourceUrl,
) -> Result<Option<Kind>, ResourceError> {
    if !exists(store, r).await? {
        return Ok(None);
    }
    let iri = r.graph_iri();
    let sys = sys_graph_iri(r);
    let binary = store
        .ask(&format!(
            "ASK {{ GRAPH <{sys}> {{ <{iri}> <{RDF_TYPE}> <{SYS_BINARY_RESOURCE}> }} }}"
        ))
        .await?;
    if !binary {
        return Ok(Some(Kind::Rdf));
    }
    // §3.1 writes both in one INSERT DATA, so a binary resource without a
    // media type is that invariant broken. Refusing beats serving bytes under
    // a type the server invented.
    let mt = stored_media_type(store, r).await?.ok_or(ResourceError::BinaryWithoutMediaType)?;
    Ok(Some(Kind::Binary(mt)))
}

/// §6 step 2: the resource graph, the registry, and one `CONSTRUCT` per shelf.
/// `query_triples` has no graph field, so a single query cannot recover which
/// shelf a triple came from — 2+N in-process queries, and no fast path that
/// skips the shelves, because the ETag covers the resource rather than the
/// response body.
pub async fn get_dataset(
    store: &dyn SparqlStore,
    r: &ResourceUrl,
) -> Result<Option<Skolemized>, ResourceError> {
    use oxigraph::model::{GraphName, NamedNode, Quad};
    if !exists(store, r).await? {
        return Ok(None);
    }
    let iri = r.graph_iri();
    let sys = sys_graph_iri(r);

    let mut quads: Vec<Quad> = store
        .query_triples(&format!(
            "CONSTRUCT {{ ?s ?p ?o }} WHERE {{ GRAPH <{iri}> {{ ?s ?p ?o }} }}"
        ))
        .await?
        .into_iter()
        .map(|t| Quad::new(t.subject, t.predicate, t.object, GraphName::DefaultGraph))
        .collect();

    // One CONSTRUCT per shelf: query_triples has no graph field, so a single
    // query cannot recover which shelf a triple came from. The graph name comes
    // from the registry, not from the key — the key is not reversible.
    for key in registered_shelves(store, r).await? {
        let k = key.graph_iri();
        let names = store.query_triples(&format!(
            "CONSTRUCT {{ <{k}> <{SYS_GRAPH_NAME}> ?n }} \
             WHERE {{ GRAPH <{sys}> {{ <{k}> <{SYS_GRAPH_NAME}> ?n }} }}"
        )).await?;
        let Some(name) = names.iter().find_map(|t| match &t.object {
            oxigraph::model::Term::NamedNode(n) => NamedNode::new(n.as_str()).ok(),
            _ => None,
        }) else {
            // A shelf with no name is the invariant of §3.2.3 broken; refusing
            // is better than serving content under a name we invented.
            return Err(ResourceError::InvalidIri);
        };
        for t in store.query_triples(&format!(
            "CONSTRUCT {{ ?s ?p ?o }} WHERE {{ GRAPH <{k}> {{ ?s ?p ?o }} }}"
        )).await? {
            quads.push(Quad::new(t.subject, t.predicate, t.object, name.clone()));
        }
    }

    Ok(Some(Skolemized::from_store(quads).expect("the store holds no blank node")))
}

/// §6.4: what the representation arrived as, for `*/*` and for the
/// `mediaType` LWS requires per container member. Stored as its media-type
/// literal, returned as the media type; the RDF path narrows it to a
/// [`Format`] — the string form exists in the registry and nowhere else.
pub async fn stored_media_type(
    store: &dyn SparqlStore,
    r: &ResourceUrl,
) -> Result<Option<crate::rdf::MediaType>, ResourceError> {
    let iri = r.graph_iri();
    let sys = sys_graph_iri(r);
    let triples = store.query_triples(&format!(
        "CONSTRUCT {{ <{iri}> <{SYS_MEDIA_TYPE}> ?m }} \
         WHERE {{ GRAPH <{sys}> {{ <{iri}> <{SYS_MEDIA_TYPE}> ?m }} }}"
    )).await?;
    Ok(triples.iter().find_map(|t| match &t.object {
        oxigraph::model::Term::Literal(l) => crate::rdf::MediaType::parse(l.value()),
        _ => None,
    }))
}

/// §5 step 5: the shelves the registry currently lists, read *before* the
/// write update because `DROP GRAPH` takes a literal IRI and the
/// variable-bound alternative empties a graph without removing it.
pub async fn registered_shelves(
    store: &dyn SparqlStore,
    r: &ResourceUrl,
) -> Result<Vec<ShelfKey>, ResourceError> {
    let iri = r.graph_iri();
    let sys = sys_graph_iri(r);
    let triples = store.query_triples(&format!(
        "CONSTRUCT {{ <{iri}> <{SYS_HAS_SUBGRAPH}> ?g }} \
         WHERE {{ GRAPH <{sys}> {{ <{iri}> <{SYS_HAS_SUBGRAPH}> ?g }} }}"
    )).await?;
    Ok(triples.iter().filter_map(|t| match &t.object {
        oxigraph::model::Term::NamedNode(n) => Some(ShelfKey::from_registry(n.as_str())),
        _ => None,
    }).collect())
}

/// `triples` carries no graph name, and `serialize_for_insert` does not read
/// one — the caller supplies it via the `GRAPH <...>` wrapper around the
/// rendered body — so every quad is tagged `GraphName::DefaultGraph` here
/// purely to satisfy [`Dataset`]'s shape.
fn as_quads(triples: &[Triple]) -> Vec<oxigraph::model::Quad> {
    triples.iter()
        .map(|t| oxigraph::model::Quad::new(
            t.subject.clone(), t.predicate.clone(), t.object.clone(),
            oxigraph::model::GraphName::DefaultGraph,
        ))
        .collect()
}

/// Replace a graph's contents and mark it present, in one update.
///
/// `triples` may be client-supplied (a `PUT`/`POST` body), so blank nodes are
/// expected here and skolemized rather than rejected — [`insert_marked`] is
/// the path for content that is ground before it arrives.
pub async fn put_rdf(
    store: &dyn SparqlStore,
    g: &impl DirectlyWritable,
    triples: &[Triple],
) -> Result<(), ResourceError> {
    let iri = g.graph_iri();
    let sys = sys_graph_iri(g);
    let skolemized = Skolemized::skolemize(&Dataset::new(as_quads(triples)));
    let body = serialize_for_insert(&skolemized);
    store
        .update(&format!(
            "DROP SILENT GRAPH <{iri}>; \
             INSERT DATA {{ GRAPH <{iri}> {{ {body} }} }}; \
             INSERT DATA {{ GRAPH <{sys}> {{ <{iri}> <{SYS_PRESENT}> true }} }}"
        ))
        .await?;
    Ok(())
}

/// Insert quads into a graph without replacing what is there, marking it
/// present in the same update. This is the additive counterpart to
/// [`put_rdf`]: containment and container type triples accumulate rather
/// than replace, but must not be able to produce content without a
/// presence marker.
///
/// Takes [`GroundQuad`] rather than `Triple` because every caller builds its
/// own assertions (container type, containment) from IRIs it just minted,
/// instead of forwarding a client body. Saying that in the parameter type
/// leaves a future caller with a client body no way to reach here without
/// either skolemizing it first or using [`put_rdf`], which is the choice that
/// used to be made by an `.expect` at run time.
pub async fn insert_marked(
    store: &dyn SparqlStore,
    g: &impl DirectlyWritable,
    quads: &[GroundQuad],
) -> Result<(), ResourceError> {
    let iri = g.graph_iri();
    let sys = sys_graph_iri(g);
    let body = serialize_for_insert(&Skolemized::new(quads.to_vec()));
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
    use crate::{space::{AuxKind, AuxUrl, ResourceUrl, StorageSpace, Target}, store::OxigraphStore};

    fn sp() -> StorageSpace { StorageSpace::new("https://pod.toph.so/").unwrap() }

    fn res(path: &str) -> crate::space::ResourceUrl {
        match sp().resolve(path).unwrap() {
            Target::Resource(r) => r,
            Target::Container(c) => c.as_resource().clone(),
            Target::Aux(_) => panic!("not a resource path"),
        }
    }

    fn triples(turtle: &str, base: &str) -> Vec<Triple> {
        Format::from_content_type("text/turtle").unwrap()
            .parse(turtle.as_bytes(), base).unwrap()
            .quads().iter().cloned().map(Triple::from).collect()
    }

    /// The same fixture in the form `insert_marked` takes. Turtle is
    /// client-shaped text, so it reaches ground form the way a client body
    /// does; these fixtures hold no blank node, so nothing is rewritten.
    fn ground_triples(turtle: &str, base: &str) -> Vec<GroundQuad> {
        Skolemized::skolemize(&Dataset::new(as_quads(&triples(turtle, base))))
            .quads().to_vec()
    }

    /// `<s> schema:name "o"` in graph `g`, stored form.
    fn gq(s: &str, o: &str, g: GroundGraphName) -> GroundQuad {
        GroundQuad::new(
            oxigraph::model::NamedNode::new(s).unwrap(),
            oxigraph::model::NamedNode::new("http://schema.org/name").unwrap(),
            oxigraph::model::Literal::new_simple_literal(o),
            g,
        )
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

    // §4's "a writer cannot smuggle a blank node past the constructor" had a
    // test here while `Skolemized` wrapped `Quad`. `insert_marked` now takes
    // `&[GroundQuad]`, so the expression that smuggles one does not compile —
    // see `tests/unrepresentable.rs`.

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

    // §4, on the one path a client body actually takes: nothing before this
    // test writes a blank node through `put_rdf`, so a no-op `skolemize` or a
    // `put_rdf` that quietly dropped every triple whenever the body held a
    // blank node would both leave the suite green. The second triple, on a
    // named subject, is what tells a total-loss mutant apart from one that
    // merely mishandles the blank node.
    #[tokio::test]
    async fn a_blank_node_in_a_client_body_is_stored_not_dropped_and_not_left_blank() {
        let store = OxigraphStore::in_memory().unwrap();
        let foo = res("/foo");
        let t = triples(
            "_:b <http://schema.org/name> \"x\" . <#it> <http://schema.org/name> \"y\" .",
            foo.graph_iri(),
        );
        put_rdf(&store, &foo, &t).await.unwrap();

        let got = get_rdf(&store, &foo).await.unwrap().expect("exists");
        assert_eq!(got.len(), 2, "both triples must survive, not just the named one");

        let from_blank = got
            .iter()
            .find(|t| matches!(&t.object, oxigraph::model::Term::Literal(l) if l.value() == "x"))
            .expect("the triple that started on a blank node round-tripped");
        assert!(
            matches!(&from_blank.subject, oxigraph::model::NamedOrBlankNode::NamedNode(_)),
            "a blank node must never reach the store as a blank node"
        );
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
        assert!(sys_graph_iri(&foo).starts_with("urn:quadpod:sys:"));
    }

    #[tokio::test]
    async fn insert_marked_accumulates_not_replaces() {
        let store = OxigraphStore::in_memory().unwrap();
        let foo = res("/foo");
        insert_marked(&store, &foo, &ground_triples("<#a> <http://schema.org/name> \"A\" .", foo.graph_iri())).await.unwrap();
        insert_marked(&store, &foo, &ground_triples("<#b> <http://schema.org/name> \"B\" .", foo.graph_iri())).await.unwrap();
        let got = get_rdf(&store, &foo).await.unwrap().unwrap();
        assert_eq!(got.len(), 2, "second insert_marked should add, not replace");
    }

    #[tokio::test]
    async fn insert_marked_writes_a_presence_marker() {
        let store = OxigraphStore::in_memory().unwrap();
        let blobs = crate::blob::ObjectStoreBlobs::in_memory();
        let foo = res("/foo");
        insert_marked(&store, &foo, &ground_triples("<#it> <http://schema.org/name> \"x\" .", foo.graph_iri())).await.unwrap();
        assert!(exists(&store, &foo).await.unwrap());
        // A resource is removed by the cascade, not by `delete_rdf`.
        assert!(crate::aux::delete_subject(&store, &blobs, &foo).await.unwrap());
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

    // The ASK is scoped to `GRAPH <urn:quadpod:sys:{iri}>`, which is what stops a
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

    #[tokio::test]
    async fn a_dataset_round_trips_through_the_store() {
        let store = OxigraphStore::in_memory().unwrap();
        let blobs = crate::blob::ObjectStoreBlobs::in_memory();
        let r = res("/c/notes");
        let jsonld = crate::rdf::Format::from_content_type("application/ld+json").unwrap();
        let g = oxigraph::model::NamedNode::new("urn:example:g1").unwrap();
        let ds = Skolemized::new(vec![
            gq("https://pod.toph.so/c/notes#it", "Toph", GroundGraphName::DefaultGraph),
            gq("http://example.org/alice", "Alice", g.clone().into()),
        ]);

        put_dataset(&store, &blobs, &r, &ds, jsonld).await.unwrap();

        let back = get_dataset(&store, &r).await.unwrap().expect("present");
        assert_eq!(back.quads().len(), 2);
        assert!(back.quads().iter().any(|q| q.graph_name == g.clone().into()),
            "the graph name came back");
        assert_eq!(
            stored_media_type(&store, &r).await.unwrap(),
            Some(crate::rdf::MediaType::parse(jsonld.media_type()).unwrap())
        );
    }

    // §3.2 invariant 4: a shelf the registry no longer lists is not litter, it
    // is content the next write to the same (resource, graph name) pair would
    // INSERT INTO — so the resource would return triples nobody wrote.
    #[tokio::test]
    async fn a_replacing_write_leaves_no_shelf_behind() {
        let store = OxigraphStore::in_memory().unwrap();
        let blobs = crate::blob::ObjectStoreBlobs::in_memory();
        let r = res("/c/notes");
        let ttl = crate::rdf::Format::from_content_type("text/turtle").unwrap();
        let g = oxigraph::model::NamedNode::new("urn:example:g1").unwrap();
        let with_graph = Skolemized::new(vec![gq("http://example.org/alice", "Alice", g.clone().into())]);

        put_dataset(&store, &blobs, &r, &with_graph, ttl).await.unwrap();
        assert_eq!(registered_shelves(&store, &r).await.unwrap().len(), 1);

        // Replace with a document that has no named graph at all.
        put_dataset(&store, &blobs, &r, &Skolemized::new(vec![]), ttl).await.unwrap();
        assert!(registered_shelves(&store, &r).await.unwrap().is_empty());

        // And the shelf is gone, not merely emptied: write the same graph name
        // again and it must not inherit the old triples.
        put_dataset(&store, &blobs, &r, &with_graph, ttl).await.unwrap();
        let back = get_dataset(&store, &r).await.unwrap().unwrap();
        assert_eq!(back.quads().len(), 1, "no resurrected content");
    }

    // Every assertion above reads state back through the registry
    // (`registered_shelves`, `get_dataset`, `exists`), so a shelf that got
    // orphaned *outside* the registry is invisible to it. This one probes
    // the store directly, bypassing the registry entirely.

    // §3.2 invariant 4, probed directly. Unlike `a_replacing_write_leaves_no_shelf_behind`,
    // graph A and graph B are different names, so the second `put_dataset`'s
    // own drop loop (built from *this* write's shelves) cannot be the thing
    // that empties A's shelf by re-dropping the same key it just wrote. Only
    // the first loop — built from `registered_shelves`, i.e. what the
    // registry said existed *before* this write — can drop A. So this test
    // fails if that first loop is removed, where the existing same-name test
    // does not.
    #[tokio::test]
    async fn a_replacing_write_with_a_different_graph_name_leaves_the_old_shelf_empty() {
        let store = OxigraphStore::in_memory().unwrap();
        let blobs = crate::blob::ObjectStoreBlobs::in_memory();
        let r = res("/c/notes");
        let ttl = crate::rdf::Format::from_content_type("text/turtle").unwrap();
        let a = oxigraph::model::NamedNode::new("urn:example:a").unwrap();
        let b = oxigraph::model::NamedNode::new("urn:example:b").unwrap();

        let with_a = Skolemized::new(vec![gq("http://example.org/alice", "Alice", a.clone().into())]);
        let with_b = Skolemized::new(vec![gq("http://example.org/bob", "Bob", b.into())]);

        put_dataset(&store, &blobs, &r, &with_a, ttl).await.unwrap();
        let key_a = ShelfKey::of(&r, a.as_ref());

        put_dataset(&store, &blobs, &r, &with_b, ttl).await.unwrap();

        let leftover = store.query_triples(&format!(
            "CONSTRUCT {{ ?s ?p ?o }} WHERE {{ GRAPH <{}> {{ ?s ?p ?o }} }}", key_a.graph_iri()
        )).await.unwrap();
        assert!(leftover.is_empty(), "graph A's shelf must be emptied when a replacing write names graph B instead");
    }

    // Module invariant at the top of this file: "existence is a stored fact,
    // not an inference from triple count." A dataset with no named graphs
    // writes no `sys:hasSubgraph` registry entries — nothing here should let
    // that also skip the presence marker itself.
    #[tokio::test]
    async fn put_dataset_with_no_named_graphs_still_marks_presence() {
        let store = OxigraphStore::in_memory().unwrap();
        let blobs = crate::blob::ObjectStoreBlobs::in_memory();
        let r = res("/c/notes");
        let ttl = crate::rdf::Format::from_content_type("text/turtle").unwrap();

        put_dataset(&store, &blobs, &r, &Skolemized::new(vec![]), ttl).await.unwrap();

        assert!(exists(&store, &r).await.unwrap(), "a graphless dataset write must still mark presence");
        assert!(get_dataset(&store, &r).await.unwrap().is_some());
    }

    // §3.6: the re-validation added to `put_dataset` sits between the parser
    // and the interpolation site, so it must accept everything that already
    // made it through the parser. This pins that: a graph name the parser
    // let through still round-trips, so the added check has not narrowed
    // what used to work.
    #[tokio::test]
    async fn a_graph_name_that_survived_the_parser_still_round_trips() {
        let store = OxigraphStore::in_memory().unwrap();
        let blobs = crate::blob::ObjectStoreBlobs::in_memory();
        let r = res("/c/notes");
        let ttl = crate::rdf::Format::from_content_type("text/turtle").unwrap();
        let g = oxigraph::model::NamedNode::new("urn:example:valid-name").unwrap();
        let ds = Skolemized::new(vec![gq("http://example.org/alice", "Alice", g.clone().into())]);

        put_dataset(&store, &blobs, &r, &ds, ttl).await.unwrap();

        let back = get_dataset(&store, &r).await.unwrap().expect("present");
        assert_eq!(back.quads().len(), 1);
        assert!(back.quads().iter().any(|q| q.graph_name == g.clone().into()));
    }

    // No test before this one writes default-graph content to the same
    // resource twice. `put_dataset`'s drop list includes `DROP SILENT GRAPH
    // <iri>` alongside the shelf drops precisely so the default graph is
    // replaced rather than accumulated — this exercises that specific drop.
    #[tokio::test]
    async fn a_second_default_graph_write_replaces_not_accumulates() {
        let store = OxigraphStore::in_memory().unwrap();
        let blobs = crate::blob::ObjectStoreBlobs::in_memory();
        let r = res("/c/notes");
        let ttl = crate::rdf::Format::from_content_type("text/turtle").unwrap();
        let first = Skolemized::new(vec![gq("http://example.org/alice", "Alice", GroundGraphName::DefaultGraph)]);
        let second = Skolemized::new(vec![gq("http://example.org/bob", "Bob", GroundGraphName::DefaultGraph)]);

        put_dataset(&store, &blobs, &r, &first, ttl).await.unwrap();
        put_dataset(&store, &blobs, &r, &second, ttl).await.unwrap();

        let back = get_dataset(&store, &r).await.unwrap().unwrap();
        assert_eq!(back.quads().len(), 1, "second default-graph write should replace, not accumulate");
        assert!(
            matches!(&back.quads()[0].object, crate::dataset::GroundTerm::Literal(l) if l.value() == "Bob"),
            "read-back must be the second write's content, not the first's"
        );
    }

    /// A `BlobStore` whose `put` always fails, for the write-order test.
    struct FailingBlobs;

    #[async_trait::async_trait]
    impl crate::blob::BlobStore for FailingBlobs {
        async fn put(&self, _: &crate::blob::BlobKey, _: bytes::Bytes)
            -> Result<(), crate::blob::BlobError> {
            Err(crate::blob::BlobError::Backend("disk on fire".into()))
        }
        async fn get(&self, _: &crate::blob::BlobKey)
            -> Result<Option<bytes::Bytes>, crate::blob::BlobError> { Ok(None) }
        async fn delete(&self, _: &crate::blob::BlobKey)
            -> Result<(), crate::blob::BlobError> { Ok(()) }
    }

    #[tokio::test]
    async fn a_blob_round_trips_with_its_declared_media_type() {
        let store = OxigraphStore::in_memory().unwrap();
        let blobs = crate::blob::ObjectStoreBlobs::in_memory();
        let r = res("/photos/cat.png");
        let mt = crate::rdf::MediaType::parse("image/png").unwrap();
        let payload = bytes::Bytes::from_static(&[0x00, 0xff, 0xfe, b'\r', b'\n', 0x41]);

        put_blob(&store, &blobs, &r, payload.clone(), &mt).await.unwrap();

        assert!(exists(&store, &r).await.unwrap());
        assert_eq!(kind_of(&store, &r).await.unwrap(), Some(Kind::Binary(mt)));
        let key = crate::blob::BlobKey::of(&r).unwrap();
        assert_eq!(
            crate::blob::BlobStore::get(&blobs, &key).await.unwrap().unwrap(),
            payload,
            "bytes survive exactly — a NUL and invalid UTF-8 are in there on purpose"
        );
    }

    // §5.1: bytes first, marker second. The reverse order leaves a resource
    // that exists and cannot be served, and nothing but this test says which
    // way round the two statements go.
    #[tokio::test]
    async fn a_failed_object_write_leaves_no_resource_behind() {
        let store = OxigraphStore::in_memory().unwrap();
        let r = res("/photos/cat.png");
        let mt = crate::rdf::MediaType::parse("image/png").unwrap();

        let err = put_blob(&store, &FailingBlobs, &r, bytes::Bytes::from_static(b"x"), &mt)
            .await
            .unwrap_err();

        assert!(matches!(err, ResourceError::Blob(_)));
        assert!(!exists(&store, &r).await.unwrap(), "the marker must not have been written");
        assert_eq!(kind_of(&store, &r).await.unwrap(), None);
    }

    // §3.3: the kind is a stored triple, not an inference from the media type.
    // Deriving it would silently re-interpret every stored RDF/XML blob on the
    // day `Format` learns application/rdf+xml.
    #[tokio::test]
    async fn an_rdf_resource_and_a_blob_are_distinguishable_by_a_stored_fact() {
        let store = OxigraphStore::in_memory().unwrap();
        let blobs = crate::blob::ObjectStoreBlobs::in_memory();
        let rdf = res("/notes");
        let blob = res("/photo");

        // `put_rdf`, not `put_dataset`: this task must not depend on Task 6's
        // signature change, and it writes the same presence marker.
        put_rdf(&store, &rdf, &[]).await.unwrap();
        put_blob(&store, &blobs, &blob, bytes::Bytes::from_static(b"x"),
                 &crate::rdf::MediaType::parse("text/plain").unwrap()).await.unwrap();

        assert_eq!(kind_of(&store, &rdf).await.unwrap(), Some(Kind::Rdf));
        assert!(matches!(kind_of(&store, &blob).await.unwrap(), Some(Kind::Binary(_))));
        assert_eq!(kind_of(&store, &res("/absent")).await.unwrap(), None);
    }

    // §3.1's invariant: a binary resource always has a stored media type.
    // This state should not occur — one INSERT DATA writes both — so the test
    // pins the fail-closed answer for when it somehow does.
    #[tokio::test]
    async fn a_binary_resource_without_a_media_type_fails_closed() {
        let store = OxigraphStore::in_memory().unwrap();
        let blobs = crate::blob::ObjectStoreBlobs::in_memory();
        let r = res("/photo");
        put_blob(&store, &blobs, &r, bytes::Bytes::from_static(b"x"),
                 &crate::rdf::MediaType::parse("text/plain").unwrap()).await.unwrap();

        let sys = sys_graph_iri(&r);
        store.update(&format!(
            "DELETE WHERE {{ GRAPH <{sys}> {{ <{}> <{SYS_MEDIA_TYPE}> ?m }} }}", r.graph_iri()
        )).await.unwrap();

        assert!(matches!(
            kind_of(&store, &r).await,
            Err(ResourceError::BinaryWithoutMediaType)
        ));
    }

    // §3.2.3's invariant: a shelf the registry lists must have a
    // `sys:graphName`. This state should never occur — every writer of the
    // registry writes both in the same update — but pins the fail-closed
    // answer for when it somehow does: refusing beats serving content under
    // a name `get_dataset` invented itself.
    #[tokio::test]
    async fn a_shelf_with_no_graph_name_makes_get_dataset_fail_closed() {
        let store = OxigraphStore::in_memory().unwrap();
        let blobs = crate::blob::ObjectStoreBlobs::in_memory();
        let r = res("/c/notes");
        let ttl = crate::rdf::Format::from_content_type("text/turtle").unwrap();
        let g = oxigraph::model::NamedNode::new("urn:example:g1").unwrap();
        let ds = Skolemized::new(vec![gq("http://example.org/alice", "Alice", g.clone().into())]);

        put_dataset(&store, &blobs, &r, &ds, ttl).await.unwrap();

        // Derived the same way the module itself derives it — never by
        // writing the string `"urn:quadpod:sys:"` here.
        let key = ShelfKey::of(&r, g.as_ref());
        let sys = sys_graph_iri(&r);
        store
            .update(&format!(
                "DELETE DATA {{ GRAPH <{sys}> {{ <{}> <{SYS_GRAPH_NAME}> <{}> }} }}",
                key.graph_iri(),
                g.as_str()
            ))
            .await
            .unwrap();

        assert!(matches!(get_dataset(&store, &r).await, Err(ResourceError::InvalidIri)));
    }

    // §5.2: PUT replaces the representation including its kind. The assertion
    // is against the BlobStore directly, not through the marker — reading back
    // through the registry is how `b4d2346` found orphans invisible.
    #[tokio::test]
    async fn writing_rdf_over_a_blob_removes_the_object() {
        let store = OxigraphStore::in_memory().unwrap();
        let blobs = crate::blob::ObjectStoreBlobs::in_memory();
        let r = res("/thing");
        let key = crate::blob::BlobKey::of(&r).unwrap();
        let ttl = Format::from_content_type("text/turtle").unwrap();

        put_blob(&store, &blobs, &r, bytes::Bytes::from_static(b"x"),
                 &crate::rdf::MediaType::parse("text/plain").unwrap()).await.unwrap();
        assert!(crate::blob::BlobStore::get(&blobs, &key).await.unwrap().is_some());

        put_dataset(&store, &blobs, &r, &Skolemized::new(vec![]), ttl).await.unwrap();

        assert_eq!(kind_of(&store, &r).await.unwrap(), Some(Kind::Rdf));
        assert!(
            crate::blob::BlobStore::get(&blobs, &key).await.unwrap().is_none(),
            "the superseded object must be gone, not merely unreachable"
        );
    }

    #[tokio::test]
    async fn writing_a_blob_over_rdf_removes_the_graph_and_its_shelves() {
        let store = OxigraphStore::in_memory().unwrap();
        let blobs = crate::blob::ObjectStoreBlobs::in_memory();
        let r = res("/thing");
        let ttl = Format::from_content_type("text/turtle").unwrap();
        let g = oxigraph::model::NamedNode::new("urn:example:g1").unwrap();
        let ds = Skolemized::new(vec![gq("http://example.org/alice", "Alice", g.clone().into())]);

        put_dataset(&store, &blobs, &r, &ds, ttl).await.unwrap();
        let shelf = ShelfKey::of(&r, g.as_ref());

        put_blob(&store, &blobs, &r, bytes::Bytes::from_static(b"x"),
                 &crate::rdf::MediaType::parse("text/plain").unwrap()).await.unwrap();

        assert!(matches!(kind_of(&store, &r).await.unwrap(), Some(Kind::Binary(_))));
        assert!(registered_shelves(&store, &r).await.unwrap().is_empty());
        // Probed directly: an emptied-but-present shelf is content the next
        // write to the same graph name would inherit.
        let leftover = store.query_triples(&format!(
            "CONSTRUCT {{ ?s ?p ?o }} WHERE {{ GRAPH <{}> {{ ?s ?p ?o }} }}", shelf.graph_iri()
        )).await.unwrap();
        assert!(leftover.is_empty());
    }
}
