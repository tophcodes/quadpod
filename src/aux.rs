//! Auxiliary-resource lifecycle.
//!
//! An auxiliary is not an independently creatable object: it exists only for
//! an existing subject, and it dies with that subject. Both rules live here,
//! in the only functions that can write or delete one, so no handler can
//! implement half of them.

use oxigraph::model::Triple;
use thiserror::Error;

use crate::{
    dataset::{Dataset, Skolemized},
    resource::{exists, registered_shelves, serialize_for_insert, sys_graph_iri, ResourceError, SYS_PRESENT},
    space::{AuxKind, AuxUrl, GraphName, ResourceUrl},
    store::SparqlStore,
};

#[derive(Debug, Error)]
pub enum AuxError {
    #[error("the auxiliary's subject resource does not exist")]
    SubjectMissing,
    #[error(transparent)]
    Resource(#[from] ResourceError),
}

/// The `404` body for an auxiliary write refused for [`AuxError::SubjectMissing`].
///
/// Two call sites answer this: `wac::guard::authorize_and_materialize` (the
/// ancestor-authorization walk, which can tell a missing subject apart from a
/// missing ancestor before writing anything) and `http::put_impl`'s
/// `aux::put` match arm (the in-update guard, for the window between that
/// check and the write). Both are wanted — see their call sites — so the
/// message lives here once rather than drifting between two copies.
pub const AUX_SUBJECT_MISSING_MESSAGE: &str =
    "an auxiliary resource cannot be created for a resource that does not exist";

/// The update [`put`] issues: it replaces the auxiliary's contents and marks
/// it present, but only for a subject that is present *at the moment of the
/// write*.
///
/// The condition is inside the update rather than a preceding `exists` call
/// because a check and a write are two round-trips: a `DELETE` interleaving
/// between them would let the write land on a subject that no longer exists,
/// planting exactly the orphan this module says cannot occur. `INSERT DATA`
/// cannot carry a condition, so both halves use the `… WHERE` form with a
/// `FILTER EXISTS` on the subject's presence marker. The guard is repeated on
/// the clearing `DELETE` so a failed write cannot destroy what it did not
/// replace.
///
/// `triples` is a client-supplied auxiliary body (an ACL commonly writes an
/// anonymous `[] a acl:Authorization`), so it is skolemized here rather than
/// required to already be ground.
fn conditional_put_update(aux: &AuxUrl, triples: &[Triple]) -> String {
    use oxigraph::model::{GraphName, Quad};
    let iri = aux.graph_iri();
    let sys = sys_graph_iri(aux);
    let subject_iri = aux.subject().graph_iri();
    let subject_sys = sys_graph_iri(aux.subject());
    let guard = format!(
        "FILTER EXISTS {{ GRAPH <{subject_sys}> {{ <{subject_iri}> <{SYS_PRESENT}> true }} }}"
    );
    let quads: Vec<Quad> = triples.iter()
        .map(|t| Quad::new(t.subject.clone(), t.predicate.clone(), t.object.clone(), GraphName::DefaultGraph))
        .collect();
    let skolemized = Skolemized::skolemize(&Dataset::new(quads));
    let body = serialize_for_insert(&skolemized);
    format!(
        "DELETE {{ GRAPH <{iri}> {{ ?s ?p ?o }} }} \
         WHERE {{ GRAPH <{iri}> {{ ?s ?p ?o }} {guard} }}; \
         INSERT {{ GRAPH <{iri}> {{ {body} }} \
                   GRAPH <{sys}> {{ <{iri}> <{SYS_PRESENT}> true }} }} \
         WHERE {{ {guard} }}"
    )
}

/// Write an auxiliary resource. Fails when its subject does not exist —
/// otherwise a policy document could be planted on a path that was never
/// created, where nearest-ACL-wins would make it permanent and unremovable.
///
/// The write is guarded inside the update (see [`conditional_put_update`]);
/// the `exists` call afterwards only decides what the caller is told. It runs
/// *after* the update on purpose, and it asks about the **auxiliary**, not
/// the subject — the question the return value actually answers is "did my
/// write land", and only that phrasing survives every interleaving. Asking
/// about the subject would report `Ok(())` when a subject was deleted and
/// recreated around the guarded update: nothing was written, yet the client
/// would believe the path is protected while nearest-ACL-wins quietly hands
/// it the ancestor's rules. Claiming success for an unwritten policy
/// document is the dangerous direction.
pub async fn put(
    store: &dyn SparqlStore,
    aux: &AuxUrl,
    triples: &[Triple],
) -> Result<(), AuxError> {
    store
        .update(&conditional_put_update(aux, triples))
        .await
        .map_err(ResourceError::from)?;
    if !exists(store, aux).await? {
        return Err(AuxError::SubjectMissing);
    }
    Ok(())
}

/// Delete a subject resource together with every auxiliary it may have and
/// every shelf its dataset registered, in a single store update. Returns
/// whether the subject existed.
///
/// The drops run unconditionally — they are `DROP SILENT`, a no-op on an
/// absent graph — and the existence check only decides the returned boolean.
/// An early return on `!exists` would leave an already-orphaned auxiliary in
/// place and unreported, and since this is the only cascade path that orphan
/// would be permanent: recreating the subject would resurrect its grants.
/// Same reasoning as [`crate::resource::delete_rdf`].
///
/// The shelf registry is read before any drop, and its drops are ordered
/// before the system graph's: the registry lives in the very graph this
/// cascade drops, and reading it after would find nothing to drop, leaving
/// the shelves as the one part of the resource a `DELETE` cannot remove
/// (design spec §7). A container's registry is simply empty, so the same
/// cascade is correct for it without a branch.
///
/// This is the one delete cascade (§7): callers remain responsible for
/// containment — the subject's membership triple in its parent, and for a
/// container subject its children, are `container`'s business, not this
/// function's — but everything else a subject can hold, including a blob it
/// stored bytes as, goes with it here.
pub async fn delete_subject(
    store: &dyn SparqlStore,
    blobs: &dyn crate::blob::BlobStore,
    subject: &ResourceUrl,
) -> Result<bool, ResourceError> {
    let existed = exists(store, subject).await?;
    let mut drops: Vec<String> = registered_shelves(store, subject).await?
        .into_iter()
        .map(|key| format!("DROP SILENT GRAPH <{}>", key.graph_iri()))
        .collect();
    drops.push(format!("DROP SILENT GRAPH <{}>", subject.graph_iri()));
    drops.push(format!("DROP SILENT GRAPH <{}>", sys_graph_iri(subject)));
    for kind in AuxKind::ALL {
        let aux = subject.aux(*kind);
        drops.push(format!("DROP SILENT GRAPH <{}>", aux.graph_iri()));
        drops.push(format!("DROP SILENT GRAPH <{}>", sys_graph_iri(&aux)));
    }
    store.update(&drops.join("; ")).await?;
    // §7: graphs and marker first, then the object. An interrupted second half
    // leaves an object no marker points at, which the next write to the same
    // URL overwrites; the reverse order would leave a resource that exists and
    // cannot be served.
    if let Some(key) = crate::blob::BlobKey::of(subject) {
        blobs.delete(&key).await?;
    }
    Ok(existed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{rdf::Format, resource::{exists, get_dataset, get_rdf, put_dataset, put_rdf, registered_shelves}, shelf::ShelfKey, space::{AuxKind, StorageSpace, Target}, store::OxigraphStore};

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

    /// A minimal but real ACL body, so the tests exercise the content path and
    /// not just the presence marker.
    fn grant(aux: &AuxUrl) -> Vec<Triple> {
        triples(
            "<#owner> <http://www.w3.org/ns/auth/acl#mode> \
             <http://www.w3.org/ns/auth/acl#Control> .",
            aux.graph_iri(),
        )
    }

    async fn graph_contents(store: &OxigraphStore, iri: &str) -> Vec<Triple> {
        store
            .query_triples(&format!(
                "CONSTRUCT {{ ?s ?p ?o }} WHERE {{ GRAPH <{iri}> {{ ?s ?p ?o }} }}"
            ))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn an_auxiliary_needs_an_existing_subject() {
        let store = OxigraphStore::in_memory().unwrap();
        let ghost = res("/ghost");
        assert!(matches!(
            put(&store, &ghost.aux(AuxKind::Acl), &[]).await,
            Err(AuxError::SubjectMissing)
        ));
        assert!(!exists(&store, &ghost.aux(AuxKind::Acl)).await.unwrap());
    }

    #[tokio::test]
    async fn an_auxiliary_can_be_written_for_an_existing_subject() {
        let store = OxigraphStore::in_memory().unwrap();
        let foo = res("/foo");
        let acl = foo.aux(AuxKind::Acl);
        put_rdf(&store, &foo, &[]).await.unwrap();
        put(&store, &acl, &grant(&acl)).await.unwrap();
        assert!(exists(&store, &acl).await.unwrap());
        assert_eq!(get_rdf(&store, &acl).await.unwrap(), Some(grant(&acl)));
    }

    // §4, on `aux::put`'s client body: an ACL commonly writes an anonymous
    // `[] a acl:Authorization`, so nothing before this test exercises that
    // shape. A no-op `skolemize` or a write that silently dropped the
    // blank-node triple would both leave the suite green; the second triple,
    // on a named subject, tells a total-loss mutant apart from one that only
    // mishandles the blank node.
    #[tokio::test]
    async fn a_blank_node_in_an_auxiliary_body_is_stored_not_dropped_and_not_left_blank() {
        let store = OxigraphStore::in_memory().unwrap();
        let foo = res("/foo");
        let acl = foo.aux(AuxKind::Acl);
        put_rdf(&store, &foo, &[]).await.unwrap();
        let t = triples(
            "_:b <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read> . \
             <#owner> <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Control> .",
            acl.graph_iri(),
        );
        put(&store, &acl, &t).await.unwrap();

        let got = get_rdf(&store, &acl).await.unwrap().expect("exists");
        assert_eq!(got.len(), 2, "both triples must survive, not just the named one");

        let from_blank = got
            .iter()
            .find(|t| matches!(&t.object, oxigraph::model::Term::NamedNode(n) if n.as_str().ends_with("#Read")))
            .expect("the triple that started on a blank node round-tripped");
        assert!(
            matches!(&from_blank.subject, oxigraph::model::NamedOrBlankNode::NamedNode(_)),
            "a blank node must never reach the store as a blank node"
        );
    }

    // `put` replaces, it does not accumulate: an ACL is the whole policy for
    // its subject, so a second write must not leave the first one's grants
    // behind.
    #[tokio::test]
    async fn a_second_put_replaces_the_first() {
        let store = OxigraphStore::in_memory().unwrap();
        let foo = res("/foo");
        let acl = foo.aux(AuxKind::Acl);
        put_rdf(&store, &foo, &[]).await.unwrap();
        put(&store, &acl, &grant(&acl)).await.unwrap();
        let read = triples(
            "<#reader> <http://www.w3.org/ns/auth/acl#mode> \
             <http://www.w3.org/ns/auth/acl#Read> .",
            acl.graph_iri(),
        );
        put(&store, &acl, &read).await.unwrap();
        assert_eq!(get_rdf(&store, &acl).await.unwrap(), Some(read));
    }

    // Finding 1a. The interleaving this defends against cannot be staged
    // against the in-memory store, so the test proves the mechanism instead:
    // the update alone, run for a subject that does not exist, must write
    // nothing at all. Deleting the `FILTER EXISTS` from
    // `conditional_put_update` makes this fail.
    #[tokio::test]
    async fn the_write_is_conditional_on_the_subject_inside_the_update() {
        let store = OxigraphStore::in_memory().unwrap();
        let acl = res("/ghost").aux(AuxKind::Acl);

        store
            .update(&conditional_put_update(&acl, &grant(&acl)))
            .await
            .unwrap();

        assert!(
            graph_contents(&store, acl.graph_iri()).await.is_empty(),
            "the auxiliary graph was written for a subject that does not exist"
        );
        assert!(
            graph_contents(&store, &sys_graph_iri(&acl)).await.is_empty(),
            "the presence marker was written for a subject that does not exist"
        );
        assert!(!exists(&store, &acl).await.unwrap());
    }

    // The other half of the guard: a failed write must not destroy what it
    // did not replace, so the clearing DELETE is conditional too.
    #[tokio::test]
    async fn a_suppressed_write_leaves_existing_content_alone() {
        let store = OxigraphStore::in_memory().unwrap();
        let foo = res("/foo");
        let acl = foo.aux(AuxKind::Acl);
        put_rdf(&store, &foo, &[]).await.unwrap();
        put(&store, &acl, &grant(&acl)).await.unwrap();

        // The subject disappears behind the API, as a concurrent DELETE would
        // leave it; the next write must be a complete no-op.
        let iri = foo.graph_iri();
        let sys = sys_graph_iri(&foo);
        store
            .update(&format!("DROP SILENT GRAPH <{iri}>; DROP SILENT GRAPH <{sys}>"))
            .await
            .unwrap();

        store.update(&conditional_put_update(&acl, &[])).await.unwrap();
        assert_eq!(graph_contents(&store, acl.graph_iri()).await, grant(&acl));
    }

    // The cascade is definitional, not a step someone remembers: deleting a
    // subject removes every auxiliary kind with it, so no orphan can outlive
    // it and be resurrected with stale grants when the path is recreated.
    #[tokio::test]
    async fn deleting_a_subject_deletes_every_auxiliary_kind() {
        let store = OxigraphStore::in_memory().unwrap();
        let blobs = crate::blob::ObjectStoreBlobs::in_memory();
        let foo = res("/foo");
        put_rdf(&store, &foo, &[]).await.unwrap();
        for kind in AuxKind::ALL {
            let aux = foo.aux(*kind);
            put(&store, &aux, &grant(&aux)).await.unwrap();
            assert_eq!(get_rdf(&store, &aux).await.unwrap(), Some(grant(&aux)));
        }

        assert!(delete_subject(&store, &blobs, &foo).await.unwrap());

        assert!(!exists(&store, &foo).await.unwrap());
        for kind in AuxKind::ALL {
            let aux = foo.aux(*kind);
            assert!(
                !exists(&store, &aux).await.unwrap(),
                "auxiliary {kind:?} outlived its subject"
            );
            assert_eq!(get_rdf(&store, &aux).await.unwrap(), None);
            // Not just the marker: the grants themselves are gone, so
            // recreating the path cannot resurrect them.
            assert!(
                graph_contents(&store, aux.graph_iri()).await.is_empty(),
                "auxiliary {kind:?} kept its triples after the cascade"
            );
        }
    }

    #[tokio::test]
    async fn deleting_an_absent_subject_reports_absence() {
        let store = OxigraphStore::in_memory().unwrap();
        let blobs = crate::blob::ObjectStoreBlobs::in_memory();
        assert!(!delete_subject(&store, &blobs, &res("/nope")).await.unwrap());
    }

    // Finding 1b/3: the asymmetric state — auxiliaries present, subject not.
    // An early return on `!exists` would leave this orphan in place, and as
    // the only cascade path that would make it permanent: nearest-ACL-wins
    // would hand the recreated path a policy nobody can remove.
    #[tokio::test]
    async fn an_orphaned_auxiliary_is_removed_even_though_the_subject_is_gone() {
        let store = OxigraphStore::in_memory().unwrap();
        let blobs = crate::blob::ObjectStoreBlobs::in_memory();
        let foo = res("/foo");
        let acl = foo.aux(AuxKind::Acl);
        put_rdf(&store, &foo, &[]).await.unwrap();
        put(&store, &acl, &grant(&acl)).await.unwrap();

        // Fabricate the orphan behind the API: the subject's graphs vanish
        // without the cascade ever running.
        let iri = foo.graph_iri();
        let sys = sys_graph_iri(&foo);
        store
            .update(&format!("DROP SILENT GRAPH <{iri}>; DROP SILENT GRAPH <{sys}>"))
            .await
            .unwrap();
        assert!(!exists(&store, &foo).await.unwrap());
        assert!(exists(&store, &acl).await.unwrap(), "orphan not staged");

        assert!(
            !delete_subject(&store, &blobs, &foo).await.unwrap(),
            "the subject was already absent, so the answer is false"
        );

        assert!(!exists(&store, &acl).await.unwrap(), "orphan survived");
        assert!(
            graph_contents(&store, acl.graph_iri()).await.is_empty(),
            "orphan kept its triples"
        );
        assert!(
            graph_contents(&store, &sys_graph_iri(&acl)).await.is_empty(),
            "orphan kept its presence marker"
        );
    }

    // Whole-branch review, finding 1: `delete_subject` dropped the resource
    // graph and the registry that pointed at its shelves, but never the
    // shelves themselves — a DELETE that erased the registry's only record of
    // them without erasing the data (design spec §7). Every assertion above
    // reads back through `exists`/`get_rdf`, which the deleted registry makes
    // report "gone" either way, so none of them could have caught this. This
    // one derives the shelf's IRI the same way the write path did — through
    // `ShelfKey::of` — and probes the store directly, bypassing the registry
    // entirely.
    #[tokio::test]
    async fn deleting_a_subject_empties_its_shelves_too() {
        let store = OxigraphStore::in_memory().unwrap();
        let blobs = crate::blob::ObjectStoreBlobs::in_memory();
        let r = res("/c/notes");
        let ttl = Format::from_content_type("text/turtle").unwrap();
        let g = oxigraph::model::NamedNode::new("urn:example:g1").unwrap();
        let ds = crate::dataset::Skolemized::new(vec![crate::dataset::GroundQuad::new(
            oxigraph::model::NamedNode::new("http://example.org/alice").unwrap(),
            oxigraph::model::NamedNode::new("http://schema.org/name").unwrap(),
            oxigraph::model::Literal::new_simple_literal("Alice"),
            g.clone(),
        )]);
        put_dataset(&store, &blobs, &r, &ds, ttl).await.unwrap();
        let key = ShelfKey::of(&r, g.as_ref());

        assert!(delete_subject(&store, &blobs, &r).await.unwrap(), "existed");

        let leftover = graph_contents(&store, key.graph_iri()).await;
        assert!(
            leftover.is_empty(),
            "delete_subject must drop the shelf graph itself, not just the registry that pointed at it"
        );
        assert!(get_dataset(&store, &r).await.unwrap().is_none());
        assert!(registered_shelves(&store, &r).await.unwrap().is_empty());
    }

    // §7: there is one delete cascade, and the blob goes with it. Asserted
    // against the BlobStore, not against a 404 from a read path.
    #[tokio::test]
    async fn the_delete_cascade_takes_the_blob_with_it() {
        let store = OxigraphStore::in_memory().unwrap();
        let blobs = crate::blob::ObjectStoreBlobs::in_memory();
        let r = res("/photo");
        let key = crate::blob::BlobKey::of(&r).unwrap();

        crate::resource::put_blob(
            &store, &blobs, &r, bytes::Bytes::from_static(b"x"),
            &crate::rdf::MediaType::parse("image/png").unwrap(),
        ).await.unwrap();

        assert!(delete_subject(&store, &blobs, &r).await.unwrap());
        assert!(!crate::resource::exists(&store, &r).await.unwrap());
        assert!(crate::blob::BlobStore::get(&blobs, &key).await.unwrap().is_none());
    }

    // The cascade is correct for a resource that never had a blob, and it
    // must not report failure for one — `delete` on an absent key succeeds.
    #[tokio::test]
    async fn the_cascade_still_works_for_an_rdf_resource() {
        let store = OxigraphStore::in_memory().unwrap();
        let blobs = crate::blob::ObjectStoreBlobs::in_memory();
        let r = res("/notes");
        crate::resource::put_rdf(&store, &r, &[]).await.unwrap();
        assert!(delete_subject(&store, &blobs, &r).await.unwrap());
    }
}
