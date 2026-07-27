//! Auxiliary-resource lifecycle.
//!
//! An auxiliary is not an independently creatable object: it exists only for
//! an existing subject, and it dies with that subject. Both rules live here,
//! in the only functions that can write or delete one, so no handler can
//! implement half of them.

use oxigraph::model::Triple;
use thiserror::Error;

use crate::{
    resource::{exists, serialize_for_insert, sys_graph_iri, ResourceError, SYS_PRESENT},
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
fn conditional_put_update(aux: &AuxUrl, triples: &[Triple]) -> String {
    let iri = aux.graph_iri();
    let sys = sys_graph_iri(aux);
    let subject_iri = aux.subject().graph_iri();
    let subject_sys = sys_graph_iri(aux.subject());
    let guard = format!(
        "FILTER EXISTS {{ GRAPH <{subject_sys}> {{ <{subject_iri}> <{SYS_PRESENT}> true }} }}"
    );
    let body = serialize_for_insert(triples);
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
/// *after* the update on purpose: if the subject is deleted mid-flight the
/// guard suppresses the write and this reports `SubjectMissing`, so the
/// caller answers 404 rather than `Ok(())` for an ACL that was never stored.
/// Claiming success for an unwritten policy document is the dangerous
/// direction — the client would believe the path is protected.
pub async fn put(
    store: &dyn SparqlStore,
    aux: &AuxUrl,
    triples: &[Triple],
) -> Result<(), AuxError> {
    store
        .update(&conditional_put_update(aux, triples))
        .await
        .map_err(ResourceError::from)?;
    if !exists(store, aux.subject()).await? {
        return Err(AuxError::SubjectMissing);
    }
    Ok(())
}

/// Delete a subject resource together with every auxiliary it may have, in a
/// single store update. Returns whether the subject existed.
///
/// The drops run unconditionally — they are `DROP SILENT`, a no-op on an
/// absent graph — and the existence check only decides the returned boolean.
/// An early return on `!exists` would leave an already-orphaned auxiliary in
/// place and unreported, and since this is the only cascade path that orphan
/// would be permanent: recreating the subject would resurrect its grants.
/// Same reasoning as [`crate::resource::delete_rdf`].
///
/// Graphs only. Callers remain responsible for containment: the subject's
/// membership triple in its parent, and for a container subject its children,
/// are `container`'s business, not this function's.
pub async fn delete_subject(
    store: &dyn SparqlStore,
    subject: &ResourceUrl,
) -> Result<bool, ResourceError> {
    let existed = exists(store, subject).await?;
    let mut drops = vec![
        format!("DROP SILENT GRAPH <{}>", subject.graph_iri()),
        format!("DROP SILENT GRAPH <{}>", sys_graph_iri(subject)),
    ];
    for kind in AuxKind::ALL {
        let aux = subject.aux(*kind);
        drops.push(format!("DROP SILENT GRAPH <{}>", aux.graph_iri()));
        drops.push(format!("DROP SILENT GRAPH <{}>", sys_graph_iri(&aux)));
    }
    store.update(&drops.join("; ")).await?;
    Ok(existed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{rdf, resource::{exists, get_rdf, put_rdf}, space::{AuxKind, StorageSpace, Target}, store::OxigraphStore};
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
        let foo = res("/foo");
        put_rdf(&store, &foo, &[]).await.unwrap();
        for kind in AuxKind::ALL {
            let aux = foo.aux(*kind);
            put(&store, &aux, &grant(&aux)).await.unwrap();
            assert_eq!(get_rdf(&store, &aux).await.unwrap(), Some(grant(&aux)));
        }

        assert!(delete_subject(&store, &foo).await.unwrap());

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
        assert!(!delete_subject(&store, &res("/nope")).await.unwrap());
    }

    // Finding 1b/3: the asymmetric state — auxiliaries present, subject not.
    // An early return on `!exists` would leave this orphan in place, and as
    // the only cascade path that would make it permanent: nearest-ACL-wins
    // would hand the recreated path a policy nobody can remove.
    #[tokio::test]
    async fn an_orphaned_auxiliary_is_removed_even_though_the_subject_is_gone() {
        let store = OxigraphStore::in_memory().unwrap();
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
            !delete_subject(&store, &foo).await.unwrap(),
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
}
