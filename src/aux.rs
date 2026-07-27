//! Auxiliary-resource lifecycle.
//!
//! An auxiliary is not an independently creatable object: it exists only for
//! an existing subject, and it dies with that subject. Both rules live here,
//! in the only functions that can write or delete one, so no handler can
//! implement half of them.

use oxigraph::model::Triple;
use thiserror::Error;

use crate::{
    resource::{exists, put_rdf, sys_graph_iri, ResourceError},
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

/// Write an auxiliary resource. Fails when its subject does not exist —
/// otherwise a policy document could be planted on a path that was never
/// created, where nearest-ACL-wins would make it permanent and unremovable.
pub async fn put(
    store: &dyn SparqlStore,
    aux: &AuxUrl,
    triples: &[Triple],
) -> Result<(), AuxError> {
    if !exists(store, aux.subject()).await? {
        return Err(AuxError::SubjectMissing);
    }
    put_rdf(store, aux, triples).await?;
    Ok(())
}

/// Delete a subject resource together with every auxiliary it may have, in a
/// single store update. Returns whether the subject existed.
pub async fn delete_subject(
    store: &dyn SparqlStore,
    subject: &ResourceUrl,
) -> Result<bool, ResourceError> {
    if !exists(store, subject).await? {
        return Ok(false);
    }
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
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{resource::{exists, get_rdf, put_rdf}, space::{AuxKind, StorageSpace, Target}, store::OxigraphStore};

    fn sp() -> StorageSpace { StorageSpace::new("https://pod.toph.so/").unwrap() }

    fn res(path: &str) -> crate::space::ResourceUrl {
        match sp().resolve(path).unwrap() {
            Target::Resource(r) => r,
            Target::Container(c) => c.as_resource().clone(),
            Target::Aux(_) => panic!("not a resource path"),
        }
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
        put_rdf(&store, &foo, &[]).await.unwrap();
        put(&store, &foo.aux(AuxKind::Acl), &[]).await.unwrap();
        assert!(exists(&store, &foo.aux(AuxKind::Acl)).await.unwrap());
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
            put(&store, &foo.aux(*kind), &[]).await.unwrap();
        }

        assert!(delete_subject(&store, &foo).await.unwrap());

        assert!(!exists(&store, &foo).await.unwrap());
        for kind in AuxKind::ALL {
            assert!(
                !exists(&store, &foo.aux(*kind)).await.unwrap(),
                "auxiliary {kind:?} outlived its subject"
            );
            assert_eq!(get_rdf(&store, &foo.aux(*kind)).await.unwrap(), None);
        }
    }

    #[tokio::test]
    async fn deleting_an_absent_subject_reports_absence() {
        let store = OxigraphStore::in_memory().unwrap();
        assert!(!delete_subject(&store, &res("/nope")).await.unwrap());
    }
}
