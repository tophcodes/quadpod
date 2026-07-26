//! Bootstrap of the root ACL.
//!
//! WAC has no implicit grants: with no ACL anywhere, the PRP walk terminates
//! empty and every request is denied — including the owner's, which would
//! make a fresh pod unusable. Provisioning writes the one authorization that
//! makes the pod owner's own pod reachable.
//!
//! There is deliberately no owner bypass in `super::guard`: after this runs,
//! the ACL alone decides. An owner who deletes their own `acl:Control` rule
//! locks themselves out, exactly as on CSS/ESS.

use oxigraph::model::NamedNode;

use crate::{
    container::RDF_TYPE,
    resource::{get_rdf, ResourceError},
    space::StorageSpace,
    store::SparqlStore,
};

use super::pdp::{
    ACL_ACCESS_TO, ACL_AGENT, ACL_AUTHORIZATION, ACL_CONTROL, ACL_DEFAULT, ACL_MODE, ACL_READ,
    ACL_WRITE,
};

/// Write the root ACL granting `owner_webid` Read/Write/Control over the
/// whole pod, unless `/.acl` already has content. Idempotent, and safe to
/// call on every start.
pub async fn provision_root_acl(
    store: &dyn SparqlStore,
    space: &StorageSpace,
    owner_webid: &str,
) -> Result<(), ResourceError> {
    // Validated because it is interpolated into SPARQL below.
    NamedNode::new(owner_webid).map_err(|_| ResourceError::InvalidIri)?;

    if get_rdf(store, space, "/.acl").await?.is_some() {
        return Ok(());
    }
    let acl_graph = space.graph_iri("/.acl")?;
    let root = space.graph_iri("/")?;
    let subject = format!("{acl_graph}#owner");
    NamedNode::new(&subject).map_err(|_| ResourceError::InvalidIri)?;

    store
        .update(&format!(
            "INSERT DATA {{ GRAPH <{acl_graph}> {{ \
             <{subject}> <{RDF_TYPE}> <{ACL_AUTHORIZATION}> . \
             <{subject}> <{ACL_AGENT}> <{owner_webid}> . \
             <{subject}> <{ACL_ACCESS_TO}> <{root}> . \
             <{subject}> <{ACL_DEFAULT}> <{root}> . \
             <{subject}> <{ACL_MODE}> <{ACL_READ}> . \
             <{subject}> <{ACL_MODE}> <{ACL_WRITE}> . \
             <{subject}> <{ACL_MODE}> <{ACL_CONTROL}> }} }}"
        ))
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wac::pdp::{decide, ACL_AGENT_CLASS, FOAF_AGENT};
    use crate::wac::Mode;
    use crate::{auth::Agent, store::OxigraphStore, wac::prp::effective_acl};

    const OWNER: &str = "https://alice.example/card#me";

    fn sp() -> StorageSpace { StorageSpace::new("https://pod.toph.so/").unwrap() }

    #[tokio::test]
    async fn provisioned_root_acl_grants_the_owner_full_control() {
        let store = OxigraphStore::in_memory().unwrap();
        provision_root_acl(&store, &sp(), OWNER).await.unwrap();

        let acl = effective_acl(&store, &sp(), "/").await.unwrap().expect("root acl");
        let owner = Agent::WebId(OWNER.to_string());
        let direct = decide(&acl.triples, &owner, &acl.governed_iri, acl.inherited);
        assert!(direct.allows(Mode::Read));
        assert!(direct.allows(Mode::Write));
        assert!(direct.allows(Mode::Control));
    }

    // acl:default is what makes the root ACL the fallback for the whole pod.
    #[tokio::test]
    async fn provisioned_root_acl_is_inherited_by_descendants() {
        let store = OxigraphStore::in_memory().unwrap();
        provision_root_acl(&store, &sp(), OWNER).await.unwrap();

        let acl = effective_acl(&store, &sp(), "/a/b/c").await.unwrap().expect("inherited");
        assert!(acl.inherited);
        let m = decide(&acl.triples, &Agent::WebId(OWNER.to_string()), &acl.governed_iri, true);
        assert!(m.allows(Mode::Write));
    }

    #[tokio::test]
    async fn nobody_else_gets_anything_from_the_default_root_acl() {
        let store = OxigraphStore::in_memory().unwrap();
        provision_root_acl(&store, &sp(), OWNER).await.unwrap();

        let acl = effective_acl(&store, &sp(), "/foo").await.unwrap().expect("inherited");
        let stranger = Agent::WebId("https://bob.example/card#me".to_string());
        assert!(!decide(&acl.triples, &stranger, &acl.governed_iri, true).allows(Mode::Read));
        assert!(!decide(&acl.triples, &Agent::Public, &acl.governed_iri, true).allows(Mode::Read));
    }

    // Restarting the server must never roll back shares the owner made.
    #[tokio::test]
    async fn existing_root_acl_is_never_overwritten() {
        let store = OxigraphStore::in_memory().unwrap();
        provision_root_acl(&store, &sp(), OWNER).await.unwrap();
        // simulate the owner editing their ACL: grant the public read
        let g = sp().graph_iri("/.acl").unwrap();
        store.update(&format!(
            "INSERT DATA {{ GRAPH <{g}> {{ <{g}#public> \
             <{ACL_AGENT_CLASS}> <{FOAF_AGENT}> ; \
             <{ACL_DEFAULT}> <https://pod.toph.so/> ; \
             <{ACL_MODE}> <{ACL_READ}> }} }}"
        )).await.unwrap();

        provision_root_acl(&store, &sp(), OWNER).await.unwrap(); // restart

        let acl = effective_acl(&store, &sp(), "/foo").await.unwrap().expect("acl");
        assert!(decide(&acl.triples, &Agent::Public, &acl.governed_iri, true).allows(Mode::Read),
            "the owner's edit must survive re-provisioning");
    }

    // The WebID is interpolated into SPARQL; an unvalidated one would be an
    // injection vector (the Plan-1 lesson).
    #[tokio::test]
    async fn non_iri_owner_is_rejected_not_interpolated() {
        let store = OxigraphStore::in_memory().unwrap();
        let err = provision_root_acl(&store, &sp(), "not an iri> } ; DROP ALL ; #").await;
        assert!(matches!(err, Err(ResourceError::InvalidIri)));
        assert!(effective_acl(&store, &sp(), "/").await.unwrap().is_none());
    }
}
