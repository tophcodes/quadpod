//! Bootstrap of the root ACL.
//!
//! WAC has no implicit grants: with no ACL anywhere, the PRP walk terminates
//! empty and every request is denied — including the owner's, which would
//! make a fresh pod unusable. Provisioning writes the one authorization that
//! makes the pod owner's own pod reachable.
//!
//! There is deliberately no owner bypass in `super::guard`: after this runs,
//! the ACL alone decides. An owner who deletes their own `acl:Control` rule
//! locks themselves out, exactly as on CSS/ESS. An *emptied* (rather than
//! deleted) root ACL is worse: existence is a stored marker independent of
//! triple count (see `resource::exists`), so an empty ACL still exists, still
//! wins over the ancestor fallback it would otherwise have, and grants
//! Control to nobody — not even the owner. `DELETE /.aux/.acl` needs Control
//! on `/`, which that same empty ACL just revoked from everyone, so there is
//! no HTTP route back and restarting the server does not re-provision either:
//! the existence check below is what makes provisioning idempotent, and it
//! cannot distinguish "empty on purpose" from "never written". The `reset`
//! flag is the deliberate, out-of-band escape hatch for exactly this: an
//! operator who can restart the process with `--reset-root-acl` (or
//! `POD_RESET_ROOT_ACL`) can get back in without ever going through HTTP
//! authorization at all.

use oxigraph::model::{NamedNode, Triple};

use crate::{
    aux::{self, AuxError},
    container::ensure_container,
    rdf::Format,
    resource::{exists, ResourceError},
    space::{AuxKind, GraphName, StorageSpace},
    store::SparqlStore,
};

use super::pdp::{
    ACL_ACCESS_TO, ACL_AGENT, ACL_AUTHORIZATION, ACL_CONTROL, ACL_DEFAULT, ACL_MODE, ACL_READ,
    ACL_WRITE,
};

/// Write the root ACL granting `owner_webid` Read/Write/Control over the
/// whole pod, unless the root's ACL auxiliary already exists and `reset` is
/// `false`. Idempotent when `reset` is `false`, and safe to call on every
/// start.
///
/// `reset` is the `--reset-root-acl` / `POD_RESET_ROOT_ACL` operator escape
/// hatch (see the module docs): when set, it overwrites whatever is there,
/// existing or not — the one way back from a root ACL that grants Control to
/// nobody. Threaded in as a plain parameter rather than read from `Config`
/// here, so this function has exactly one place — its caller — that decides
/// whether a reset was asked for.
///
/// `aux::put` refuses to write an auxiliary whose subject does not exist, and
/// the root ACL's subject is the root container — so this ensures the root
/// container first rather than trusting the caller to have done so. `main.rs`
/// already calls `provision_root` before this, but a caller that got the
/// order wrong must not silently produce an unreachable pod.
pub async fn provision_root_acl(
    store: &dyn SparqlStore,
    space: &StorageSpace,
    owner_webid: &str,
    reset: bool,
) -> Result<(), ResourceError> {
    // Validated because it is interpolated into Turtle below.
    NamedNode::new(owner_webid).map_err(|_| ResourceError::InvalidIri)?;

    let root = space.root();
    let acl = root.as_resource().aux(AuxKind::Acl);
    if exists(store, &acl).await? && !reset {
        return Ok(());
    }

    ensure_container(store, &root).await?;

    let root_iri = root.graph_iri();
    let turtle = format!(
        "<#owner> a <{ACL_AUTHORIZATION}> ; \
         <{ACL_AGENT}> <{owner_webid}> ; \
         <{ACL_ACCESS_TO}> <{root_iri}> ; \
         <{ACL_DEFAULT}> <{root_iri}> ; \
         <{ACL_MODE}> <{ACL_READ}>, <{ACL_WRITE}>, <{ACL_CONTROL}> ."
    );
    let dataset = Format::from_content_type("text/turtle")
        .expect("text/turtle is always supported")
        .parse(turtle.as_bytes(), acl.graph_iri())?;
    let triples: Vec<Triple> = dataset.quads().iter().cloned().map(Triple::from).collect();

    match aux::put(store, &acl, &triples).await {
        Ok(()) => Ok(()),
        Err(AuxError::Resource(e)) => Err(e),
        // Unreachable: the root container was just ensured to exist above,
        // and provisioning runs at startup, not concurrently with a delete.
        Err(AuxError::SubjectMissing) => {
            unreachable!("the root container was just ensured to exist")
        }
        // Unreachable by construction: `put` writes the auxiliary, so it never
        // asks for one that is already there.
        Err(AuxError::Missing) => unreachable!("put does not require an existing auxiliary"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wac::pdp::{decide, ACL_AGENT_CLASS, FOAF_AGENT};
    use crate::wac::Mode;
    use crate::{
        auth::Agent,
        space::{ResourceUrl, Target},
        store::OxigraphStore,
        wac::prp::effective_acl,
    };

    const OWNER: &str = "https://alice.example/card#me";

    fn sp() -> StorageSpace { StorageSpace::new("https://pod.toph.so/").unwrap() }

    fn res(path: &str) -> ResourceUrl {
        match sp().resolve(path).unwrap() {
            Target::Resource(r) => r,
            Target::Container(c) => c.as_resource().clone(),
            Target::Aux(_) => panic!("not a resource path"),
        }
    }

    #[tokio::test]
    async fn provisioned_root_acl_grants_the_owner_full_control() {
        let store = OxigraphStore::in_memory().unwrap();
        provision_root_acl(&store, &sp(), OWNER, false).await.unwrap();

        let acl = effective_acl(&store, sp().root().as_resource()).await.unwrap().expect("root acl");
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
        provision_root_acl(&store, &sp(), OWNER, false).await.unwrap();

        let acl = effective_acl(&store, &res("/a/b/c")).await.unwrap().expect("inherited");
        assert!(acl.inherited);
        let m = decide(&acl.triples, &Agent::WebId(OWNER.to_string()), &acl.governed_iri, true);
        assert!(m.allows(Mode::Write));
    }

    #[tokio::test]
    async fn nobody_else_gets_anything_from_the_default_root_acl() {
        let store = OxigraphStore::in_memory().unwrap();
        provision_root_acl(&store, &sp(), OWNER, false).await.unwrap();

        let acl = effective_acl(&store, &res("/foo")).await.unwrap().expect("inherited");
        let stranger = Agent::WebId("https://bob.example/card#me".to_string());
        let stranger_decision = decide(&acl.triples, &stranger, &acl.governed_iri, true);
        assert!(!stranger_decision.allows(Mode::Read));
        assert!(!stranger_decision.allows(Mode::Write));
        assert!(!stranger_decision.allows(Mode::Append));
        assert!(!stranger_decision.allows(Mode::Control));

        let public_decision = decide(&acl.triples, &Agent::Public, &acl.governed_iri, true);
        assert!(!public_decision.allows(Mode::Read));
        assert!(!public_decision.allows(Mode::Write));
        assert!(!public_decision.allows(Mode::Append));
        assert!(!public_decision.allows(Mode::Control));
    }

    // Restarting the server must never roll back shares the owner made.
    #[tokio::test]
    async fn existing_root_acl_is_never_overwritten() {
        let store = OxigraphStore::in_memory().unwrap();
        provision_root_acl(&store, &sp(), OWNER, false).await.unwrap();
        // simulate the owner editing their ACL: grant the public read
        let g = sp().root().as_resource().aux(AuxKind::Acl).graph_iri().to_string();
        store.update(&format!(
            "INSERT DATA {{ GRAPH <{g}> {{ <{g}#public> \
             <{ACL_AGENT_CLASS}> <{FOAF_AGENT}> ; \
             <{ACL_DEFAULT}> <https://pod.toph.so/> ; \
             <{ACL_MODE}> <{ACL_READ}> }} }}"
        )).await.unwrap();

        provision_root_acl(&store, &sp(), OWNER, false).await.unwrap(); // restart

        let acl = effective_acl(&store, &res("/foo")).await.unwrap().expect("acl");
        assert!(decide(&acl.triples, &Agent::Public, &acl.governed_iri, true).allows(Mode::Read),
            "the owner's edit must survive re-provisioning");
    }

    // Finding 1b. The scenario the flag exists for: an emptied root ACL
    // still exists (existence is a stored marker, not a triple count), so it
    // still wins over the fallback it would otherwise provide and grants
    // Control to nobody, not even the owner — there is no HTTP route back.
    // `reset: true` is the only thing that gets the owner's grant back.
    #[tokio::test]
    async fn reset_flag_overwrites_an_emptied_root_acl() {
        let store = OxigraphStore::in_memory().unwrap();
        provision_root_acl(&store, &sp(), OWNER, false).await.unwrap();
        // simulate an emptied root ACL: DELETE WHERE with no restriction on
        // the subject removes every triple but leaves the presence marker
        // (and thus `exists`) untouched, exactly as `aux::put` with an empty
        // body does over HTTP.
        let g = sp().root().as_resource().aux(AuxKind::Acl).graph_iri().to_string();
        store.update(&format!("DELETE WHERE {{ GRAPH <{g}> {{ ?s ?p ?o }} }}")).await.unwrap();

        // Without the flag, the owner stays locked out — this is the bug the
        // flag exists to escape, pinned here so the counterweight below means
        // something.
        provision_root_acl(&store, &sp(), OWNER, false).await.unwrap(); // restart, no flag
        let acl = effective_acl(&store, sp().root().as_resource()).await.unwrap().expect("acl");
        let m = decide(&acl.triples, &Agent::WebId(OWNER.to_string()), &acl.governed_iri, acl.inherited);
        assert!(!m.allows(Mode::Control), "an emptied ACL must stay empty without the flag");

        provision_root_acl(&store, &sp(), OWNER, true).await.unwrap(); // restart --reset-root-acl

        let acl = effective_acl(&store, sp().root().as_resource()).await.unwrap().expect("acl");
        let m = decide(&acl.triples, &Agent::WebId(OWNER.to_string()), &acl.governed_iri, acl.inherited);
        assert!(m.allows(Mode::Read), "the flag must restore the owner's Read");
        assert!(m.allows(Mode::Write), "the flag must restore the owner's Write");
        assert!(m.allows(Mode::Control), "the flag must restore the owner's Control");
    }

    // The existence guard is what makes ownership transfer and deliberate
    // self-lockout stick: without it every restart would resurrect the
    // owner's authorization. INSERT DATA is additive, so only a test that
    // REMOVES the owner rule can prove the guard does anything at all.
    #[tokio::test]
    async fn provisioning_does_not_resurrect_a_removed_owner_rule() {
        let store = OxigraphStore::in_memory().unwrap();
        provision_root_acl(&store, &sp(), OWNER, false).await.unwrap();
        let g = sp().root().as_resource().aux(AuxKind::Acl).graph_iri().to_string();
        // the owner hands control to a successor, then removes their own rule
        store.update(&format!(
            "INSERT DATA {{ GRAPH <{g}> {{ <{g}#successor> \
             <{ACL_AGENT}> <https://carol.example/card#me> ; \
             <{ACL_DEFAULT}> <https://pod.toph.so/> ; \
             <{ACL_MODE}> <{ACL_CONTROL}> }} }}"
        )).await.unwrap();
        store.update(&format!(
            "DELETE WHERE {{ GRAPH <{g}> {{ <{g}#owner> ?p ?o }} }}"
        )).await.unwrap();

        provision_root_acl(&store, &sp(), OWNER, false).await.unwrap(); // restart

        let acl = effective_acl(&store, sp().root().as_resource()).await.unwrap().expect("acl");
        let m = decide(&acl.triples, &Agent::WebId(OWNER.to_string()), &acl.governed_iri, acl.inherited);
        assert!(!m.allows(Mode::Control), "a removed owner rule must not be re-provisioned");
        assert!(!m.allows(Mode::Read));
        assert!(!m.allows(Mode::Write));
    }

    // The WebID is interpolated into SPARQL; an unvalidated one would be an
    // injection vector (the Plan-1 lesson).
    #[tokio::test]
    async fn non_iri_owner_is_rejected_not_interpolated() {
        let store = OxigraphStore::in_memory().unwrap();
        let err = provision_root_acl(&store, &sp(), "not an iri> } ; DROP ALL ; #", false).await;
        assert!(matches!(err, Err(ResourceError::InvalidIri)));
        assert!(effective_acl(&store, sp().root().as_resource()).await.unwrap().is_none());
    }
}
