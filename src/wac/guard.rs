//! The enforcement point: one call handlers make before touching the store.
//!
//! Fails closed in every direction — a missing ACL, a store error, or an
//! unroutable path all deny. The only path to `Ok(())` is an ACL that
//! explicitly grants the requested mode to this agent.

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::{
    auth::Agent,
    container,
    resource,
    space::{ContainerUrl, GraphName, ResourceUrl, Target},
    store::SparqlStore,
};

use super::{pdp, prp, Mode};

/// The challenge sent with a 401, telling a client which credential the pod
/// accepts. `Bearer` is deliberately absent: Plan 4 verifies DPoP-bound
/// tokens only.
const DPOP_CHALLENGE: &str = "DPoP algs=\"ES256\"";

/// Deny in the way that tells the caller the truth without leaking anything:
/// an anonymous caller learns that credentials would help (401), a verified
/// one that theirs are insufficient (403). Neither learns whether the
/// resource exists — `authorize` runs before any existence check.
fn deny(agent: &Agent) -> Response {
    match agent {
        Agent::Public => (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, DPOP_CHALLENGE)],
        )
            .into_response(),
        Agent::WebId(_) => StatusCode::FORBIDDEN.into_response(),
    }
}

/// May `agent` perform `mode` on `target`?
///
/// An auxiliary is decided against its subject and always requires
/// `acl:Control`, whatever `mode` the handler asked for. That rewrite lives
/// here rather than in the handlers so no handler can forget it — and it is
/// now the type that carries the subject, so there is nothing left to derive
/// from a string.
pub async fn authorize(
    store: &dyn SparqlStore,
    agent: &Agent,
    target: &Target,
    mode: Mode,
) -> Result<(), Response> {
    let (subject, required) = match target {
        Target::Aux(a) => (a.subject().clone(), Mode::Control),
        Target::Resource(r) => (r.clone(), mode),
        Target::Container(c) => (c.as_resource().clone(), mode),
    };

    let acl = match prp::effective_acl(store, &subject).await {
        Ok(Some(acl)) => acl,
        Ok(None) => return Err(deny(agent)),
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()),
    };

    if pdp::decide(&acl.triples, agent, &acl.governed_iri, acl.inherited).allows(required) {
        Ok(())
    } else {
        Err(deny(agent))
    }
}

/// Authorize and perform the container materialization a write implies —
/// from one traversal.
///
/// A level is written iff it is created, or it is the first already-existing
/// ancestor (which gains a containment triple). Those are exactly the levels
/// this walk authorizes `Append` on, and it stops there: above that point the
/// inserts are no-ops, and demanding rights there would break the
/// append-only inbox pattern. An auxiliary is never a container member, so a
/// write to one adds no containment — only the containers it would create
/// count.
///
/// The walk decides the whole chain before it writes any of it. A denial
/// halfway up must leave the store exactly as it found it: interleaving the
/// two would let an agent authorized only *below* a container create a fresh
/// subtree there and then be refused, leaving containers they were never
/// allowed to make. Two loops, one derivation — the plan the second loop
/// applies is the plan the first one authorized, level for level.
pub async fn authorize_and_materialize(
    store: &dyn SparqlStore,
    agent: &Agent,
    target: &Target,
) -> Result<(), Response> {
    let (subject, is_member): (&ResourceUrl, bool) = match target {
        Target::Resource(r) => (r, true),
        Target::Container(c) => (c.as_resource(), true),
        Target::Aux(a) => (a.subject(), false),
    };

    // The IRI to record as a member at the next level up. It starts as the
    // target and becomes each container this walk creates.
    let mut child_iri = target.graph_iri().to_string();
    let mut record_child = is_member;
    let mut plan: Vec<(ContainerUrl, Option<String>)> = Vec::new();
    for ancestor in subject.ancestors() {
        let existed = resource::exists(store, &ancestor)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
        if existed && !record_child {
            break; // nothing observable changes at or above this level
        }
        authorize(store, agent, &Target::Container(ancestor.clone()), Mode::Append).await?;
        plan.push((ancestor.clone(), record_child.then(|| child_iri.clone())));
        if existed {
            break;
        }
        child_iri = ancestor.graph_iri().to_string();
        record_child = true;
    }

    for (ancestor, child_iri) in plan {
        container::ensure_container(store, &ancestor)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
        if let Some(child_iri) = child_iri {
            container::add_containment(store, &ancestor, &child_iri)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wac::pdp::{
        ACL_ACCESS_TO, ACL_AGENT, ACL_APPEND, ACL_CONTROL, ACL_DEFAULT, ACL_MODE, ACL_READ,
        ACL_WRITE,
    };
    use crate::{
        rdf,
        space::{AuxKind, StorageSpace},
        store::OxigraphStore,
    };
    use oxigraph::io::RdfFormat;

    const ALICE: &str = "https://alice.example/card#me";
    const BOB: &str = "https://bob.example/card#me";

    fn sp() -> StorageSpace { StorageSpace::new("https://pod.toph.so/").unwrap() }
    fn alice() -> Agent { Agent::WebId(ALICE.to_string()) }
    fn bob() -> Agent { Agent::WebId(BOB.to_string()) }

    fn resource(path: &str) -> ResourceUrl {
        match sp().resolve(path).unwrap() {
            Target::Resource(r) => r,
            Target::Container(c) => c.as_resource().clone(),
            Target::Aux(_) => panic!("not a resource path"),
        }
    }

    fn container(path: &str) -> ContainerUrl {
        match sp().resolve(path).unwrap() {
            Target::Container(c) => c,
            _ => panic!("not a container path"),
        }
    }

    async fn seed_container(store: &OxigraphStore, path: &str) {
        crate::container::ensure_container(store, &container(path)).await.unwrap();
    }

    /// Mark the subject present, then write its ACL. The presence marker goes
    /// in additively: `aux::put` refuses an auxiliary whose subject does not
    /// exist, and seeding a policy must not erase whatever the subject
    /// already holds.
    async fn seed_acl(store: &OxigraphStore, subject_path: &str, turtle: &str) {
        let subject = resource(subject_path);
        crate::resource::insert_marked(store, &subject, &[]).await.unwrap();
        let aux = subject.aux(AuxKind::Acl);
        let t = rdf::parse(turtle.as_bytes(), RdfFormat::Turtle, aux.graph_iri()).unwrap();
        crate::aux::put(store, &aux, &t).await.unwrap();
    }

    fn status(r: Result<(), Response>) -> Option<StatusCode> {
        r.err().map(|res| res.status())
    }

    #[tokio::test]
    async fn granted_mode_is_allowed() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_acl(&store, "/foo", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/foo> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        let target = sp().resolve("/foo").unwrap();
        assert!(authorize(&store, &alice(), &target, Mode::Read).await.is_ok());
    }

    #[tokio::test]
    async fn missing_mode_denies_authenticated_agent_with_403() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_acl(&store, "/foo", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/foo> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        let target = sp().resolve("/foo").unwrap();
        assert_eq!(
            status(authorize(&store, &alice(), &target, Mode::Write).await),
            Some(StatusCode::FORBIDDEN)
        );
    }

    #[tokio::test]
    async fn public_denial_is_401_with_a_challenge() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_acl(&store, "/foo", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/foo> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        let target = sp().resolve("/foo").unwrap();
        let res = authorize(&store, &Agent::Public, &target, Mode::Read).await
            .expect_err("denied");
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        assert!(res.headers().get(header::WWW_AUTHENTICATE).is_some());
    }

    // No ACL anywhere = no grant. WAC has no implicit allow.
    #[tokio::test]
    async fn no_acl_anywhere_denies() {
        let store = OxigraphStore::in_memory().unwrap();
        let target = sp().resolve("/foo").unwrap();
        assert_eq!(
            status(authorize(&store, &alice(), &target, Mode::Read).await),
            Some(StatusCode::FORBIDDEN)
        );
    }

    // Reading an ACL needs Control on the governed resource — Read on the
    // resource is explicitly NOT enough, or every reader could see who else
    // has access.
    #[tokio::test]
    async fn acl_access_requires_control_not_read() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_acl(&store, "/foo", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/foo> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        let target = sp().resolve("/.aux/acl/foo").unwrap();
        assert_eq!(
            status(authorize(&store, &alice(), &target, Mode::Read).await),
            Some(StatusCode::FORBIDDEN)
        );
    }

    #[tokio::test]
    async fn control_grants_acl_access() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_acl(&store, "/foo", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/foo> ; \
             <{ACL_MODE}> <{ACL_CONTROL}> ."
        )).await;
        let target = sp().resolve("/.aux/acl/foo").unwrap();
        assert!(authorize(&store, &alice(), &target, Mode::Read).await.is_ok());
        assert!(authorize(&store, &alice(), &target, Mode::Write).await.is_ok());
    }

    // Write subsumes Append, so a writer may POST into a container.
    #[tokio::test]
    async fn write_satisfies_an_append_requirement() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_acl(&store, "/box/", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/box/> ; \
             <{ACL_MODE}> <{ACL_WRITE}> ."
        )).await;
        let target = sp().resolve("/box/").unwrap();
        assert!(authorize(&store, &alice(), &target, Mode::Append).await.is_ok());
    }

    // One traversal: every level the materialization would write is a level
    // the walk authorized, and it stops where writing stops. Neither half can
    // drift from the other, because there is only one half.
    #[tokio::test]
    async fn materialization_is_authorized_at_every_level_it_writes() {
        let store = OxigraphStore::in_memory().unwrap();
        // Bob may write below /box/ but holds nothing on /box/ itself.
        seed_acl(&store, "/box/", &format!(
            "<#bob> <{ACL_AGENT}> <{BOB}> ; <{ACL_DEFAULT}> <https://pod.toph.so/box/> ; \
             <{ACL_MODE}> <{ACL_WRITE}> ."
        )).await;
        let target = sp().resolve("/box/sub/file").unwrap();
        let res = authorize_and_materialize(&store, &bob(), &target).await;
        assert!(res.is_err(), "creating /box/sub/ mutates /box/, which Bob cannot append to");
        assert!(!crate::resource::exists(&store, &container("/box/sub/")).await.unwrap(),
            "nothing may be materialized when the walk denies");
    }

    #[tokio::test]
    async fn an_existing_parent_costs_exactly_one_check() {
        let store = OxigraphStore::in_memory().unwrap();
        // Bob has Append on /inbox/ itself — the append-only inbox pattern.
        seed_container(&store, "/inbox/").await;
        seed_acl(&store, "/inbox/", &format!(
            "<#bob> <{ACL_AGENT}> <{BOB}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/inbox/> ; \
             <{ACL_MODE}> <{ACL_APPEND}> ."
        )).await;
        let target = sp().resolve("/inbox/note").unwrap();
        assert!(authorize_and_materialize(&store, &bob(), &target).await.is_ok(),
            "an append-only agent must not need rights on the root");
    }

    // An auxiliary is not a container member, so writing one materializes
    // nothing at its parent — but any container it would create still counts.
    #[tokio::test]
    async fn writing_an_auxiliary_under_an_existing_container_needs_nothing_extra() {
        let store = OxigraphStore::in_memory().unwrap();
        seed_container(&store, "/box/").await;
        crate::resource::put_rdf(&store, &resource("/box/doc"), &[]).await.unwrap();
        seed_acl(&store, "/box/", &format!(
            "<#bob> <{ACL_AGENT}> <{BOB}> ; <{ACL_DEFAULT}> <https://pod.toph.so/box/> ; \
             <{ACL_MODE}> <{ACL_CONTROL}> ."
        )).await;
        let target = sp().resolve("/.aux/acl/box/doc").unwrap();
        assert!(authorize_and_materialize(&store, &bob(), &target).await.is_ok(),
            "Control alone must suffice when nothing is materialized");
    }
}
