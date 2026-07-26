//! The enforcement point: one call handlers make before touching the store.
//!
//! Fails closed in every direction — a missing ACL, a store error, or an
//! unroutable path all deny. The only path to `Ok(())` is an ACL that
//! explicitly grants the requested mode to this agent.

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::{auth::Agent, space::StorageSpace, store::SparqlStore};

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

/// May `agent` perform `mode` on `request_path`?
///
/// A request for an ACL resource (`<res>.acl`) is rewritten: the decision is
/// made against `<res>` and always requires `acl:Control`, whatever `mode`
/// the handler asked for. That rewrite lives here rather than in the
/// handlers so no handler can forget it.
pub async fn authorize(
    store: &dyn SparqlStore,
    space: &StorageSpace,
    agent: &Agent,
    request_path: &str,
    mode: Mode,
) -> Result<(), Response> {
    let (target, required) = if prp::is_acl_path(request_path) {
        (prp::acl_subject_path(request_path), Mode::Control)
    } else {
        (request_path.to_string(), mode)
    };

    let acl = match prp::effective_acl(store, space, &target).await {
        Ok(Some(acl)) => acl,
        Ok(None) => return Err(deny(agent)),
        Err(crate::resource::ResourceError::InvalidIri) => {
            return Err(StatusCode::BAD_REQUEST.into_response())
        }
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()),
    };

    if pdp::decide(&acl.triples, agent, &acl.governed_iri, acl.inherited).allows(required) {
        Ok(())
    } else {
        Err(deny(agent))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wac::pdp::{ACL_ACCESS_TO, ACL_AGENT, ACL_CONTROL, ACL_MODE, ACL_READ};
    use crate::{rdf, resource::put_rdf, store::OxigraphStore};
    use oxigraph::io::RdfFormat;

    const ALICE: &str = "https://alice.example/card#me";

    fn sp() -> StorageSpace { StorageSpace::new("https://pod.toph.so/").unwrap() }
    fn alice() -> Agent { Agent::WebId(ALICE.to_string()) }

    async fn write_acl(store: &OxigraphStore, path: &str, turtle: &str) {
        let base = sp().graph_iri(path).unwrap();
        let t = rdf::parse(turtle.as_bytes(), RdfFormat::Turtle, &base).unwrap();
        put_rdf(store, &sp(), path, &t).await.unwrap();
    }

    fn status(r: Result<(), Response>) -> Option<StatusCode> {
        r.err().map(|res| res.status())
    }

    #[tokio::test]
    async fn granted_mode_is_allowed() {
        let store = OxigraphStore::in_memory().unwrap();
        write_acl(&store, "/foo.acl", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/foo> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        assert!(authorize(&store, &sp(), &alice(), "/foo", Mode::Read).await.is_ok());
    }

    #[tokio::test]
    async fn missing_mode_denies_authenticated_agent_with_403() {
        let store = OxigraphStore::in_memory().unwrap();
        write_acl(&store, "/foo.acl", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/foo> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        assert_eq!(
            status(authorize(&store, &sp(), &alice(), "/foo", Mode::Write).await),
            Some(StatusCode::FORBIDDEN)
        );
    }

    #[tokio::test]
    async fn public_denial_is_401_with_a_challenge() {
        let store = OxigraphStore::in_memory().unwrap();
        write_acl(&store, "/foo.acl", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/foo> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        let res = authorize(&store, &sp(), &Agent::Public, "/foo", Mode::Read).await
            .expect_err("denied");
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        assert!(res.headers().get(header::WWW_AUTHENTICATE).is_some());
    }

    // No ACL anywhere = no grant. WAC has no implicit allow.
    #[tokio::test]
    async fn no_acl_anywhere_denies() {
        let store = OxigraphStore::in_memory().unwrap();
        assert_eq!(
            status(authorize(&store, &sp(), &alice(), "/foo", Mode::Read).await),
            Some(StatusCode::FORBIDDEN)
        );
    }

    // Reading an ACL needs Control on the governed resource — Read on the
    // resource is explicitly NOT enough, or every reader could see who else
    // has access.
    #[tokio::test]
    async fn acl_access_requires_control_not_read() {
        let store = OxigraphStore::in_memory().unwrap();
        write_acl(&store, "/foo.acl", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/foo> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        )).await;
        assert_eq!(
            status(authorize(&store, &sp(), &alice(), "/foo.acl", Mode::Read).await),
            Some(StatusCode::FORBIDDEN)
        );
    }

    #[tokio::test]
    async fn control_grants_acl_access() {
        let store = OxigraphStore::in_memory().unwrap();
        write_acl(&store, "/foo.acl", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/foo> ; \
             <{ACL_MODE}> <{ACL_CONTROL}> ."
        )).await;
        assert!(authorize(&store, &sp(), &alice(), "/foo.acl", Mode::Read).await.is_ok());
        assert!(authorize(&store, &sp(), &alice(), "/foo.acl", Mode::Write).await.is_ok());
    }

    // Write subsumes Append, so a writer may POST into a container.
    #[tokio::test]
    async fn write_satisfies_an_append_requirement() {
        let store = OxigraphStore::in_memory().unwrap();
        write_acl(&store, "/box/.acl", &format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/box/> ; \
             <{ACL_MODE}> <http://www.w3.org/ns/auth/acl#Write> ."
        )).await;
        assert!(authorize(&store, &sp(), &alice(), "/box/", Mode::Append).await.is_ok());
    }
}
