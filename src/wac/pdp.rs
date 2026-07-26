//! The WAC policy decision point: given the applicable ACL triples, which
//! access modes does this agent hold on the governed resource?
//!
//! Deliberately pure — no store access, no async. Everything I/O-shaped lives
//! in `super::prp`. That split is what makes the decision exhaustively
//! table-testable, and it keeps the choice of decision engine local to this
//! file.

use oxigraph::model::{NamedOrBlankNode, Term, Triple};

use crate::auth::Agent;

use super::AccessModes;
#[cfg(test)]
use super::Mode;

pub const ACL_AGENT: &str = "http://www.w3.org/ns/auth/acl#agent";
pub const ACL_AGENT_CLASS: &str = "http://www.w3.org/ns/auth/acl#agentClass";
pub const ACL_ACCESS_TO: &str = "http://www.w3.org/ns/auth/acl#accessTo";
pub const ACL_DEFAULT: &str = "http://www.w3.org/ns/auth/acl#default";
pub const ACL_MODE: &str = "http://www.w3.org/ns/auth/acl#mode";
pub const ACL_READ: &str = "http://www.w3.org/ns/auth/acl#Read";
pub const ACL_WRITE: &str = "http://www.w3.org/ns/auth/acl#Write";
pub const ACL_APPEND: &str = "http://www.w3.org/ns/auth/acl#Append";
pub const ACL_CONTROL: &str = "http://www.w3.org/ns/auth/acl#Control";
pub const ACL_AUTHENTICATED_AGENT: &str =
    "http://www.w3.org/ns/auth/acl#AuthenticatedAgent";
pub const ACL_AUTHORIZATION: &str = "http://www.w3.org/ns/auth/acl#Authorization";
pub const FOAF_AGENT: &str = "http://xmlns.com/foaf/0.1/Agent";

/// Which modes `agent` holds on `governed_iri`, according to `acl`.
///
/// `inherited` selects the scope predicate: an ACL reached by walking up to a
/// container grants through `acl:default`, one found directly on the resource
/// through `acl:accessTo`. The two never cross over — otherwise a container's
/// own `accessTo` rules would silently apply to every child.
pub fn decide(acl: &[Triple], agent: &Agent, governed_iri: &str, inherited: bool) -> AccessModes {
    let scope_predicate = if inherited { ACL_DEFAULT } else { ACL_ACCESS_TO };
    let mut granted = AccessModes::default();

    for subject in authorization_subjects(acl) {
        if !has_object(acl, &subject, scope_predicate, governed_iri) {
            continue;
        }
        if !matches_agent(acl, &subject, agent) {
            continue;
        }
        for t in acl.iter().filter(|t| t.subject == subject && t.predicate.as_str() == ACL_MODE) {
            if let Term::NamedNode(m) = &t.object {
                match m.as_str() {
                    ACL_READ => granted.read = true,
                    ACL_WRITE => granted.write = true,
                    ACL_APPEND => granted.append = true,
                    ACL_CONTROL => granted.control = true,
                    _ => {}
                }
            }
        }
    }
    granted
}

/// Every distinct subject in the ACL graph. We do not require an explicit
/// `a acl:Authorization` type triple — WAC treats the scope/agent/mode
/// predicates themselves as what makes an authorization, and many real ACLs
/// omit the type.
fn authorization_subjects(acl: &[Triple]) -> Vec<NamedOrBlankNode> {
    let mut out: Vec<NamedOrBlankNode> = Vec::new();
    for t in acl {
        if !out.contains(&t.subject) {
            out.push(t.subject.clone());
        }
    }
    out
}

fn has_object(acl: &[Triple], subject: &NamedOrBlankNode, predicate: &str, object_iri: &str) -> bool {
    acl.iter().any(|t| {
        t.subject == *subject
            && t.predicate.as_str() == predicate
            && matches!(&t.object, Term::NamedNode(n) if n.as_str() == object_iri)
    })
}

/// `acl:agent <webid>` matches that WebID exactly; `acl:agentClass foaf:Agent`
/// matches everyone including the public; `acl:agentClass acl:AuthenticatedAgent`
/// matches any verified WebID but never the public.
fn matches_agent(acl: &[Triple], subject: &NamedOrBlankNode, agent: &Agent) -> bool {
    if has_object(acl, subject, ACL_AGENT_CLASS, FOAF_AGENT) {
        return true;
    }
    match agent {
        Agent::Public => false,
        Agent::WebId(webid) => {
            has_object(acl, subject, ACL_AGENT_CLASS, ACL_AUTHENTICATED_AGENT)
                || has_object(acl, subject, ACL_AGENT, webid)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdf;
    use oxigraph::io::RdfFormat;

    const ALICE: &str = "https://alice.example/card#me";
    const BOB: &str = "https://bob.example/card#me";
    const FOO: &str = "https://pod.toph.so/foo";
    const BOX_: &str = "https://pod.toph.so/box/";

    fn acl(turtle: &str) -> Vec<Triple> {
        rdf::parse(turtle.as_bytes(), RdfFormat::Turtle, "https://pod.toph.so/foo.acl")
            .expect("test ACL parses")
    }

    fn alice() -> Agent { Agent::WebId(ALICE.to_string()) }

    #[test]
    fn named_agent_gets_its_listed_modes() {
        let a = acl(&format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <{FOO}> ; \
             <{ACL_MODE}> <{ACL_READ}>, <{ACL_WRITE}> ."
        ));
        let m = decide(&a, &alice(), FOO, false);
        assert!(m.allows(Mode::Read));
        assert!(m.allows(Mode::Write));
        assert!(m.allows(Mode::Append), "write subsumes append");
        assert!(!m.allows(Mode::Control));
    }

    #[test]
    fn other_agent_gets_nothing() {
        let a = acl(&format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <{FOO}> ; <{ACL_MODE}> <{ACL_READ}> ."
        ));
        let m = decide(&a, &Agent::WebId(BOB.to_string()), FOO, false);
        assert!(!m.allows(Mode::Read));
    }

    #[test]
    fn foaf_agent_grants_the_public_too() {
        let a = acl(&format!(
            "<#o> <{ACL_AGENT_CLASS}> <{FOAF_AGENT}> ; <{ACL_ACCESS_TO}> <{FOO}> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        ));
        assert!(decide(&a, &Agent::Public, FOO, false).allows(Mode::Read));
        assert!(decide(&a, &alice(), FOO, false).allows(Mode::Read));
    }

    #[test]
    fn authenticated_agent_class_excludes_the_public() {
        let a = acl(&format!(
            "<#o> <{ACL_AGENT_CLASS}> <{ACL_AUTHENTICATED_AGENT}> ; <{ACL_ACCESS_TO}> <{FOO}> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        ));
        assert!(decide(&a, &alice(), FOO, false).allows(Mode::Read));
        assert!(!decide(&a, &Agent::Public, FOO, false).allows(Mode::Read));
    }

    // An authorization scoped to a DIFFERENT resource must not leak across.
    #[test]
    fn access_to_another_resource_does_not_apply() {
        let a = acl(&format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/other> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        ));
        assert!(!decide(&a, &alice(), FOO, false).allows(Mode::Read));
    }

    // acl:default only applies when we reached this ACL by inheritance;
    // acl:accessTo only when we did not. The two must not cross over.
    #[test]
    fn scope_predicate_depends_on_inheritance() {
        let default_only = acl(&format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_DEFAULT}> <{BOX_}> ; <{ACL_MODE}> <{ACL_READ}> ."
        ));
        assert!(decide(&default_only, &alice(), BOX_, true).allows(Mode::Read));
        assert!(!decide(&default_only, &alice(), BOX_, false).allows(Mode::Read));

        let access_only = acl(&format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <{BOX_}> ; <{ACL_MODE}> <{ACL_READ}> ."
        ));
        assert!(decide(&access_only, &alice(), BOX_, false).allows(Mode::Read));
        assert!(!decide(&access_only, &alice(), BOX_, true).allows(Mode::Read));
    }

    #[test]
    fn authorization_without_modes_grants_nothing() {
        let a = acl(&format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <{FOO}> ."
        ));
        let m = decide(&a, &alice(), FOO, false);
        assert!(!m.allows(Mode::Read) && !m.allows(Mode::Write)
            && !m.allows(Mode::Append) && !m.allows(Mode::Control));
    }

    #[test]
    fn control_is_independent_of_read_and_write() {
        let a = acl(&format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <{FOO}> ; <{ACL_MODE}> <{ACL_CONTROL}> ."
        ));
        let m = decide(&a, &alice(), FOO, false);
        assert!(m.allows(Mode::Control));
        assert!(!m.allows(Mode::Read));
        assert!(!m.allows(Mode::Write));
    }

    #[test]
    fn append_alone_does_not_grant_write() {
        let a = acl(&format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <{FOO}> ; <{ACL_MODE}> <{ACL_APPEND}> ."
        ));
        let m = decide(&a, &alice(), FOO, false);
        assert!(m.allows(Mode::Append));
        assert!(!m.allows(Mode::Write));
    }

    // Two authorizations, one matching agent + one matching class: the union
    // of their modes applies.
    #[test]
    fn matching_authorizations_union_their_modes() {
        let a = acl(&format!(
            "<#a> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <{FOO}> ; <{ACL_MODE}> <{ACL_READ}> .\n\
             <#b> <{ACL_AGENT_CLASS}> <{ACL_AUTHENTICATED_AGENT}> ; <{ACL_ACCESS_TO}> <{FOO}> ; \
             <{ACL_MODE}> <{ACL_WRITE}> ."
        ));
        let m = decide(&a, &alice(), FOO, false);
        assert!(m.allows(Mode::Read) && m.allows(Mode::Write));
    }

    #[test]
    fn empty_acl_grants_nothing() {
        assert!(!decide(&[], &alice(), FOO, false).allows(Mode::Read));
    }
}
