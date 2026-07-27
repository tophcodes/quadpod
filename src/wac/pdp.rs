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
/// The rdf:type triple marking an authorization. Written by provisioning for
/// interoperability, but `decide` intentionally does not require it — many
/// real-world ACLs omit the type and rely on scope/agent/mode predicates alone.
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

/// The stand-in agent used by [`grants_anything`] to probe for a rule that
/// matches *any* authenticated WebID. It is a `urn:`, so it can never be a
/// WebID a real request arrives with, and never one an ACL would name.
const PROBE_AUTHENTICATED_AGENT: &str = "urn:sparql-pod:pdp:probe-authenticated-agent";

/// Does `acl` grant **any** mode to **anyone** on `governed_iri`, under either
/// scope predicate?
///
/// The question an ACL's author needs answered before their document takes
/// effect: an ACL that grants nothing denies everything at and below its
/// subject, deliberately (an empty ACL is "nothing is granted here", not
/// "absent"), and it revokes the very `Control` that would let anyone remove
/// it. The empty body is the obvious way to write one; the likelier one is a
/// document full of triples that happen to match nobody — a typo in a WebID,
/// the wrong predicate, an `acl:accessTo` naming a different IRI.
///
/// Answered by running [`decide`] itself over a candidate set, rather than by
/// re-reading the triples, so there is exactly one implementation of what a
/// grant is. The candidate set is complete by construction, because
/// [`matches_agent`] can only say yes three ways:
///
/// - `acl:agentClass foaf:Agent` matches everyone, so [`Agent::Public`] finds it;
/// - `acl:agentClass acl:AuthenticatedAgent` matches any WebID, so the
///   synthetic [`PROBE_AUTHENTICATED_AGENT`] finds it;
/// - `acl:agent <w>` matches exactly `w`, and every such `w` is an object of
///   an `acl:agent` triple *in this document*, so enumerating those finds them
///   all.
///
/// Both scopes are probed: an ACL that grants only through `acl:default` still
/// grants, to its subject's descendants, and must not be reported as granting
/// nothing.
pub fn grants_anything(acl: &[Triple], governed_iri: &str) -> bool {
    let mut candidates = vec![
        Agent::Public,
        Agent::WebId(PROBE_AUTHENTICATED_AGENT.to_string()),
    ];
    for t in acl.iter().filter(|t| t.predicate.as_str() == ACL_AGENT) {
        if let Term::NamedNode(w) = &t.object {
            candidates.push(Agent::WebId(w.as_str().to_string()));
        }
    }
    candidates.iter().any(|agent| {
        [false, true]
            .into_iter()
            .any(|inherited| decide(acl, agent, governed_iri, inherited) != AccessModes::default())
    })
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
        assert!(!decide(&a, &Agent::Public, FOO, false).allows(Mode::Read));
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
        assert!(!m.allows(Mode::Append));
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

    // Authorizations are subject-scoped: an agent matched by one
    // authorization must not inherit another's modes. Without the
    // `t.subject == subject` filter, Alice would pick up Bob's Control here.
    #[test]
    fn modes_do_not_leak_across_authorizations() {
        let a = acl(&format!(
            "<#a> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <{FOO}> ; <{ACL_MODE}> <{ACL_READ}> .\n\
             <#b> <{ACL_AGENT}> <{BOB}> ; <{ACL_ACCESS_TO}> <{FOO}> ; <{ACL_MODE}> <{ACL_CONTROL}> ."
        ));
        let m = decide(&a, &alice(), FOO, false);
        assert!(m.allows(Mode::Read));
        assert!(!m.allows(Mode::Control), "Bob's authorization must not grant Alice Control");
    }

    // The obvious empty ACL, and the one that actually happens: a document
    // full of triples that match nobody. Both grant nothing and must be
    // reported as such.
    #[test]
    fn grants_anything_is_false_for_an_acl_that_matches_nobody() {
        assert!(!grants_anything(&[], FOO), "an empty ACL grants nothing");

        // `acl:accessTo` naming a different resource — the mistyped-IRI case.
        let wrong_scope = acl(&format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/other> ; \
             <{ACL_DEFAULT}> <https://pod.toph.so/other> ; <{ACL_MODE}> <{ACL_READ}> ."
        ));
        assert!(!grants_anything(&wrong_scope, FOO));

        // Scope and agent right, but no mode at all.
        let no_modes = acl(&format!(
            "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <{FOO}> ; <{ACL_DEFAULT}> <{FOO}> ."
        ));
        assert!(!grants_anything(&no_modes, FOO));

        // Scope and mode right, but no agent or agentClass names anyone.
        let no_agent = acl(&format!(
            "<#o> <{ACL_ACCESS_TO}> <{FOO}> ; <{ACL_DEFAULT}> <{FOO}> ; <{ACL_MODE}> <{ACL_READ}> ."
        ));
        assert!(!grants_anything(&no_agent, FOO));

        // Triples that are simply not about access control at all.
        let unrelated = acl("<#o> <http://schema.org/name> \"not an acl\" .");
        assert!(!grants_anything(&unrelated, FOO));
    }

    // Each of the three ways `matches_agent` can say yes must be found by the
    // probe set, under each scope predicate — otherwise a real grant would be
    // reported as "grants nobody anything".
    #[test]
    fn grants_anything_finds_every_way_an_authorization_can_match() {
        for scope in [ACL_ACCESS_TO, ACL_DEFAULT] {
            for agent_clause in [
                format!("<{ACL_AGENT}> <{ALICE}>"),
                format!("<{ACL_AGENT_CLASS}> <{FOAF_AGENT}>"),
                format!("<{ACL_AGENT_CLASS}> <{ACL_AUTHENTICATED_AGENT}>"),
            ] {
                let a = acl(&format!(
                    "<#o> {agent_clause} ; <{scope}> <{FOO}> ; <{ACL_MODE}> <{ACL_READ}> ."
                ));
                assert!(
                    grants_anything(&a, FOO),
                    "{agent_clause} under {scope} is a grant"
                );
            }
        }
    }

    // Any single mode counts — Control in particular, since a Control-only ACL
    // is exactly the one that stays removable and must not be warned about.
    #[test]
    fn grants_anything_counts_every_mode() {
        for mode in [ACL_READ, ACL_WRITE, ACL_APPEND, ACL_CONTROL] {
            let a = acl(&format!(
                "<#o> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <{FOO}> ; <{ACL_MODE}> <{mode}> ."
            ));
            assert!(grants_anything(&a, FOO), "{mode} alone is a grant");
        }
    }

    // The synthetic probe WebID must not be reachable as a real grant: an ACL
    // that names it explicitly is a genuine (if useless) grant, and one that
    // does not must never be matched by it.
    #[test]
    fn the_probe_agent_only_finds_grants_that_are_really_there() {
        let named_other = acl(&format!(
            "<#o> <{ACL_AGENT}> <{BOB}> ; <{ACL_ACCESS_TO}> <{FOO}> ; <{ACL_MODE}> <{ACL_READ}> ."
        ));
        // Bob is enumerated from the document, so this is found — but it is
        // found as Bob, not as the probe.
        assert!(grants_anything(&named_other, FOO));
        assert!(!decide(
            &named_other,
            &Agent::WebId(PROBE_AUTHENTICATED_AGENT.to_string()),
            FOO,
            false
        )
        .allows(Mode::Read));
    }

    // The scope check is subject-scoped too: a matching agent's own
    // authorization must carry the accessTo, not borrow it from another.
    #[test]
    fn scope_does_not_leak_across_authorizations() {
        let a = acl(&format!(
            "<#scoped> <{ACL_AGENT}> <{BOB}> ; <{ACL_ACCESS_TO}> <{FOO}> ; <{ACL_MODE}> <{ACL_READ}> .\n\
             <#unscoped> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/other> ; \
             <{ACL_MODE}> <{ACL_READ}> ."
        ));
        assert!(!decide(&a, &alice(), FOO, false).allows(Mode::Read));
    }
}
