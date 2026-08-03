//! The WAC policy decision point: given the applicable ACL triples, which
//! access modes does this agent hold on the governed resource?
//!
//! Deliberately pure — no store access, no async. Everything I/O-shaped lives
//! in `super::prp`. That split is what makes the decision exhaustively
//! table-testable, and it keeps the choice of decision engine local to this
//! file.

use std::collections::HashMap;

use oxigraph::model::{NamedOrBlankNode, Term, Triple};

use crate::auth::Agent;

use super::{AccessModes, Mode};

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

/// The one definition of "a recognized WAC access mode": which `acl:mode`
/// object IRIs count, and which [`Mode`] each one is. [`decide`] uses this to
/// know WHICH mode a triple grants; [`has_recognized_mode`] uses it to know
/// only THAT one does, for [`grants_anything`]. Any other object of
/// `acl:mode` — an unrecognized IRI, or a non-IRI term — is silently ignored
/// by both, exactly as it always was.
fn recognized_mode(mode_iri: &str) -> Option<Mode> {
    match mode_iri {
        ACL_READ => Some(Mode::Read),
        ACL_WRITE => Some(Mode::Write),
        ACL_APPEND => Some(Mode::Append),
        ACL_CONTROL => Some(Mode::Control),
        _ => None,
    }
}

/// Which modes `agent` holds on `governed_iri`, according to `acl`.
///
/// `inherited` selects the scope predicate: an ACL reached by walking up to a
/// container grants through `acl:default`, one found directly on the resource
/// through `acl:accessTo`. The two never cross over — otherwise a container's
/// own `accessTo` rules would silently apply to every child.
///
/// Every question is asked of one authorization's own triples, found once
/// through [`by_subject`] — see there for why the whole document is never
/// rescanned per subject.
pub fn decide(acl: &[Triple], agent: &Agent, governed_iri: &str, inherited: bool) -> AccessModes {
    let scope_predicate = if inherited { ACL_DEFAULT } else { ACL_ACCESS_TO };
    let mut granted = AccessModes::default();

    for authorization in by_subject(acl).values() {
        if !has_object(authorization, scope_predicate, governed_iri) {
            continue;
        }
        if !matches_agent(authorization, agent) {
            continue;
        }
        for t in authorization.iter().filter(|t| t.predicate.as_str() == ACL_MODE) {
            if let Term::NamedNode(m) = &t.object {
                match recognized_mode(m.as_str()) {
                    Some(Mode::Read) => granted.read = true,
                    Some(Mode::Write) => granted.write = true,
                    Some(Mode::Append) => granted.append = true,
                    Some(Mode::Control) => granted.control = true,
                    None => {}
                }
            }
        }
    }
    granted
}

/// Does `acl` grant **any** mode to **anyone** on `governed_iri`, under either
/// scope predicate?
///
/// The question an ACL's author needs answered before their document takes
/// effect: an ACL that grants nothing denies everything at and below its
/// subject, deliberately (an empty ACL is "nothing is granted here", not
/// "absent"), and it revokes the very `Control` that would let anyone remove
/// it. The empty document is the obvious way to write one; the likelier one
/// is a document full of triples that happen to match nobody — the wrong
/// predicate, or an `acl:accessTo` naming a different IRI. (Not a typo in a
/// WebID: [`names_someone`] treats any `acl:agent` object as naming *someone*,
/// so a misspelled WebID with an otherwise-correct scope and mode is a
/// genuine, if useless, grant to that spelling — reported as granting
/// something, not as granting nothing. Catching that needs a different
/// question — "does this ACL still grant `Control` to the agent writing it?"
/// — which is out of scope here.)
///
/// Answered in one pass over the ACL's distinct subjects, asking of each:
/// does it have a scope triple naming `governed_iri` (`acl:accessTo` or
/// `acl:default` — either counts, since a grant reached only through
/// `acl:default` still denies nothing), an agent-matching triple of any of
/// the three recognized forms ([`names_someone`] — the existential version of
/// the same three predicates [`matches_agent`] checks for one specific
/// agent), and at least one [`recognized_mode`] ([`has_recognized_mode`], the
/// same definition [`decide`] uses to assign modes) — all three on the SAME
/// subject, since an authorization is subject-scoped and a scope triple on
/// one must not be paired with a mode on another.
///
/// Asked directly rather than by probing [`decide`] once per candidate agent
/// — `Public`, a synthetic authenticated-agent probe, and every `acl:agent`
/// object in the document, undeduplicated — under both scopes. An ACL is
/// attacker-supplied: anyone holding `Control` on a resource can `PUT` its
/// ACL, sized on the wire by the `max_body_bytes` knob and in triples by
/// [`crate::aux::MAX_AUX_TRIPLES`]. Probing multiplies the document by every
/// agent it happens to mention, and a document of `acl:agent` triples with
/// distinct subjects and no `acl:mode` is the case that never lets `.any()`
/// short-circuit — a synchronous loop with no `await` in it, hanging the
/// worker on the exact feature meant to warn about a self-denying ACL. One
/// pass over [`by_subject`] answers the question in time linear in the
/// document instead, the same order as a single [`decide`] call.
pub fn grants_anything(acl: &[Triple], governed_iri: &str) -> bool {
    by_subject(acl).values().any(|authorization| {
        (has_object(authorization, ACL_ACCESS_TO, governed_iri)
            || has_object(authorization, ACL_DEFAULT, governed_iri))
            && names_someone(authorization)
            && has_recognized_mode(authorization)
    })
}

/// The ACL grouped by subject: each distinct subject with the triples that
/// carry it. We do not require an explicit `a acl:Authorization` type triple —
/// WAC treats the scope/agent/mode predicates themselves as what makes an
/// authorization, and many real ACLs omit the type.
///
/// Every question this module asks — scope, agent, mode — is subject-scoped,
/// so asking it of the whole slice means rescanning the document once per
/// subject, which for a document whose subjects are all distinct is the
/// document multiplied by itself. The ACL is attacker-supplied (see
/// [`grants_anything`]), and the cost recurs: the guard re-reads the
/// applicable ACL and decides per level of the ancestor chain on every
/// request, so one accepted write would tax every later request in that
/// subtree. Grouping once up front is what keeps a decision linear in the
/// document — and it subsumes deduplication, since a repeated subject is one
/// entry with more triples in it.
fn by_subject(acl: &[Triple]) -> HashMap<&NamedOrBlankNode, Vec<&Triple>> {
    let mut index: HashMap<&NamedOrBlankNode, Vec<&Triple>> = HashMap::new();
    for t in acl {
        index.entry(&t.subject).or_default().push(t);
    }
    index
}

/// Whether one authorization — the triples [`by_subject`] grouped under a
/// single subject — has `predicate` pointing at `object_iri`.
fn has_object(authorization: &[&Triple], predicate: &str, object_iri: &str) -> bool {
    authorization.iter().any(|t| {
        t.predicate.as_str() == predicate
            && matches!(&t.object, Term::NamedNode(n) if n.as_str() == object_iri)
    })
}

/// `acl:agent <webid>` matches that WebID exactly; `acl:agentClass foaf:Agent`
/// matches everyone including the public; `acl:agentClass acl:AuthenticatedAgent`
/// matches any verified WebID but never the public.
///
/// **If you add a form here, add it to [`names_someone`] too.** That function
/// answers "could this authorization match *anybody*", which is this function
/// existentially quantified over the agent — a correspondence the compiler
/// does not enforce. Forgetting it does not misdecide access (`decide` stays
/// the only authority), but it makes `grants_anything` report "grants
/// nothing" for an ACL that does grant, i.e. a spurious warning on a write
/// that was in fact effective.
fn matches_agent(authorization: &[&Triple], agent: &Agent) -> bool {
    if has_object(authorization, ACL_AGENT_CLASS, FOAF_AGENT) {
        return true;
    }
    match agent {
        Agent::Public => false,
        Agent::WebId(webid) => {
            has_object(authorization, ACL_AGENT_CLASS, ACL_AUTHENTICATED_AGENT)
                || has_object(authorization, ACL_AGENT, webid)
        }
    }
}

/// Whether this authorization's agent clauses would match **some** agent, existentially
/// — what [`grants_anything`] needs, as opposed to [`matches_agent`]'s "does
/// this ONE agent match", which [`decide`] needs. The same three predicates,
/// read the same way: `acl:agentClass foaf:Agent` and `acl:agentClass
/// acl:AuthenticatedAgent` match unconditionally (everyone, respectively any
/// authenticated WebID), and an `acl:agent` triple matches whatever WebID its
/// object names — so the mere existence of one such triple, whatever its
/// object, is exactly the existential form of `matches_agent`'s third case.
fn names_someone(authorization: &[&Triple]) -> bool {
    has_object(authorization, ACL_AGENT_CLASS, FOAF_AGENT)
        || has_object(authorization, ACL_AGENT_CLASS, ACL_AUTHENTICATED_AGENT)
        || authorization.iter().any(|t| {
            t.predicate.as_str() == ACL_AGENT && matches!(t.object, Term::NamedNode(_))
        })
}

/// Whether this authorization has at least one `acl:mode` triple whose object is a
/// [`recognized_mode`] — the same notion [`decide`] uses to decide WHICH mode
/// a triple grants, here only asked THAT one is granted.
fn has_recognized_mode(authorization: &[&Triple]) -> bool {
    authorization.iter().any(|t| {
        t.predicate.as_str() == ACL_MODE
            && matches!(&t.object, Term::NamedNode(m) if recognized_mode(m.as_str()).is_some())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdf::Format;

    const ALICE: &str = "https://alice.example/card#me";
    const BOB: &str = "https://bob.example/card#me";
    const FOO: &str = "https://pod.toph.so/foo";
    const BOX_: &str = "https://pod.toph.so/box/";

    /// A synthetic WebID, never one a real request arrives with and never
    /// one an ACL would name (a `urn:` in a private namespace). Used only
    /// here, to pin that `acl:agentClass acl:AuthenticatedAgent` matches ANY
    /// WebID via `decide` directly, not just ones an ACL happens to name —
    /// see `the_probe_agent_only_finds_grants_that_are_really_there`.
    /// `grants_anything` no longer probes with a stand-in like this; see its
    /// own doc comment for what replaced probing.
    const PROBE_AUTHENTICATED_AGENT: &str = "urn:sparql-pod:pdp:probe-authenticated-agent";

    fn acl(turtle: &str) -> Vec<Triple> {
        Format::from_content_type("text/turtle").unwrap()
            .parse(turtle.as_bytes(), "https://pod.toph.so/foo.acl", crate::rdf::RdfVersion::Rdf11)
            .expect("test ACL parses")
            .quads().iter().cloned().map(Triple::from).collect()
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

    // What used to be pathological: `grants_anything` used to probe `decide`
    // once per distinct `acl:agent` object in the document, undeduplicated,
    // each probe itself `O(subjects × triples)` — so a document with this
    // many distinct-subject `acl:agent` triples and no `acl:mode` (the case
    // that never lets `.any()` short-circuit) drove that towards the 10¹³
    // comparisons the DoS finding describes. The one-pass replacement is
    // `O(subjects × triples)` total, so this must simply finish, fast, in a
    // single test — no timing assertion, the wall-clock speed of the test
    // suite itself is the check.
    #[test]
    fn grants_anything_stays_fast_on_a_large_ungranted_acl() {
        let mut turtle = String::new();
        for i in 0..3000 {
            turtle.push_str(&format!(
                "<#s{i}> <{ACL_AGENT}> <https://webid.example/{i}> .\n"
            ));
        }
        let a = acl(&turtle);
        assert!(!grants_anything(&a, FOO), "no subject here ever names a mode");
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

    /// `decide`'s question answered without an index: every clause rescans
    /// the whole document, filtering on the subject as it goes. The literal
    /// reading of "an authorization is a subject with a scope, an agent and
    /// modes", written so it shares nothing with [`decide`] but
    /// [`recognized_mode`] — so where the two agree, the grouping changed
    /// only what the answer costs.
    fn decide_by_rescan(
        acl: &[Triple],
        agent: &Agent,
        governed_iri: &str,
        inherited: bool,
    ) -> AccessModes {
        let scope = if inherited { ACL_DEFAULT } else { ACL_ACCESS_TO };
        let object = |subject: &NamedOrBlankNode, predicate: &str, object_iri: &str| {
            acl.iter().any(|t| {
                t.subject == *subject
                    && t.predicate.as_str() == predicate
                    && matches!(&t.object, Term::NamedNode(n) if n.as_str() == object_iri)
            })
        };
        let mut granted = AccessModes::default();
        for subject in acl.iter().map(|t| t.subject.clone()) {
            if !object(&subject, scope, governed_iri) {
                continue;
            }
            let agent_matches = object(&subject, ACL_AGENT_CLASS, FOAF_AGENT)
                || match agent {
                    Agent::Public => false,
                    Agent::WebId(webid) => {
                        object(&subject, ACL_AGENT_CLASS, ACL_AUTHENTICATED_AGENT)
                            || object(&subject, ACL_AGENT, webid)
                    }
                };
            if !agent_matches {
                continue;
            }
            for t in acl.iter().filter(|t| t.subject == subject && t.predicate.as_str() == ACL_MODE)
            {
                if let Term::NamedNode(m) = &t.object {
                    match recognized_mode(m.as_str()) {
                        Some(Mode::Read) => granted.read = true,
                        Some(Mode::Write) => granted.write = true,
                        Some(Mode::Append) => granted.append = true,
                        Some(Mode::Control) => granted.control = true,
                        None => {}
                    }
                }
            }
        }
        granted
    }

    // The truth table above is exhaustive per rule, one authorization at a
    // time; this pins the same decision on a document where the rules
    // interact — subjects repeated across statements, a blank-node subject, a
    // subject whose scope names another resource, a subject scoped under the
    // other predicate, an unrecognized mode IRI and a mode object that is not
    // an IRI at all — against the definition read straight off the slice. Both
    // scopes, and an agent of every kind: named in the document, named nowhere
    // in it, and the public.
    #[test]
    fn grouping_by_subject_decides_exactly_what_rescanning_the_acl_does() {
        let a = acl(&format!(
            "<#a> <{ACL_AGENT}> <{ALICE}>, <{BOB}> ; <{ACL_ACCESS_TO}> <{FOO}> ; \
               <{ACL_MODE}> <{ACL_READ}> .\n\
             <#a> <{ACL_MODE}> <{ACL_APPEND}>, <http://example.org/Fly> ; \
               <{ACL_DEFAULT}> <{FOO}> .\n\
             <#b> <{ACL_AGENT_CLASS}> <{ACL_AUTHENTICATED_AGENT}> ; <{ACL_ACCESS_TO}> <{FOO}> ; \
               <{ACL_MODE}> <{ACL_WRITE}> .\n\
             <#c> <{ACL_AGENT_CLASS}> <{FOAF_AGENT}> ; <{ACL_DEFAULT}> <{FOO}> ; \
               <{ACL_MODE}> <{ACL_READ}> .\n\
             <#d> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <https://pod.toph.so/other> ; \
               <{ACL_MODE}> <{ACL_CONTROL}> .\n\
             <#e> <{ACL_AGENT}> <{ALICE}> ; <{ACL_ACCESS_TO}> <{FOO}> ; \
               <{ACL_MODE}> \"Control\" .\n\
             [] <{ACL_AGENT}> <{BOB}> ; <{ACL_ACCESS_TO}> <{FOO}> ; \
               <{ACL_MODE}> <{ACL_CONTROL}> .\n\
             <#f> <http://schema.org/name> \"not an authorization\" ."
        ));

        // Agreement is only worth something if there is something to agree
        // about: two implementations that both grant nothing agree trivially.
        assert_eq!(
            decide(&a, &alice(), FOO, false),
            AccessModes { read: true, write: true, append: true, control: false },
            "Alice reads and appends through <#a> and writes through <#b>; the \
             `Control` in <#d> is scoped elsewhere and the one in <#e> is a literal"
        );
        assert_eq!(
            decide(&a, &Agent::Public, FOO, true),
            AccessModes { read: true, write: false, append: false, control: false },
            "the public inherits only <#c>'s Read"
        );

        for agent in [
            alice(),
            Agent::WebId(BOB.to_string()),
            Agent::WebId("https://carol.example/card#me".to_string()),
            Agent::Public,
        ] {
            for inherited in [false, true] {
                assert_eq!(
                    decide(&a, &agent, FOO, inherited),
                    decide_by_rescan(&a, &agent, FOO, inherited),
                    "{agent:?}, inherited={inherited}"
                );
            }
        }
    }

    // What the grouping is for. Every subject here is distinct and none of
    // them names a mode, so nothing short-circuits and a `decide` that
    // rescanned the slice per subject would do 10¹⁰ term comparisons — the
    // shape issue #45 describes. Grouped, it is one pass. The size is well
    // past what `aux::MAX_AUX_TRIPLES` lets anyone store, deliberately:
    // `decide` is pure and takes a slice, so this pins the function rather
    // than the write path that feeds it.
    //
    // **This check fails by not finishing, which is the honest description of
    // it**: there is no assertion that separates linear from quadratic, only
    // the wall clock of the suite, exactly as
    // `grants_anything_stays_fast_on_a_large_ungranted_acl` above. It is built
    // through the model rather than parsed from Turtle so the ACL, not the
    // parser, is what the time is spent on.
    #[test]
    fn decide_stays_linear_on_an_acl_of_distinct_subjects() {
        use oxigraph::model::NamedNode;
        let agent = NamedNode::new(ACL_AGENT).unwrap();
        let a: Vec<Triple> = (0..100_000)
            .map(|i| {
                Triple::new(
                    NamedNode::new(format!("https://pod.toph.so/foo.acl#s{i}")).unwrap(),
                    agent.clone(),
                    NamedNode::new(format!("https://webid.example/{i}")).unwrap(),
                )
            })
            .collect();
        assert_eq!(decide(&a, &alice(), FOO, false), AccessModes::default());
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
